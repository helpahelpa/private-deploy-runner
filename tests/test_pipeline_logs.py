"""Runner log delivery, inert output, and bounded protocol regression checks."""
import contextlib
import io
import json
from pathlib import Path
import socket
import socketserver
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import pipeline

SHA = "a" * 40
TOKEN = "private-token-" + "x" * 40


def status(state="running", stage="server"):
    return {"sha": SHA, "status": state, "stage": stage}


def page(text="", cursor=0, more=False, state="running"):
    return dict(status(state), text=text, cursor=cursor, more=more)


class PipelineLogTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        token = self.root / "token"
        token.write_text(TOKEN)
        self.config = {"token_file": str(token)}

    def execute(self, replies):
        calls = []
        def respond(config, token, operation, sha, cursor=None):
            self.assertEqual((token, sha), (TOKEN, SHA))
            expected, result = replies.pop(0)
            self.assertEqual((operation, cursor), expected)
            calls.append((operation, cursor))
            return result
        output = io.StringIO()
        with patch.object(pipeline, "request", side_effect=respond), contextlib.redirect_stdout(output):
            result = pipeline.execute(self.config, SHA, sleep=lambda _: None)
        self.assertEqual(replies, [])
        return result, output.getvalue(), calls

    def test_success_drains_all_pages_in_order_and_keeps_partial_lines(self):
        result, output, _ = self.execute([
            (("submit", None), status()),
            (("logs", 0), page("compile caf", 11)),
            (("status", None), status("success", "complete")),
            (("logs", 11), page("é\nfirst\n", 20, True, "success")),
            (("logs", 20), page("last line", 29, False, "success")),
            (("status", None), status("success", "complete")),
        ])
        self.assertEqual(result, 0)
        self.assertEqual(output, "deployment_server\ndeployment_complete\n[build] compile café\n[build] first\n[build] last line\n")

    def test_failure_drains_diagnostics_before_returning_failure(self):
        result, output, _ = self.execute([
            (("submit", None), status("failed", "failed")),
            (("logs", 0), page("test one failed\n", 16, True, "failed")),
            (("logs", 16), page("2 tests run", 27, False, "failed")),
        ])
        self.assertEqual(result, 1)
        self.assertIn("[build] test one failed\n[build] 2 tests run\n", output)

    def test_log_status_observing_completed_build_is_drained_once_more_before_success(self):
        result, output, _ = self.execute([
            (("submit", None), status()),
            (("logs", 0), page("done\n", 5, False, "success")),
            (("logs", 5), page("", 5, False, "success")),
            (("status", None), status("success", "complete")),
        ])
        self.assertEqual(result, 0)
        self.assertEqual(output.count("[build] done"), 1)

    def test_stale_success_during_final_log_read_fails_closed(self):
        result, _, _ = self.execute([
            (("submit", None), status("success", "complete")),
            (("logs", 0), page("", 0, False, "failed")),
        ])
        self.assertEqual(result, 1)

    def test_final_status_rechecks_runtime_after_log_drain(self):
        result, _, calls = self.execute([
            (("submit", None), status("success", "complete")),
            (("logs", 0), page("", 0, False, "success")),
            (("status", None), status("failed", "failed")),
        ])
        self.assertEqual(result, 1)
        self.assertEqual(calls[-1], ("status", None))

    def test_old_cached_build_without_log_is_accepted(self):
        result, output, _ = self.execute([
            (("submit", None), status("success", "complete")),
            (("logs", 0), page("", 0, False, "success")),
            (("status", None), status("success", "complete")),
        ])
        self.assertEqual((result, output), (0, "deployment_complete\n"))

    def test_output_neutralizes_workflow_commands_and_terminal_control_characters(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            pipeline.BuildOutput.emit("::error::untrusted\r\x1b[2K\tmessage\x00")
        self.assertEqual(out.getvalue(), "[build] ::error::untrusted??[2K?message?\n")

    def test_log_drain_rejects_regression_nonprogress_and_unbounded_offsets(self):
        cases = [page("", 2, True), page("x", 2), page("x", 1),
                 page("", 3), page("x", pipeline.MAX_LOG_BYTES + 1)]
        for value in cases:
            output = pipeline.BuildOutput()
            output.cursor = 2
            with self.subTest(value=value), patch.object(pipeline, "request", return_value=value):
                with self.assertRaises(ValueError):
                    output.drain({}, TOKEN, SHA)
        output = pipeline.BuildOutput()
        output.pages = pipeline.MAX_LOG_PAGES
        with self.assertRaises(ValueError), patch.object(pipeline, "request") as request:
            output.drain({}, TOKEN, SHA)
        request.assert_not_called()

    def test_timeout_drains_available_log_before_exit(self):
        clocks = iter((0, 4000))
        replies = [status(), page("timeout diagnostics", 19)]
        output = io.StringIO()
        with patch.object(pipeline, "request", side_effect=replies), contextlib.redirect_stdout(output):
            result = pipeline.execute(self.config, SHA, clock=lambda: next(clocks))
        self.assertEqual(result, 1)
        self.assertIn("[build] timeout diagnostics\n", output.getvalue())

    def test_top_level_errors_never_print_raw_credentials_or_paths(self):
        config = self.root / "runner.json"
        config.write_text(json.dumps(self.config))
        output = io.StringIO()
        with patch.object(sys, "argv", ["pipeline.py", "--config", str(config)]), \
                patch.dict(pipeline.os.environ, {"SOURCE_SHA": SHA}), \
                patch.object(pipeline, "request", side_effect=ValueError("credential secret /private/host")), \
                contextlib.redirect_stdout(output):
            self.assertEqual(pipeline.main(), 1)
        self.assertEqual(output.getvalue(), "deployment_unavailable\n")

    def test_logs_only_reads_all_recorded_pages_without_submitting_or_polling_status(self):
        output = io.StringIO()
        replies = [page("recorded tests passed\n", 22, True, "failed"),
                   page("final summary", 35, False, "failed")]
        with patch.object(pipeline, "request", side_effect=replies) as request, contextlib.redirect_stdout(output):
            self.assertEqual(pipeline.show_logs(self.config, SHA), 0)
        self.assertEqual([call.args[2:] for call in request.call_args_list],
                         [("logs", SHA, 0), ("logs", SHA, 22)])
        self.assertIn("Recorded build/test logs; no build or deployment requested.\n", output.getvalue())
        self.assertIn("[build] recorded tests passed\n[build] final summary\nlog replay complete\n", output.getvalue())
        self.assertNotIn("deployment_success", output.getvalue())
        self.assertNotIn("deployment_complete", output.getvalue())

    def test_logs_only_rejects_invalid_commit_before_opening_token(self):
        with patch.object(pipeline.Path, "read_text") as read, patch.object(pipeline, "request") as request:
            with self.assertRaises(ValueError):
                pipeline.show_logs({"token_file": "/missing"}, "refs/heads/master")
        read.assert_not_called()
        request.assert_not_called()

    def test_logs_only_cli_selects_read_only_action(self):
        config = self.root / "runner.json"
        config.write_text(json.dumps(self.config))
        with patch.object(sys, "argv", ["pipeline.py", "--config", str(config), "--logs-only"]), \
                patch.dict(pipeline.os.environ, {"SOURCE_SHA": SHA}), \
                patch.object(pipeline, "show_logs", return_value=0) as show, \
                patch.object(pipeline, "execute") as execute:
            self.assertEqual(pipeline.main(), 0)
        show.assert_called_once_with(self.config, SHA)
        execute.assert_not_called()

    def test_request_validates_page_types_status_and_cursor_before_output(self):
        socket_path = str(self.root / "protocol.sock")
        responses = []
        requests = []
        class Handler(socketserver.StreamRequestHandler):
            def handle(self):
                requests.append(json.loads(self.rfile.readline()))
                self.wfile.write((json.dumps(responses.pop(0)) + "\n").encode())
        with socketserver.UnixStreamServer(socket_path, Handler) as server:
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                cfg = {"socket_path": socket_path}
                responses.append({"ok": True, "data": page("café\n", 6)})
                result = pipeline.request(cfg, TOKEN, "logs", SHA, 0)
                self.assertEqual(result["text"], "café\n")
                self.assertEqual(requests[-1], {"token": TOKEN, "op": "logs", "sha": SHA, "cursor": 0})
                invalid = [None, [], dict(page(), sha="b" * 40), dict(page(), status="other"),
                           dict(page(), text=5), dict(page(), cursor=True), dict(page(), cursor=-1),
                           dict(page(), cursor=1 << 63), dict(page(), more=1), status(),
                           page("x", 2), page("", 0, True)]
                for data in invalid:
                    responses.append({"ok": True, "data": data})
                    with self.subTest(data=data), self.assertRaises(ValueError):
                        pipeline.request(cfg, TOKEN, "logs", SHA, 0)
                for cursor in (-1, True, "0", 1 << 63, None):
                    with self.subTest(cursor=cursor), self.assertRaises(ValueError):
                        pipeline.request(cfg, TOKEN, "logs", SHA, cursor)
            finally:
                server.shutdown()
                thread.join(2)


if __name__ == "__main__":
    unittest.main()

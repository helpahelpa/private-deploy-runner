"""Privacy and live forwarding tests run only trusted local fixture programs."""
import concurrent.futures
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import build_logs as logs


class BuildLogTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.environment = patch.dict(os.environ)
        self.environment.start()
        self.addCleanup(self.environment.stop)
        os.environ.pop(logs.FILE_ENV, None)
        os.environ.pop(logs.PRIVACY_ENV, None)

    def configure(self, literals=None):
        self.journal = logs.configure(self.root / "journal", literals)
        return self.journal

    def text(self):
        return self.journal.read_text()

    def test_configuration_private_modes_and_retry_retention(self):
        journal = self.configure(["fixture-secret-value"])
        logs.emit("first build")
        self.assertEqual(logs.configure(journal.parent), journal)
        logs.emit("second build")
        self.assertIn("first build", self.text())
        self.assertIn("second build", self.text())
        self.assertEqual(journal.stat().st_mode & 0o777, 0o600)
        self.assertEqual(journal.parent.stat().st_mode & 0o777, 0o700)
        self.assertEqual((journal.parent / "privacy.json").stat().st_mode & 0o777, 0o600)

    def test_literals_machine_details_credentials_and_terminal_commands_redacted(self):
        with patch.object(logs.socket, "gethostname", return_value="fixture-machine"), \
                patch.object(logs.getpass, "getuser", return_value="fixture-user"):
            self.configure(["secret-known-123"])
        logs.emit("fixture-machine fixture-user secret-known-123\n"
                  "address 192.168.44.8 2001:db8::37 [::1] person@example.invalid\n"
                  "File /home/fixture-user/project/test.py and C:\\Users\\fixture-user\\project\\a.py\n"
                  "https://person:password@example.invalid/route\n"
                  "Authorization: Bearer abcdef sensitive tail\n"
                  "password='long secret containing spaces' remaining\n"
                  "https://example.invalid/?api_key=myapikey\n"
                  "ghp_abcdefghijklmno12345678901234567890\n"
                  "\x1b[31m::error::injected\x1b[0m\r::warning::reset\n")
        text = self.text()
        for private in ["fixture-machine", "fixture-user", "secret-known-123", "192.168.44.8",
                        "2001:db8::37", "::1", "person@example.invalid", "C:\\Users", "/home/",
                        "person:password", "abcdef", "long secret", "myapikey", "ghp_", "\x1b", "\r"]:
            self.assertNotIn(private, text)
        self.assertTrue(all(line.startswith("[build] ") for line in text.splitlines()))
        self.assertIn("[build] ::error::injected", text)
        self.assertIn("[build] ::warning::reset", text)

    def test_line_boundaries_keep_secret_out_of_long_line(self):
        self.configure(["short-secret"])
        logs.emit("prefix short-secret " + "z" * logs.MAX_LINE + " tail\nnormal output")
        self.assertEqual(self.text(), "[build] [long line omitted]\n[build] normal output\n")

    def test_private_capture_preserves_binary_and_complete_stdout_stderr(self):
        self.configure(["fixture-raw-secret"])
        code = "import os; os.write(1,b'fixture-raw-secret\\xff\\n'); os.write(2,b'private stderr\\n')"
        raw = self.root / "raw.log"
        result = logs.run([sys.executable, "-c", code], timeout=5, log=raw)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout, b"fixture-raw-secret\xff\n")
        self.assertEqual(result.stderr, b"private stderr\n")
        self.assertEqual(raw.read_bytes(), result.stdout + b"\nSTDERR\n" + result.stderr)
        self.assertEqual(raw.stat().st_mode & 0o777, 0o600)
        self.assertNotIn("fixture-raw-secret", self.text())

    def test_live_output_is_visible_before_subprocess_finishes(self):
        self.configure()
        code = "import os,time; os.write(1,b'first live line\\n'); time.sleep(0.8); os.write(2,b'last line\\n')"
        with concurrent.futures.ThreadPoolExecutor(1) as pool:
            future = pool.submit(logs.run, [sys.executable, "-c", code], timeout=5)
            deadline = time.monotonic() + 3
            while "first live line" not in self.text() and time.monotonic() < deadline:
                time.sleep(0.01)
            self.assertIn("first live line", self.text())
            self.assertFalse(future.done())
            self.assertEqual(future.result().stderr, b"last line\n")

    def test_incremental_utf8_and_pem_states_are_isolated_between_pipes(self):
        self.configure()
        code = ("import os,time; "
                "os.write(1,b'-----BEGIN PRIVATE KEY-----\\n'); time.sleep(.04); "
                "os.write(2,b'stderr test passed\\n'); time.sleep(.04); "
                "os.write(1,b'rawkeymaterial\\n-----END PRIVATE KEY-----\\n\\xe6'); time.sleep(.04); "
                "os.write(1,b'\\x97\\xa5\\xe6\\x9c\\xac\\n')")
        result = logs.run([sys.executable, "-c", code], timeout=5)
        self.assertIn(b"rawkeymaterial", result.stdout)
        self.assertNotIn("rawkeymaterial", self.text())
        self.assertIn("stderr test passed", self.text())
        self.assertIn("日本", self.text())
        self.assertNotIn("�", self.text())

    def test_timeout_preserves_private_captures_and_ends_promptly(self):
        self.configure(["timeout-private"])
        code = "import os,time; os.write(1,b'timeout-private\\n'); time.sleep(10)"
        started = time.monotonic()
        raw = self.root / "timeout.log"
        with self.assertRaises(subprocess.TimeoutExpired) as caught:
            logs.run([sys.executable, "-c", code], timeout=.15, log=raw)
        self.assertLess(time.monotonic() - started, 2)
        self.assertEqual(caught.exception.output, b"timeout-private\n")
        self.assertIn(b"timeout-private", raw.read_bytes())
        self.assertNotIn("timeout-private", self.text())

    def test_no_configuration_disables_journal_but_keeps_capture(self):
        logs.emit("disabled")
        result = logs.run([sys.executable, "-c", "print('private output')"], timeout=5)
        self.assertEqual(result.stdout, b"private output\n")
        self.assertEqual(list(self.root.iterdir()), [])

    def test_invalid_configuration_fails_closed_before_command(self):
        self.configure()
        marker = self.root / "must-not-exist"
        (self.journal.parent / "privacy.json").write_text("invalid configuration with private text")
        with self.assertRaisesRegex(ValueError, "^" + logs.ERROR + "$"):
            logs.run([sys.executable, "-c", f"open({str(marker)!r},'w').close()"], timeout=5)
        self.assertFalse(marker.exists())
        self.assertEqual(self.text(), "")

    def test_multithread_append_keeps_individual_lines_atomic(self):
        self.configure()
        def emit_rows(worker):
            for row in range(50):
                logs.emit(f"worker-{worker}-row-{row}")
        with concurrent.futures.ThreadPoolExecutor(8) as pool:
            list(pool.map(emit_rows, range(8)))
        expected = {f"[build] worker-{worker}-row-{row}" for worker in range(8) for row in range(50)}
        self.assertEqual(set(self.text().splitlines()), expected)
        self.assertEqual(len(self.text().splitlines()), 400)

    def test_journal_retention_is_bounded_and_marker_is_final(self):
        self.configure()
        with patch.object(logs, "MAX_JOURNAL", 200):
            for _ in range(50):
                logs.emit("a" * 30)
            before = self.journal.read_bytes()
            logs.emit("must not be appended")
            self.assertLessEqual(len(before), 200)
            self.assertEqual(self.journal.read_bytes(), before)
            self.assertEqual(before.count(logs.TRUNCATED), 1)
            self.assertTrue(before.endswith(logs.TRUNCATED))

    def test_read_pages_have_utf8_byte_cursors_and_serialized_bound(self):
        self.configure()
        logs.emit(("日本😀 quote\\\" " * 300) + "\nlast line")
        # Keep fixture below the long-line guard, but require several IPC pages.
        self.assertNotIn("long line", self.text())
        cursor = 0
        parts = []
        for _ in range(100):
            page = logs.read_page(self.journal, cursor)
            self.assertLess(len(json.dumps(page).encode()), 3200)
            self.assertEqual(page["cursor"], cursor + len(page["text"].encode()))
            self.assertGreaterEqual(page["cursor"], cursor)
            parts.append(page["text"])
            cursor = page["cursor"]
            if not page["more"]:
                break
        else:
            self.fail("pagination did not finish")
        self.assertEqual("".join(parts), self.text())

    def test_read_rejects_bad_cursors_utf8_offsets_and_symlinks(self):
        self.configure()
        logs.emit("日本")
        for cursor in (-1, True, 1.2, "0", 10000, 9):
            with self.subTest(cursor=cursor), self.assertRaises(ValueError):
                logs.read_page(self.journal, cursor)
        link = self.root / "link"
        link.symlink_to(self.journal)
        with self.assertRaises(ValueError):
            logs.read_page(link, 0)
        directory_link = self.root / "directory-link"
        directory_link.symlink_to(self.journal.parent, target_is_directory=True)
        with self.assertRaises(ValueError):
            logs.read_page(directory_link / "journal.log", 0)

    def test_raw_capture_limit_fails_closed_without_unbounded_memory(self):
        self.configure()
        code = "import os; os.write(1,b'x'*12000)"
        with patch.object(logs, "MAX_CAPTURE", 4000), self.assertRaisesRegex(RuntimeError, "capture limit"):
            logs.run([sys.executable, "-c", code], timeout=5)

    def test_emit_pem_state_survives_calls_and_long_line_boundaries(self):
        self.configure()
        logs.emit("-----BEGIN PRIVATE KEY-----")
        logs.emit("secret material from a later call")
        logs.emit("-----END PRIVATE KEY-----\nnormal test")
        logs.emit("x" * (logs.MAX_LINE + 1) + "-----BEGIN PRIVATE KEY-----\n"
                  "long line secret body\n-----END PRIVATE KEY-----\nnormal again")
        self.assertNotIn("secret material", self.text())
        self.assertNotIn("secret body", self.text())
        self.assertIn("normal test", self.text())
        self.assertIn("normal again", self.text())

    def test_missing_legacy_journal_empty_only_at_zero_cursor(self):
        self.assertEqual(logs.read_page(self.root / "missing.log", 0),
                         {"text": "", "cursor": 0, "more": False})
        with self.assertRaises(ValueError):
            logs.read_page(self.root / "missing.log", 1)

    def test_closed_pipes_do_not_shorten_requested_timeout(self):
        self.configure()
        code = "import os,time; os.close(1); os.close(2); time.sleep(.15)"
        self.assertEqual(logs.run([sys.executable, "-c", code], timeout=3).returncode, 0)
        with self.assertRaises(subprocess.TimeoutExpired) as caught:
            logs.run([sys.executable, "-c", code.replace(".15", "10")], timeout=.1)
        self.assertEqual(caught.exception.timeout, .1)


if __name__ == "__main__":
    unittest.main()

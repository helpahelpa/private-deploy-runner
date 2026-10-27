"""QA policy crosses the workflow boundary once and stays bound to its attempt."""
import contextlib
import io
import json
import os
from pathlib import Path
import re
import sys
import tempfile
import threading
import unittest
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import broker
import pipeline
from test_broker import A, TOKEN, AttemptOperations


ATTEMPT = "34567-1"


class PolicyOperations(AttemptOperations):
    def __init__(self):
        super().__init__()
        self.policies = []

    def build(self, sha, version, stage, *, request_id=None, force_full_qa=False):
        self.policies.append((request_id, force_full_qa))
        return super().build(sha, version, stage, request_id=request_id)


class BrokerQaPolicyTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        token = self.root / "token"
        token.write_text(TOKEN)
        token.chmod(0o600)
        self.config = {"local_root": self.root / "state", "token_file": token,
                       "minimum_version": 63}
        self.operations = PolicyOperations()
        self.subject = broker.Broker(self.config, self.operations)

    def submit(self, **extra):
        return self.subject.handle(dict(op="submit", token=TOKEN, sha="",
                                        request_id=ATTEMPT, **extra))

    def files(self):
        return {str(path.relative_to(self.subject.root)): path.read_bytes()
                for path in self.subject.root.rglob("*") if path.is_file()}

    def run_worker(self):
        self.subject.pending.put(None)
        worker = threading.Thread(target=self.subject.worker, daemon=True)
        worker.start()
        worker.join(3)
        self.assertFalse(worker.is_alive(), "fixture worker must consume its stop marker")

    def test_omitted_policy_defaults_to_false_in_persisted_job_and_worker(self):
        queued = self.submit()
        self.assertIs(queued["force_full_qa"], False)
        self.assertIs(self.subject.load(A, ATTEMPT)["force_full_qa"], False)
        self.run_worker()
        self.assertEqual(self.operations.policies, [(ATTEMPT, False)])
        self.assertEqual(self.subject.load(A, ATTEMPT)["status"], "success")

    def test_forced_policy_is_persisted_and_reaches_actual_worker_build(self):
        queued = self.submit(force_full_qa=True)
        self.assertIs(queued["force_full_qa"], True)
        self.run_worker()
        self.assertEqual(self.operations.policies, [(ATTEMPT, True)])
        completed = self.subject.handle(dict(op="status", token=TOKEN, sha=A,
                                             request_id=ATTEMPT))
        self.assertIs(completed["force_full_qa"], True)
        self.assertEqual(completed["status"], "success")
        self.assertTrue(completed["replacement_verified"])

    def test_queued_forced_policy_survives_broker_reconstruction(self):
        self.submit(force_full_qa=True)
        self.subject = broker.Broker(self.config, self.operations)
        self.run_worker()
        self.assertEqual(self.operations.policies, [(ATTEMPT, True)])

    def test_invalid_policy_types_create_no_binding_job_counter_or_queue_entry(self):
        for invalid in (None, 0, 1, "true", "false", [], {}):
            before = self.files()
            with self.subTest(invalid=invalid), self.assertRaises(broker.BrokerError):
                self.submit(force_full_qa=invalid)
            self.assertEqual(self.files(), before)
            self.assertTrue(self.subject.pending.empty())
        self.assertEqual(self.operations.builds, [])

    def test_policy_is_forbidden_on_reads_unknown_operations_and_legacy_submit(self):
        for operation in ("status", "logs", "unknown", "submit"):
            for policy in (False, True):
                request = dict(op=operation, token=TOKEN, sha=A, force_full_qa=policy)
                if operation != "submit":
                    request["request_id"] = ATTEMPT
                if operation == "logs":
                    request["cursor"] = 0
                before = self.files()
                with self.subTest(operation=operation, policy=policy), \
                        self.assertRaises(broker.BrokerError):
                    self.subject.handle(request)
                self.assertEqual(self.files(), before)
                self.assertTrue(self.subject.pending.empty())

    def test_same_attempt_policy_is_immutable_before_and_after_completion(self):
        for forced in (False, True):
            with self.subTest(forced=forced):
                identifier = "34567-" + str(int(forced) + 1)
                payload = dict(op="submit", token=TOKEN, sha="", request_id=identifier,
                               force_full_qa=forced)
                self.subject.handle(payload)
                before = self.files()
                with self.assertRaises(broker.BrokerError):
                    self.subject.handle(dict(payload, force_full_qa=not forced))
                self.assertEqual(self.files(), before)
                self.run_worker()
                before = self.files()
                with self.assertRaises(broker.BrokerError):
                    self.subject.handle(dict(payload, force_full_qa=not forced))
                self.assertEqual(self.files(), before)
                result = self.subject.handle(payload)
                self.assertEqual(result["status"], "success")
                self.assertIs(result["force_full_qa"], forced)

    def test_explicit_false_and_omitted_false_are_same_idempotent_policy(self):
        first = self.submit()
        before = self.files()
        self.assertEqual(self.submit(force_full_qa=False), first)
        self.assertEqual(self.files(), before)
        self.assertEqual(self.subject.pending.qsize(), 1)


class PipelineQaPolicyTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        token = self.root / "token"
        token.write_text(TOKEN)
        self.config = {"token_file": str(token), "socket_path": str(self.root / "socket")}

    def status(self, forced=False):
        return {"sha": A, "request_id": ATTEMPT, "status": "success", "stage": "complete",
                "phase": "complete", "replacement_verified": True, "force_full_qa": forced}

    def test_serialized_request_sends_boolean_policy_only_for_submit(self):
        for forced in (False, True):
            stream = MagicMock()
            stream.__enter__.return_value = stream
            stream.makefile.return_value.readline.return_value = (
                json.dumps({"ok": True, "data": self.status(forced)}) + "\n").encode()
            with patch.object(pipeline.socket, "socket", return_value=stream):
                pipeline.request(self.config, TOKEN, "submit", A, request_id=ATTEMPT,
                                 force_full_qa=forced)
            payload = json.loads(stream.sendall.call_args.args[0])
            self.assertIs(payload["force_full_qa"], forced)
            self.assertEqual(payload["request_id"], ATTEMPT)

    def test_invalid_request_policies_fail_before_connecting_to_broker(self):
        invalid = [("submit", ATTEMPT, value) for value in (0, 1, "true", [], {})]
        invalid += [(op, ATTEMPT, value) for op in ("status", "logs") for value in (False, True)]
        invalid += [("submit", None, value) for value in (False, True)]
        for operation, identifier, policy in invalid:
            with self.subTest(operation=operation, policy=policy), \
                    patch.object(pipeline.socket, "socket") as socket, self.assertRaises(ValueError):
                pipeline.request(self.config, TOKEN, operation, A, request_id=identifier,
                                 force_full_qa=policy)
            socket.assert_not_called()

    def test_submit_requires_exact_policy_acknowledgement_including_explicit_false(self):
        for requested in (False, True):
            for acknowledgement in (not requested, None, "false", 0, 1):
                response = self.status(requested)
                if acknowledgement is None:
                    del response["force_full_qa"]
                else:
                    response["force_full_qa"] = acknowledgement
                stream = MagicMock()
                stream.__enter__.return_value = stream
                stream.makefile.return_value.readline.return_value = (
                    json.dumps({"ok": True, "data": response}) + "\n").encode()
                with self.subTest(requested=requested, acknowledgement=acknowledgement), \
                        patch.object(pipeline.socket, "socket", return_value=stream), \
                        self.assertRaises(ValueError):
                    pipeline.request(self.config, TOKEN, "submit", A, request_id=ATTEMPT,
                                     force_full_qa=requested)



    def cli(self, policy, start):
        config = self.root / "runner.json"
        config.write_text(json.dumps(self.config))
        environment = {"GITHUB_RUN_ID": "34567", "GITHUB_RUN_ATTEMPT": "1", "SOURCE_SHA": A}
        if policy is not None:
            environment["FORCE_FULL_QA"] = policy
        with patch.dict(os.environ, environment, clear=True), \
                patch.object(sys, "argv", ["pipeline.py", "--config", str(config), "--start"]), \
                patch.object(pipeline, "start_attempt", start), contextlib.redirect_stdout(io.StringIO()):
            return pipeline.main()

    def test_cli_accepts_only_exact_boolean_strings_and_defaults_to_false(self):
        for value, expected in ((None, False), ("false", False), ("true", True)):
            with self.subTest(value=value):
                start = MagicMock(return_value=0)
                self.assertEqual(self.cli(value, start), 0)
                self.assertIs(start.call_args.kwargs["force_full_qa"], expected)
                self.assertEqual(start.call_args.args[2], ATTEMPT)
        for value in ("", "True", "FALSE", "1", "0", " true", "false\n", "null"):
            with self.subTest(value=value):
                start = MagicMock(return_value=0)
                self.assertEqual(self.cli(value, start), 1)
                start.assert_not_called()



if __name__ == "__main__":
    unittest.main()

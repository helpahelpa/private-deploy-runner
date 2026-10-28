"""Runner/Broker integration through real Unix IPC; no GitHub, Docker or live data."""
import contextlib
import io
import json
from pathlib import Path
import socketserver
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import broker
import build_logs
import pipeline

SHA = "a" * 40
OTHER = "b" * 40
TOKEN = "isolated-workflow-token-" + "x" * 40


class DisposableRuntime:
    def __init__(self, root):
        self.root = root
        (root / "deployments").mkdir(parents=True)
        self.cid = "1" * 64
        self.release = SHA
        self.path = str(root / "original-release")
        self.running = {self.cid: True}
        self.unhealthy = False

    def status(self):
        if self.unhealthy:
            raise ValueError("Fixture runtime unhealthy")
        return {"managed_release": self.release}

    def active(self):
        return {"release": self.release, "container": self.cid, "release_path": self.path}

    def inspect(self, cid):
        return {"State": {"Running": self.running[cid]}}


class GatedOperations:
    """Deterministic build/activation fixture with real replacement validation."""
    def __init__(self, config):
        self.config = config
        self.runtime = DisposableRuntime(config["local_root"] / "runtime")
        self.master = SHA
        self.builds = []
        self.promotions = []
        self.failure = None
        self.events = {name: threading.Event() for name in ("build", "promote", "finalize", "verify")}
        self.gates = {name: threading.Event() for name in self.events}
        for gate in self.gates.values():
            gate.set()

    def point(self, name):
        self.events[name].set()
        if not self.gates[name].wait(5):
            raise TimeoutError("Fixture gate timed out")

    def current(self):
        return self.master

    def preflight(self):
        pass

    def build(self, sha, version, stage, *, request_id=None):
        self.builds.append((sha, version, request_id))
        for component in ("server", "client", "transport"):
            stage(component)
            build_logs.emit("Fixture " + request_id + " " + component + " tests started")
            if self.failure == component:
                build_logs.emit("Fixture " + component + " tests failed")
                raise ValueError("Fixture build/test failure")
            build_logs.emit("Fixture " + request_id + " " + component + " tests passed")
        stage("assemble")
        self.point("build")
        if self.failure == "source_changed":
            self.master = OTHER
        return self.config["local_root"] / "releases" / request_id

    def release_is_active(self, release):
        return False

    def promote(self, sha, release, *, replace_same_commit=False):
        if replace_same_commit is not True:
            raise AssertionError("Fresh attempts must replace even the same commit")
        self.promotions.append((sha, release))
        self.point("promote")
        previous = self.runtime.cid
        previous_path = self.runtime.path
        cid = format(len(self.promotions) + 100, "064x")
        self.runtime.running[previous] = False
        self.runtime.running[cid] = True
        self.runtime.cid = cid
        self.runtime.release = sha
        self.runtime.path = str(Path(release).resolve())
        if self.failure == "rollback":
            # A rollback can create a different healthy CID with the SAME SHA.
            # Neither SHA equality nor CID inequality may turn this attempt green.
            self.runtime.path = str(self.runtime.root / "rollback-release")
            build_logs.emit("Fixture promotion rolled back; deployment failed")
            raise ValueError("Fixture promotion rollback")
        proof = {"id": format(len(self.promotions), "032x"), "phase": "healthy", "to": sha,
                 "from_container": previous, "container": cid, "old_stopped": True,
                 "release_path": self.runtime.path, "previous_release_path": previous_path,
                 "replace_same_commit": True, "rollback": False}
        receipt = dict(proof)
        if self.failure == "receipt_mismatch":
            receipt["phase"] = "rolled_back_code_only"
        (self.runtime.root / "deployments" / (proof["id"] + ".json")).write_text(json.dumps(receipt))
        if self.failure == "old_running":
            self.runtime.running[previous] = True
        if self.failure == "wrong_cid":
            self.runtime.cid = "f" * 64
        return proof

    def finalize(self, sha):
        self.point("finalize")
        if self.failure == "finalize":
            raise ValueError("Fixture registry failure")
        if self.failure == "health":
            self.runtime.unhealthy = True

    def status(self):
        return self.runtime.status()["managed_release"]

    def verify_replacement(self, sha, release, proof):
        self.point("verify")
        with patch.object(broker.engine, "Engine", return_value=self.runtime):
            return broker.Operations(self.config).verify_replacement(sha, release, proof)


class WorkflowIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        token = self.root / "token"
        token.write_text(TOKEN)
        token.chmod(0o600)
        engine_config = self.root / "engine.json"
        engine_config.write_text(json.dumps({"data_compatibility": broker.engine.COMPATIBILITY}))
        self.config = {"local_root": self.root / "state", "token_file": token,
                       "socket_path": self.root / "ipc.sock", "minimum_version": 1,
                       "engine_config": engine_config}
        self.ops = GatedOperations(self.config)
        self.broker = broker.Broker(self.config, self.ops)
        self.server = socketserver.UnixStreamServer(str(self.config["socket_path"]), broker.Handler)
        self.server.broker = self.broker
        self.server_thread = threading.Thread(target=self.server.serve_forever,
                                              kwargs={"poll_interval": .01}, daemon=True)
        self.server_thread.start()
        self.worker = threading.Thread(target=self.broker.worker, daemon=True)
        self.worker.start()
        self.addCleanup(self.close)
        self.runner = {"token_file": str(token), "socket_path": str(self.config["socket_path"]),
                       "poll_seconds": 1, "timeout_seconds": 10}

    def close(self):
        for gate in self.ops.gates.values():
            gate.set()
        self.broker.pending.put(None)
        self.worker.join(6)
        self.server.shutdown()
        self.server_thread.join(2)
        self.server.server_close()

    def execute(self, request_id="12345-1", sha=""):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            result = pipeline.execute(self.runner, sha, request_id=request_id,
                                      sleep=lambda _: time.sleep(.003))
        return result, output.getvalue()

    def status(self, request_id):
        return pipeline.request(self.runner, TOKEN, "status", SHA, request_id=request_id)

    def test_blank_manual_dispatch_waits_through_build_handoff_registry_and_exact_cid(self):
        for gate in self.ops.gates.values():
            gate.clear()
        result = {}
        errors = []
        def run():
            try:
                result["value"] = self.execute()
            except BaseException as error:
                errors.append(error)
        client = threading.Thread(target=run, daemon=True)
        client.start()
        try:
            for point, stage in (("build", "assemble"), ("promote", "promote"),
                                 ("finalize", "verify"), ("verify", "verify")):
                self.assertTrue(self.ops.events[point].wait(3), point)
                state = self.status("12345-1")
                self.assertEqual((SHA, "12345-1", "running", stage),
                                 (state["sha"], state["request_id"], state["status"], state["stage"]))
                self.assertIs(state["replacement_verified"], False)
                self.assertTrue(client.is_alive(), point)
                self.ops.gates[point].set()
            client.join(3)
            self.assertFalse(client.is_alive())
            self.assertFalse(errors, repr(errors))
            self.assertEqual(result["value"][0], 0)
            self.assertNotEqual(self.ops.runtime.cid, "1" * 64)
            self.assertIs(self.status("12345-1")["replacement_verified"], True)
        finally:
            for gate in self.ops.gates.values():
                gate.set()
            client.join(6)

    def test_same_github_run_next_attempt_replaces_again_and_isolates_logs(self):
        before = self.ops.runtime.cid
        first_result, first_log = self.execute("12345-1")
        first_cid = self.ops.runtime.cid
        second_result, second_log = self.execute("12345-2")
        self.assertEqual((first_result, second_result), (0, 0))
        self.assertEqual(len({before, first_cid, self.ops.runtime.cid}), 3)
        self.assertEqual([x[2] for x in self.ops.builds], ["12345-1", "12345-2"])
        self.assertIn("Fixture 12345-1 server tests passed", first_log)
        self.assertNotIn("Fixture 12345-1", second_log)
        self.assertIn("Fixture 12345-2 server tests passed", second_log)
        # Transport retries of one workflow attempt must not submit another build.
        self.assertEqual(self.execute("12345-2")[0], 0)
        self.assertEqual(len(self.ops.builds), 2)

    def test_separate_action_steps_wait_at_their_boundaries_and_share_one_log_cursor(self):
        for gate in self.ops.gates.values():
            gate.clear()
        progress = self.root / "progress.json"
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.assertEqual(pipeline.start_attempt(self.runner, "", "52345-1", progress), 0)
        results = {}
        clients = []
        def launch(through):
            def run():
                stream = io.StringIO()
                with contextlib.redirect_stdout(stream):
                    value = pipeline.wait_through(self.runner, progress, through,
                                                  sleep=lambda _: time.sleep(.003))
                results[through] = (value, stream.getvalue())
            client = threading.Thread(target=run, daemon=True)
            clients.append(client)
            client.start()
            return client
        try:
            self.assertTrue(self.ops.events["build"].wait(3))
            build = launch("build")
            self.assertTrue(build.is_alive())
            self.ops.gates["build"].set()
            self.assertTrue(self.ops.events["promote"].wait(3))
            build.join(3)
            self.assertFalse(build.is_alive())
            self.assertEqual(results["build"][0], 0)
            deploy = launch("deploy")
            self.assertTrue(deploy.is_alive())
            self.ops.gates["promote"].set()
            self.assertTrue(self.ops.events["finalize"].wait(3))
            deploy.join(3)
            self.assertFalse(deploy.is_alive())
            self.assertEqual(results["deploy"][0], 0)
            verify = launch("verify")
            self.assertTrue(verify.is_alive())
            self.ops.gates["finalize"].set()
            self.assertTrue(self.ops.events["verify"].wait(3))
            self.assertTrue(verify.is_alive())
            self.ops.gates["verify"].set()
            verify.join(3)
            self.assertFalse(verify.is_alive())
            self.assertEqual(results["verify"][0], 0)
            combined = output.getvalue() + "".join(results[name][1] for name in ("build", "deploy", "verify"))
            for component in ("server", "client", "transport"):
                self.assertEqual(combined.count("Fixture 52345-1 " + component + " tests passed"), 1)
            state = json.loads(progress.read_text())
            self.assertEqual((state["sha"], state["request_id"]), (SHA, "52345-1"))
            self.assertGreater(state["cursor"], 0)
        finally:
            for gate in self.ops.gates.values():
                gate.set()
            for client in clients:
                client.join(6)

    def test_final_status_rejects_replacement_lost_after_success_without_rewriting_history(self):
        self.assertEqual(self.execute()[0], 0)
        path = self.broker.path(SHA, "12345-1")
        receipt = path.read_bytes()
        self.ops.runtime.cid = "f" * 64
        self.assertEqual(self.execute()[0], 1)
        self.assertEqual(self.status("12345-1")["status"], "failed")
        self.assertEqual(path.read_bytes(), receipt)
        self.assertEqual(len(self.ops.builds), 1)

    def test_server_client_or_transport_failure_returns_nonzero_without_touching_runtime(self):
        initial = self.ops.runtime.cid
        for number, component in enumerate(("server", "client", "transport"), 1):
            with self.subTest(component=component):
                self.ops.failure = component
                identity = "22345-" + str(number)
                result, output = self.execute(identity)
                self.assertEqual(result, 1)
                self.assertIn("Fixture " + component + " tests failed", output)
                self.assertEqual(self.status(identity)["status"], "failed")
                self.assertEqual(self.ops.runtime.cid, initial)
                self.assertFalse(self.ops.promotions)
                self.assertEqual(self.execute(identity)[0], 1)
                self.assertEqual(len(self.ops.builds), number)

    def test_same_sha_healthy_rollback_with_new_cid_is_still_failed(self):
        initial = self.ops.runtime.cid
        self.ops.failure = "rollback"
        result, output = self.execute()
        self.assertEqual(result, 1)
        self.assertEqual(self.ops.status(), SHA)
        self.assertNotEqual(self.ops.runtime.cid, initial)
        self.assertIn("Fixture promotion rolled back", output)
        state = self.status("12345-1")
        self.assertEqual(state["status"], "failed")
        self.assertIs(state["replacement_verified"], False)

    def test_registry_health_or_replacement_receipt_failure_never_reports_success(self):
        for number, failure in enumerate(("finalize", "health", "receipt_mismatch", "old_running", "wrong_cid"), 1):
            with self.subTest(failure=failure):
                self.ops.failure = failure
                self.ops.runtime.unhealthy = False
                identity = "32345-" + str(number)
                self.assertEqual(self.execute(identity)[0], 1)
                state = self.status(identity)
                self.assertEqual(state["status"], "failed")
                self.assertIs(state["replacement_verified"], False)

    def test_master_change_during_build_fails_before_handoff(self):
        self.ops.failure = "source_changed"
        self.assertEqual(self.execute()[0], 1)
        self.assertFalse(self.ops.promotions)
        self.assertEqual(self.ops.runtime.cid, "1" * 64)

    def test_interrupted_attempt_cannot_recover_green_from_healthy_same_sha(self):
        config = dict(self.config, local_root=self.root / "interrupted-state")
        operations = GatedOperations(config)
        previous = broker.Broker(config, operations)
        previous.handle({"op": "submit", "token": TOKEN, "sha": "", "request_id": "42345-1"})
        job = previous.load(SHA, "42345-1")
        job.update(status="running", stage="verify")
        previous.save(job)
        recovered = broker.Broker(config, operations)
        self.server.broker = recovered
        self.assertEqual(self.execute("42345-1")[0], 1)
        self.assertEqual(recovered.load(SHA, "42345-1")["status"], "failed")
        self.assertFalse(operations.builds)
        self.assertEqual(operations.status(), SHA)


if __name__ == "__main__":
    unittest.main()

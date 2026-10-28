"""Deterministic host/runner boundary tests; no GitHub, Docker or live runtime."""
import hashlib
import importlib.util
import json
from pathlib import Path
import socket
import socketserver
import sys
import tempfile
import threading
import subprocess
import unittest
from unittest.mock import patch

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))
import broker
import pipeline

A, B = "a" * 40, "b" * 40
TOKEN = "fixture-private-token-" + "x" * 40


class FakeOperations:
    def __init__(self):
        self.master = A
        self.active = B
        self.builds = []
        self.promotions = []
        self.finalized = []
        self.after_build = None
        self.build_started = threading.Event()
        self.release_build = None
        self.fail = False

    def current(self):
        return self.master

    def preflight(self):
        pass

    def build(self, sha, version, stage):
        self.builds.append((sha, version))
        stage("server")
        self.build_started.set()
        if self.release_build is not None:
            self.release_build.wait(3)
        stage("client")
        if self.fail:
            raise ValueError("private-hostname credential secret")
        if self.after_build is not None:
            self.master = self.after_build
        return Path("/private/release")

    def promote(self, sha, release):
        self.promotions.append(sha)
        self.active = sha

    def status(self):
        return self.active

    def finalize(self, sha):
        self.finalized.append(sha)


class AttemptOperations(FakeOperations):
    def build(self,sha,version,stage,*,request_id=None):
        release=super().build(sha,version,stage)
        return release/str(request_id)

    def assets_can_publish(self, release):
        return False

    def release_is_active(self, release):
        return False

    def promote(self,sha,release,*,replace_same_commit=False):
        if not replace_same_commit:raise AssertionError('Attempt must replace the container')
        super().promote(sha,release)
        return {'id':'d'*32,'phase':'healthy','container':'e'*64,'from_container':'f'*64,
                'release_path':str(release),'to':sha,'old_stopped':True}

    def verify_replacement(self,sha,release,proof):
        return proof['container']!=proof['from_container'] and proof['release_path']==str(release)


class AttemptBrokerTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);token=self.root/'token';token.write_text(TOKEN);token.chmod(0o600)
        self.config={'local_root':self.root/'state','token_file':token,'minimum_version':63}
        self.ops=AttemptOperations();self.broker=broker.Broker(self.config,self.ops)

    def request(self,operation='submit',sha='',request_id='12345-1',**extra):
        return self.broker.handle(dict(op=operation,sha=sha,request_id=request_id,token=TOKEN,**extra))

    def process(self,request_id='12345-1'):
        self.broker.process(broker.job_key(A,request_id))

    def test_manual_submit_resolves_master_and_same_id_is_idempotent_after_master_moves(self):
        first=self.request();self.ops.master=B;second=self.request()
        self.assertEqual(first,second)
        self.assertEqual((A,'12345-1','queued'),(first['sha'],first['request_id'],first['phase']))
        self.assertEqual(1,self.broker.pending.qsize())
        with self.assertRaises(broker.BrokerError):self.request(sha=B)
        for value in ('','0-1','1-0','1/2','../private',True,None,'9'*21+'-1','1-'+'9'*11):
            with self.subTest(value=value),self.assertRaises(broker.BrokerError):self.request(request_id=value)

    def test_production_policy_rejects_legacy_submit_but_keeps_historical_reads(self):
        legacy=dict(op='submit',sha=A,token=TOKEN)
        self.broker.handle(legacy)
        self.config['require_request_id_for_submit']=True
        with self.assertRaises(broker.BrokerError):self.broker.handle(legacy)
        self.assertEqual('queued',self.broker.handle(dict(legacy,op='status'))['status'])
        self.assertEqual('',self.broker.handle(dict(legacy,op='logs',cursor=0))['text'])
        self.assertEqual('queued',self.request()['status'])

    def test_each_attempt_builds_and_replaces_even_when_sha_already_active(self):
        self.ops.active=A
        for request_id in ('12345-1','12345-2'):
            self.request(request_id=request_id);self.process(request_id)
            result=self.request('status',sha=A,request_id=request_id)
            self.assertEqual('success',result['status']);self.assertEqual('complete',result['phase'])
            self.assertIs(result['replacement_verified'],True)
        self.assertEqual([(A,63),(A,64)],self.ops.builds)
        self.assertEqual([A,A],self.ops.promotions)
        self.assertNotEqual(self.broker.path(A,'12345-1'),self.broker.path(A,'12345-2'))
        self.assertEqual('success',self.request(sha=A)['status'])
        self.assertEqual(2,len(self.ops.builds))

    def test_failed_attempt_never_retries_or_turns_green_from_same_sha(self):
        self.ops.active=A;self.ops.fail=True
        self.request();self.process()
        job_before=self.broker.path(A,'12345-1').read_bytes()
        self.assertEqual('failed',self.request(sha=A)['status'])
        self.assertEqual(job_before,self.broker.path(A,'12345-1').read_bytes())
        self.ops.fail=False;self.request(request_id='12345-2');self.process('12345-2')
        self.assertEqual('success',self.request('status',sha=A,request_id='12345-2')['status'])
        self.assertEqual('failed',self.request('status',sha=A)['status'])

    def test_attempt_logs_and_status_cannot_read_another_attempt_or_sha(self):
        self.request();self.request(request_id='12345-2')
        for request_id,text in (('12345-1','first attempt\n'),('12345-2','second attempt\n')):
            directory=self.broker.root/'public-logs'/broker.job_key(A,request_id);directory.mkdir(parents=True)
            (directory/'journal.log').write_text(text);(directory/'journal.log').chmod(0o600)
            self.assertEqual(text,self.request('logs',sha=A,request_id=request_id,cursor=0)['text'])
        for kwargs in ({'sha':B},{'request_id':'99999-1'},{'sha':''}):
            with self.subTest(kwargs=kwargs),self.assertRaises(broker.BrokerError):self.request('status',sha=kwargs.get('sha',A),request_id=kwargs.get('request_id','12345-1'))

    def test_live_phase_is_available_before_terminal_status(self):
        self.request()
        for stage,phase in (('source','building'),('client','building_testing'),('promote','deploying'),('verify','verifying')):
            self.broker.stage(broker.job_key(A,'12345-1'),stage)
            result=self.request('status',sha=A)
            self.assertEqual(phase,result['phase']);self.assertEqual('running',result['status'])

    def test_interrupted_attempt_is_failed_even_when_same_sha_is_healthy(self):
        for stage in ('client','promote','verify'):
            request_id='12345-'+str(('client','promote','verify').index(stage)+1)
            self.request(request_id=request_id);self.broker.stage(broker.job_key(A,request_id),stage)
            self.ops.active=A;restarted=broker.Broker(self.config,self.ops)
            self.assertEqual('failed',restarted.load(A,request_id)['status'])
            self.broker=restarted




class BrokerTests(unittest.TestCase):
    def test_public_controller_still_requires_exact_repository_identity(self):
        from unittest.mock import Mock
        source=broker.watch.Identity('example/source',10,1)
        control=broker.watch.Identity('example/control',11,1)
        operations=broker.Operations({'source':source,'control':control,'local_root':Path('/state'),'control_private':False})
        operations.github=Mock()
        responses=[{'id':10,'owner':{'id':1,'login':'example'},'full_name':'example/source','private':True},
                   {'id':11,'owner':{'id':1,'login':'example'},'full_name':'example/control','private':False}]
        operations.github.request.side_effect=responses
        operations.identities()
        for field,value in (('id',12),('private',True)):
            changed=dict(responses[1]);changed[field]=value
            operations.github.request.side_effect=[responses[0],changed]
            with self.subTest(field=field),self.assertRaises(broker.watch.WatchError):
                operations.identities()

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        token = self.root / "token"
        token.write_text(TOKEN)
        token.chmod(0o600)
        self.config = {"local_root": self.root / "state", "token_file": token,
                       "minimum_version": 63, "socket_path": self.root / "broker.sock",
                       "engine_config": self.root / "engine.json"}
        Path(self.config['engine_config']).write_text(json.dumps({'data_compatibility':broker.engine.COMPATIBILITY}))
        self.ops = FakeOperations()
        self.broker = broker.Broker(self.config, self.ops)

    def request(self, operation="submit", sha=A, **extra):
        value = {"op": operation, "sha": sha, "token": TOKEN}
        value.update(extra)
        return self.broker.handle(value)


    def test_bad_token_injection_and_unknown_operations_never_queue_work(self):
        bad = [{"token": "bad"}, {"sha": "../../private"}, {"sha": A + ";id"},
               {"sha": A.upper()}, {"op": "command"}, {"command": ["id"]},
               {"path": "/private"}, {"config": "/private"}]
        for change in bad:
            with self.subTest(change=change), self.assertRaises(broker.BrokerError):
                self.request(**change)
        self.assertEqual(self.broker.pending.qsize(), 0)
        self.assertEqual(list(self.broker.jobs.glob("*.json")), [])

    def test_log_operation_is_authenticated_bounded_and_has_no_caller_path(self):
        self.request()
        directory = self.broker.root / "public-logs" / A
        directory.mkdir(parents=True)
        (directory / "journal.log").write_text("server tests passed\n")
        (directory / "journal.log").chmod(0o600)
        response = self.request("logs", cursor=0)
        self.assertEqual(response, {"sha": A, "status": "queued", "stage": "queued",
                                   "text": "server tests passed\n", "cursor": 20, "more": False})
        self.assertLess(len(json.dumps({"ok": True, "data": response}).encode()), 4096)
        for extra in ({"cursor": -1}, {"cursor": True}, {"cursor": 1 << 63},
                      {"cursor": "0"}, {"cursor": 0, "path": "/etc/passwd"},
                      {"cursor": 0, "token": "bad"}):
            with self.subTest(extra=extra), self.assertRaises(broker.BrokerError):
                self.request("logs", **extra)
        with self.assertRaises(broker.BrokerError):
            self.request("logs")
        with self.assertRaises(broker.BrokerError):
            self.request("status", cursor=0)
        with self.assertRaises(broker.BrokerError):
            self.request("logs", sha=B, cursor=0)
        self.assertEqual(self.broker.pending.qsize(), 1)

    def test_reading_historical_success_logs_does_not_mutate_job_or_check_active_release(self):
        self.request()
        self.broker.process(A)
        before = self.broker.path(A).read_bytes()
        self.ops.active = B
        with patch.object(self.ops, "status", side_effect=AssertionError("read-only log request checked runtime")):
            self.assertEqual(self.request("logs", cursor=0)["status"], "success")
        self.assertEqual(self.broker.path(A).read_bytes(), before)
        self.assertEqual(self.request("status")["status"], "failed")

    def test_old_job_without_journal_has_empty_log_page(self):
        self.request()
        self.assertEqual(self.request("logs", cursor=0),
                         {"sha": A, "status": "queued", "stage": "queued",
                          "text": "", "cursor": 0, "more": False})

    def test_stale_observation_fails_before_build(self):
        self.request()
        self.ops.master = B
        self.broker.process(A)
        self.assertEqual(self.request("status")["status"], "failed")
        self.assertFalse(self.ops.builds)
        self.assertFalse(self.ops.promotions)


    def test_build_failure_returns_only_generic_fields_and_retains_private_diagnostics(self):
        self.request()
        self.ops.fail = True
        self.broker.process(A)
        response = self.request("status")
        self.assertEqual(response, {"sha": A, "status": "failed", "stage": "failed"})
        self.assertNotIn("secret", json.dumps(response))
        log = self.config["local_root"] / "broker.private.log"
        self.assertIn("credential secret", log.read_text())
        self.assertEqual(log.stat().st_mode & 0o777, 0o600)

    def test_monotonic_versions_survive_restart_and_failed_build(self):
        self.request()
        self.ops.fail = True
        self.broker.process(A)
        self.broker = broker.Broker(self.config, self.ops)
        self.request()
        self.assertEqual(self.broker.load(A)["version"], 64)
        self.request(sha=B)
        self.assertEqual(self.broker.load(B)["version"], 65)

    def test_log_setup_failure_fails_job_without_killing_future_deployments(self):
        self.request()
        self.config["log_redactions"] = None
        self.broker.process(A)
        self.assertEqual(self.request("status")["status"], "failed")
        self.assertFalse(self.ops.builds)
        self.config.pop("log_redactions")
        self.request()
        self.broker.process(A)
        self.assertEqual(self.request("status")["status"], "success")

    def test_pre_handoff_crash_resumes_reserved_version(self):
        self.request()
        self.broker.stage(A, "client")
        restarted = broker.Broker(self.config, self.ops)
        self.assertEqual(restarted.load(A)["status"], "queued")
        self.assertEqual(restarted.load(A)["version"], 63)
        self.assertEqual(restarted.pending.get_nowait(), A)
        restarted.process(A)
        self.assertEqual(restarted.load(A)["status"], "success")

    def test_handoff_crash_does_not_turn_sha_equality_into_success(self):
        self.request()
        self.broker.stage(A, "promote")
        self.ops.active = A
        restarted = broker.Broker(self.config, self.ops)
        self.assertEqual(restarted.load(A)["status"], "failed")
        self.assertTrue(restarted.pending.empty())
        self.assertEqual(self.ops.finalized, [A])

    def test_uncertain_handoff_blocks_automatic_replay(self):
        self.request()
        self.broker.stage(A, "promote")
        restarted = broker.Broker(self.config, self.ops)
        self.assertTrue(restarted.load(A)["recovery_required"])
        self.assertEqual(self.ops.finalized, [B])
        response = restarted.handle({"op": "submit", "sha": A, "token": TOKEN})
        self.assertEqual(response["status"], "failed")
        self.assertTrue(restarted.pending.empty())

    def test_historical_success_does_not_claim_release_is_still_active(self):
        self.request()
        self.broker.process(A)
        self.ops.active = B
        self.assertEqual(self.request("status")["status"], "failed")
        self.assertEqual(self.request()["status"], "queued")

    def test_single_worker_serializes_deployments(self):
        self.ops.release_build = threading.Event()
        self.request()
        self.request(sha=B)
        worker = threading.Thread(target=self.broker.worker)
        worker.start()
        self.assertTrue(self.ops.build_started.wait(2))
        self.assertEqual(self.ops.builds, [(A, 63)])
        self.assertEqual(self.broker.load(B)["status"], "queued")
        self.ops.release_build.set()
        self.broker.pending.join()
        self.broker.pending.put(None)
        worker.join(2)
        self.assertFalse(worker.is_alive())
        # Second queued request became stale and never entered its build.
        self.assertEqual(self.ops.builds, [(A, 63)])

    def test_real_unix_protocol_rejects_oversize_and_never_echoes_token(self):
        with socketserver.UnixStreamServer(str(self.config["socket_path"]), broker.Handler) as server:
            server.broker = self.broker
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                data = pipeline.request({"socket_path": str(self.config["socket_path"])}, TOKEN, "submit", A)
                self.assertEqual(data["status"], "queued")
                directory = self.broker.root / "public-logs" / A
                directory.mkdir(parents=True)
                expected = "test café passed\n" * 1000
                (directory / "journal.log").write_text(expected)
                (directory / "journal.log").chmod(0o600)
                cursor, chunks = 0, []
                while True:
                    page = pipeline.request({"socket_path": str(self.config["socket_path"])}, TOKEN, "logs", A, cursor)
                    self.assertEqual(page["status"], "queued")
                    self.assertGreater(page["cursor"], cursor)
                    chunks.append(page["text"])
                    cursor = page["cursor"]
                    if not page["more"]:
                        break
                self.assertEqual("".join(chunks), expected)
                self.assertEqual(cursor, len(expected.encode()))
                with self.assertRaises(ValueError):
                    pipeline.request({"socket_path": str(self.config["socket_path"])}, TOKEN, "logs", A, cursor + 1)
                with socket.socket(socket.AF_UNIX) as stream:
                    stream.connect(str(self.config["socket_path"]))
                    stream.sendall(b"x" * 4097 + b"\n")
                    raw = stream.makefile("rb").readline()
                self.assertEqual(json.loads(raw), {"ok": False, "error": "request_rejected"})
                self.assertNotIn(TOKEN, raw.decode())
            finally:
                server.shutdown()
                thread.join(2)

    def test_client_validates_sha_before_opening_token_or_connecting(self):
        with patch.object(pipeline, "request") as request:
            with self.assertRaises(ValueError):
                pipeline.execute({"token_file": "/does/not/exist"}, "refs/heads/master")
            request.assert_not_called()


    def test_cached_receipt_is_immutable_and_detects_tampering(self):
        config = dict(self.config)
        operations = broker.Operations(config)
        cache = self.config["local_root"] / "builds" / A
        cache.mkdir(parents=True)
        (cache / "payload").write_text("tested")
        broker.engine.write_json(cache / "receipt.json", {"sha": A, "files": broker.engine.tree(cache)})
        self.assertEqual(operations.cached(A), cache)
        (cache / "payload").write_text("tampered")
        with self.assertRaises(broker.BrokerError):
            operations.cached(A)

    def test_git_boundary_disables_hooks_global_config_and_captures_diagnostics(self):
        config = dict(self.config, source_deploy_key=Path("/private/key"), known_hosts=Path("/private/known-hosts"))
        operations = broker.Operations(config)
        with patch.object(operations, "command", return_value=b"") as command:
            operations.git("status")
        args = command.call_args.args[0]
        env = command.call_args.kwargs["env"]
        self.assertIn("core.hooksPath=/dev/null", args)
        self.assertIn("credential.helper=", args)
        self.assertEqual(env["GIT_CONFIG_GLOBAL"], "/dev/null")
        self.assertIn("StrictHostKeyChecking=yes", env["GIT_SSH_COMMAND"])
        self.assertIn("IdentitiesOnly=yes", env["GIT_SSH_COMMAND"])

    def test_clean_source_snapshot_never_runs_source_hooks_or_scripts(self):
        repo = self.root / "fixture-source"
        subprocess.run(["git", "init", "-q", repo], check=True)
        subprocess.run(["git", "-C", repo, "config", "user.name", "Fixture"], check=True)
        subprocess.run(["git", "-C", repo, "config", "user.email", "fixture@example.invalid"], check=True)
        (repo / "source.py").write_text("raise RuntimeError('must never execute source on host')")
        (repo / "source.py").chmod(0o755)
        (repo / ".gitattributes").write_text("* filter=untrusted\n")
        subprocess.run(["git", "-C", repo, "add", "."], check=True)
        subprocess.run(["git", "-C", repo, "commit", "-qm", "Fixture"], check=True)
        sha = subprocess.check_output(["git", "-C", repo, "rev-parse", "HEAD"], text=True).strip()
        config = dict(self.config, source_cache=self.root / "cache.git", source_deploy_key=self.root / "key",
                      known_hosts=self.root / "known-hosts", source=broker.watch.Identity("example/source", 1, 1))
        operations = broker.Operations(config)
        original = operations.git
        def local_git(*arguments):
            return original(*(str(repo) if argument == "git@github.com:example/source.git" else argument for argument in arguments))
        with patch.object(operations, "git", side_effect=local_git):
            snapshot = operations.source(sha)
        self.assertEqual((snapshot / "source.py").read_text(), (repo / "source.py").read_text())
        broker.engine.verify_source(snapshot, sha)
        # The generated repository only carries trusted local index/config state.
        self.assertFalse((snapshot / ".git/hooks/post-checkout").exists())

    def test_assembly_merges_pinned_base_publishes_apk_and_attests_exact_files(self):
        base = self.root / "static"
        base.mkdir()
        (base / "base.bin").write_text("original static asset")
        (base / "update_config.json").write_text("old")
        base_hash = hashlib.sha256(json.dumps(broker.engine.tree(base), sort_keys=True).encode()).hexdigest()
        config = dict(self.config, client_config=self.root / "client-config.json", transport_config=self.root / "transport-config.json",
                      static_assets={"path": str(base), "tree_sha256": base_hash})
        Path(config["client_config"]).write_text("{}")
        operations = broker.Operations(config)
        assembled = []
        def build_server(source, sha, output, data, **kwargs):
            output.mkdir()
            (output / "server.json").write_text("{}")
        def client_command(arguments, **kwargs):
            output = Path(arguments[arguments.index("--output") + 1])
            if str(arguments[1]).endswith("check_transport.py"):
                output.mkdir()
                broker.engine.write_json(output / "transport.json", {"commit": A, "passed": True})
                return
            (output / "assets").mkdir(parents=True)
            (output / "assets/update_config.json").write_text("new")
            (output / "client.apk").write_bytes(b"signed-fixture")
            broker.engine.write_json(output / "client-tests.json", {"commit": A, "passed": True})
            manifest = {"commit": A, "package": "example.privateworld",
                "apk_version_code": 68, "apk_version_name": "4.2.0.68",
                "apk_input_sha256": "1" * 64, "apk_source_commit": B, "apk_reused": True,
                "signing_certificate_sha256": "f" * 64,
                "client_tests_sha256": broker.engine.digest(output / "client-tests.json"),
                "apk_sha256": broker.engine.digest(output / "client.apk")}
            broker.engine.write_json(output / "assets/apk-update.json",
                                     broker.native_apk.update_metadata(manifest, output / "client.apk"))
            manifest["asset_files"] = broker.engine.tree(output / "assets")
            broker.engine.write_json(output / "manifest.json", manifest)
        def assemble(server, assets, provenance, receipt, output):
            value = json.loads(provenance.read_text())
            self.assertEqual(value["files"], broker.engine.tree(assets))
            self.assertEqual((assets / "update_config.json").read_text(), "new")
            self.assertEqual((assets / "base.bin").read_text(), "original static asset")
            self.assertEqual((assets / "client.apk").read_bytes(), b"signed-fixture")
            metadata = json.loads((assets / "apk-update.json").read_text())
            self.assertEqual(metadata["version_code"], 68)
            self.assertEqual(metadata["sha256"], broker.engine.digest(assets / "client.apk"))
            self.assertEqual(metadata["url"], "/client.apk")
            assembled.append(value)
            output.mkdir()
            (output / "manifest.json").write_text("fixture")
        with patch.object(operations, "source", return_value=self.root), patch.object(operations, "command", side_effect=client_command), \
                patch.object(broker.engine, "build_server", side_effect=build_server), patch.object(broker.engine, "assemble", side_effect=assemble):
            release = operations.build(A, 63, lambda _: None)
        self.assertEqual(len(assembled), 1)
        self.assertEqual(release, operations.cached(A) / "release")
        receipt = json.loads((release.parent / "receipt.json").read_text())
        self.assertIn("transport/transport.json", receipt["files"])
        original=broker.engine.tree(release.parent)
        for request_id,version in (('45678-1',64),('45678-2',65)):
            with patch.object(operations,'cached',side_effect=AssertionError('Fresh attempt used SHA artifacts')), \
                    patch.object(operations,'source',return_value=self.root) as source, \
                    patch.object(operations,'command',side_effect=client_command), \
                    patch.object(broker.engine,'build_server',side_effect=build_server), \
                    patch.object(broker.engine,'assemble',side_effect=assemble):
                fresh=operations.build(A,version,lambda _:None,request_id=request_id)
                source.assert_called_once_with(A,request_id=request_id)
            self.assertEqual(operations.root/'builds'/broker.job_key(A,request_id)/'release',fresh)
            self.assertEqual(request_id,json.loads((fresh.parent/'receipt.json').read_text())['request_id'])
            self.assertEqual(original,broker.engine.tree(release.parent))
        self.assertEqual(3,len(assembled))

    def test_public_apk_metadata_cannot_advertise_a_different_signed_artifact(self):
        client = self.root / 'metadata-client'
        (client / 'assets').mkdir(parents=True)
        (client / 'client.apk').write_bytes(b'signed fixture')
        manifest = {'package': 'example.privateworld', 'apk_version_code': 68,
            'apk_version_name': '4.2.0.68', 'signing_certificate_sha256': 'f' * 64,
            'apk_input_sha256': '1' * 64, 'apk_source_commit': A, 'apk_reused': False}
        metadata = broker.native_apk.update_metadata(manifest, client / 'client.apk')
        broker.engine.write_json(client / 'assets/apk-update.json', metadata)
        broker.verify_apk_update(client, manifest)
        for change in ({'version_code': 69}, {'sha256': '2' * 64}, {'package': 'example.other'},
                       {'signing_cert_sha256': '0' * 64}, {'url': 'https://other.example/client.apk'}):
            broker.engine.write_json(client / 'assets/apk-update.json', dict(metadata, **change))
            with self.subTest(change=change), self.assertRaises(broker.BrokerError):
                broker.verify_apk_update(client, manifest)

    def test_fixed_builds_overlap_and_failed_client_waits_for_server_completion(self):
        config = dict(self.config, client_config=self.root / "client-config.json")
        Path(config["client_config"]).write_text("{}")
        operations = broker.Operations(config)
        server_started = threading.Event()
        client_started = threading.Event()
        release_server = threading.Event()
        server_done = threading.Event()
        failures = []
        def server_build(*args, **kwargs):
            server_started.set()
            release_server.wait(3)
            server_done.set()
        def client_build(*args, **kwargs):
            client_started.set()
            raise broker.BrokerError("fixture build failure")
        def perform():
            try:
                operations.build(A, 63, lambda _: None)
            except Exception as error:
                failures.append(error)
        with patch.object(operations, "source", return_value=self.root), patch.object(operations, "command", side_effect=client_build), \
                patch.object(broker.engine, "build_server", side_effect=server_build), patch.object(broker.engine, "assemble") as assemble:
            thread = threading.Thread(target=perform)
            thread.start()
            try:
                self.assertTrue(server_started.wait(2))
                self.assertTrue(client_started.wait(2), "client must start while server build is still active")
                self.assertTrue(thread.is_alive(), "a failed parallel build must wait for its peer")
                self.assertFalse(server_done.is_set())
            finally:
                release_server.set()
                thread.join(3)
            self.assertFalse(thread.is_alive())
            self.assertTrue(server_done.is_set())
            self.assertEqual(len(failures), 1)
            self.assertIsInstance(failures[0], broker.BrokerError)
            assemble.assert_not_called()

    def test_lfs_objects_are_hash_checked_and_kept_out_of_clean_worktree(self):
        data = b"exact commit binary fixture"
        oid = hashlib.sha256(data).hexdigest()
        store = self.root / "seed-objects"
        original = store / oid[:2] / oid[2:4] / oid
        original.parent.mkdir(parents=True)
        original.write_bytes(data)
        config = dict(self.config, source_cache=self.root / "cache.git", lfs_object_store=str(store))
        operations = broker.Operations(config)
        destination = self.root / "snapshot"
        destination.mkdir()
        pointer = b"version https://git-lfs.github.com/spec/v1\noid sha256:" + oid.encode() + b"\nsize " + str(len(data)).encode() + b"\n"
        (destination / "fixture.bin").write_bytes(pointer)
        with patch.object(operations, "fetch_lfs") as fetch:
            operations.hydrate_lfs({oid: len(data)}, destination, A)
            fetch.assert_not_called()
        target = destination / ".git/lfs/objects" / oid[:2] / oid[2:4] / oid
        self.assertEqual(target.read_bytes(), data)
        self.assertEqual((destination / "fixture.bin").read_bytes(), pointer)
        original.write_bytes(b"tampered")
        with self.assertRaises(broker.BrokerError):
            operations.hydrate_lfs({oid: len(data)}, destination, A)

    def test_missing_lfs_fetches_once_then_revalidates_download(self):
        data = b"download fixture"
        oid = hashlib.sha256(data).hexdigest()
        cache = self.root / "cache.git"
        operations = broker.Operations(dict(self.config, source_cache=cache))
        def downloaded(sha):
            self.assertEqual(sha, A)
            target = cache / "lfs/objects" / oid[:2] / oid[2:4] / oid
            target.parent.mkdir(parents=True)
            target.write_bytes(data)
        with patch.object(operations, "fetch_lfs", side_effect=downloaded) as fetch:
            operations.hydrate_lfs({oid: len(data)}, self.root / "snapshot", A)
            fetch.assert_called_once_with(A)
        with self.assertRaises(broker.BrokerError):
            operations.hydrate_lfs({"c" * 64: 2 * 1024 * 1024 * 1024 + 1}, self.root / "snapshot", A)

    def test_lfs_fetch_uses_pinned_binary_fixed_endpoint_and_readonly_ssh_identity(self):
        binary = self.root / "git-lfs"
        binary.write_bytes(b"trusted fixture binary")
        cache = self.root / "cache.git"
        cache.mkdir()
        (cache / "config").write_text("[core]\n bare = true\n")
        config = dict(self.config, source_cache=cache, source_deploy_key=self.root / "read-key",
                      known_hosts=self.root / "known-hosts", source=broker.watch.Identity("example/source", 1, 1),
                      lfs_binary={"path": str(binary), "sha256": hashlib.sha256(binary.read_bytes()).hexdigest()})
        operations = broker.Operations(config)
        with patch.object(operations, "command", return_value=b"") as command:
            operations.fetch_lfs(A)
        self.assertEqual(command.call_args.args[0], [binary, "fetch", "--include=", "--exclude=", "origin", A])
        env = command.call_args.kwargs["env"]
        settings = {env["GIT_CONFIG_KEY_" + str(index)]: env["GIT_CONFIG_VALUE_" + str(index)]
                    for index in range(int(env["GIT_CONFIG_COUNT"]))}
        self.assertEqual(settings["remote.origin.url"], "git@github.com:example/source.git")
        self.assertNotIn("lfs.url", settings)
        self.assertEqual((cache / "HEAD").read_text(), "ref: refs/heads/broker-lfs-unborn\n")
        self.assertEqual(command.call_args.kwargs["cwd"], cache)
        self.assertEqual(settings["credential.helper"], "")
        self.assertEqual(settings["lfs.storage"], str(cache / "lfs"))
        self.assertIn("StrictHostKeyChecking=yes", env["GIT_SSH_COMMAND"])
        binary.write_bytes(b"changed")
        with patch.object(operations, "command") as command, self.assertRaises(broker.BrokerError):
            operations.fetch_lfs(A)
        command.assert_not_called()

    def test_automatic_promotion_advances_history_and_rejects_force_pushed_branch(self):
        repo = self.root / "source-history"
        subprocess.run(["git", "init", "-q", repo], check=True)
        subprocess.run(["git", "-C", repo, "config", "user.name", "Fixture"], check=True)
        subprocess.run(["git", "-C", repo, "config", "user.email", "fixture@example.invalid"], check=True)
        def commit(value):
            (repo / "source").write_text(value)
            subprocess.run(["git", "-C", repo, "add", "."], check=True)
            subprocess.run(["git", "-C", repo, "commit", "-qm", value], check=True)
            return subprocess.check_output(["git", "-C", repo, "rev-parse", "HEAD"], text=True).strip()
        original = commit("original")
        forward = commit("forward")
        subprocess.run(["git", "-C", repo, "reset", "--hard", original], check=True, capture_output=True)
        divergent = commit("divergent")
        config = dict(self.config, source_cache=repo / ".git", source_deploy_key=self.root / "key",
                      known_hosts=self.root / "known-hosts", engine_config=self.root / "engine.json")
        operations = broker.Operations(config)
        with patch.object(broker.engine, "Engine") as factory, patch.object(operations, "current", return_value=forward):
            runtime = factory.return_value
            runtime.c = {"desired_commit_file": self.root / "desired-master"}
            runtime.status.side_effect = [{"managed_release": original}, {"managed_release": forward}]
            operations.promote(forward, Path("/private/release"))
            runtime.promote.assert_called_once_with(Path("/private/release"), original)
        with patch.object(broker.engine, "Engine") as factory:
            runtime = factory.return_value
            runtime.status.return_value = {"managed_release": forward}
            with self.assertRaises(broker.BrokerError):
                operations.promote(divergent, Path("/private/release"))
            runtime.promote.assert_not_called()

    def test_operator_history_alias_requires_identical_tree_and_new_history_ancestry(self):
        repo = self.root / "rewritten-history"
        subprocess.run(["git", "init", "-q", repo], check=True)
        def git(*args):
            return subprocess.check_output(["git", "-C", str(repo), "-c", "user.name=Fixture",
                "-c", "user.email=fixture@example.invalid", *args]).decode().strip()
        (repo / "source").write_text("original")
        git("add", ".")
        tree = git("write-tree")
        original = git("commit-tree", tree, "-m", "Original metadata")
        rewritten = git("commit-tree", tree, "-m", "Rewritten metadata")
        (repo / "source").write_text("next version")
        git("add", ".")
        next_tree = git("write-tree")
        forward = git("commit-tree", next_tree, "-p", rewritten, "-m", "Next version")
        unrelated = git("commit-tree", next_tree, "-m", "Unrelated branch")
        config = dict(self.config, source_cache=repo / ".git", source_deploy_key=self.root / "key",
                      known_hosts=self.root / "hosts", history_aliases={original: rewritten})
        operations = broker.Operations(config)
        operations.check_successor(original, rewritten)
        operations.check_successor(original, forward)
        with self.assertRaises(broker.BrokerError):
            operations.check_successor(original, unrelated)
        operations.c["history_aliases"] = {original: forward}
        with self.assertRaises(broker.BrokerError):
            operations.check_successor(original, forward)

    def test_already_active_release_needs_no_ancestry_or_new_handoff(self):
        operations = broker.Operations(dict(self.config, engine_config=self.root / "engine.json"))
        with patch.object(broker.engine, "Engine") as factory, patch.object(operations, "git") as git:
            runtime = factory.return_value
            runtime.status.return_value = {"managed_release": A}
            operations.promote(A, Path("/private/release"))
            runtime.promote.assert_not_called()
            git.assert_not_called()


    def test_replacement_verification_requires_exact_healthy_receipt_cid_and_stopped_old_world(self):
        operations=broker.Operations(self.config)
        release=(self.root/'release').resolve()
        proof={'id':'1'*32,'phase':'healthy','to':A,'old_stopped':True,'rollback':False,'replace_same_commit':True,
               'release_path':str(release),'previous_release_path':str(self.root/'old'),
               'container':'2'*64,'from_container':'3'*64}
        runtime_root=self.root/'runtime';(runtime_root/'deployments').mkdir(parents=True)
        receipt=runtime_root/'deployments'/(proof['id']+'.json');broker.engine.write_json(receipt,proof)
        with patch.object(broker.engine,'Engine') as factory:
            runtime=factory.return_value;runtime.root=runtime_root
            runtime.status.return_value={'managed_release':A}
            active={'release':A,'container':proof['container'],'release_path':str(release)}
            runtime.active.return_value=active;runtime.inspect.return_value={'State':{'Running':False}}
            self.assertIs(operations.verify_replacement(A,release,proof),True)
            for change in ({'container':'4'*64},{'release_path':str(self.root/'other')},{'release':B}):
                runtime.active.return_value=dict(active,**change)
                with self.subTest(change=change),self.assertRaises(broker.BrokerError):operations.verify_replacement(A,release,proof)
            runtime.active.return_value=active;runtime.inspect.return_value={'State':{'Running':True}}
            with self.assertRaises(broker.BrokerError):operations.verify_replacement(A,release,proof)
            runtime.inspect.return_value={'State':{'Running':False}}
            for change in ({'phase':'rolled_back_code_only'},{'container':proof['from_container']},
                           {'release_path':proof['previous_release_path']},{'old_stopped':False},{'replace_same_commit':False}):
                with self.subTest(change=change),self.assertRaises(broker.BrokerError):operations.verify_replacement(A,release,dict(proof,**change))
            broker.engine.write_json(receipt,dict(proof,phase='rolled_back_code_only'))
            with self.assertRaises(broker.BrokerError):operations.verify_replacement(A,release,proof)



    def test_unhealthy_failed_handoff_requires_operator_recovery(self):
        operations = broker.Operations(dict(self.config, source_cache=self.root / "source.git", engine_config=self.root / "engine.json"))
        with patch.object(broker.engine, "Engine") as factory, patch.object(operations, "git"), \
                patch.object(operations, "current", return_value=A), patch.object(operations, "status", side_effect=ValueError("unhealthy")), \
                patch.object(operations, "finalize") as finalize:
            runtime = factory.return_value
            runtime.c = {"desired_commit_file": self.root / "desired-master"}
            runtime.status.return_value = {"managed_release": B}
            runtime.promote.side_effect = ValueError("handoff failed")
            with self.assertRaises(broker.PromotionRecoveryRequired):
                operations.promote(A, Path("/private/release"))
            finalize.assert_not_called()
        self.request()
        with patch.object(self.ops, "promote", side_effect=broker.PromotionRecoveryRequired("recovery required")):
            self.broker.process(A)
        self.assertTrue(self.broker.load(A)["recovery_required"])
        self.assertEqual(self.request()["status"], "failed")

    def test_missing_latest_authority_fails_preflight_before_build(self):
        config_path = self.root / "engine.json"
        config_path.write_text("{}")
        operations = broker.Operations(dict(self.config, engine_config=config_path))
        with self.assertRaises(broker.BrokerError):
            operations.preflight()
        config_path.write_text(json.dumps({"desired_commit_file": "relative"}))
        with self.assertRaises(broker.BrokerError):
            operations.preflight()
        config_path.write_text(json.dumps({"desired_commit_file": str(self.root / "desired-master")}))
        operations.preflight()
        self.assertFalse((self.root / "desired-master").exists())
        self.request()
        with patch.object(self.ops, "preflight", side_effect=broker.BrokerError("missing authority")), \
                patch.object(self.ops, "build") as build:
            self.broker.process(A)
            build.assert_not_called()
        self.assertEqual(self.broker.load(A)["status"], "failed")



if __name__ == "__main__":
    unittest.main()

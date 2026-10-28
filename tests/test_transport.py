"""Transport gate tests use Git fixtures and fake container outputs only."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import check_transport as gate

COMMIT = "a" * 40
IMAGE = "sha256:" + "b" * 64
PYTHON_OK = b"Ran 60 tests in 2.345s\n\nOK\n"
NODE_OK = b"TAP version 13\n1..20\n# tests 20\n# suites 0\n# pass 20\n# fail 0\n# cancelled 0\n# skipped 0\n# todo 0\n# duration_ms 12.3\n"


class TransportTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.config = {"python_image": IMAGE, "node_image": IMAGE,
                       "minimum_python_tests": 59, "minimum_node_tests": 20}

    def repository(self):
        source = self.root / "source"
        subprocess.run(["git", "init", "-q", source], check=True)
        subprocess.run(["git", "-C", source, "config", "user.name", "Fixture"], check=True)
        subprocess.run(["git", "-C", source, "config", "user.email", "fixture@example.invalid"], check=True)
        names = ["deploy/cloudflare/test_outbound443_agent.py", "deploy/cloudflare/test_private_relay.py",
                 "deploy/cloudflare/test_wss_gateway.py", "deploy/cloudflare/test_outbound443_worker.mjs",
                 "deploy/cloudflare/outbound443_worker.mjs", "server/multiplayer_server.py",
                 "server/native_contracts.json", "deploy/multiplayer/create_private_certs.py",
                 "deploy/cloudflare/local.env", "deploy/cloudflare/local/private.py",
                 "deploy/admin/agent.py", "deploy/admin/test_agent.py", "deploy/admin/test_worker.mjs",
                 "tools/private_admin.py", "tools/test_admin_cli.py", "deploy/admin/local/private.py"]
        for name in names:
            path = source / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("raise RuntimeError('never execute source on host')")
        return source

    def commit(self, source):
        subprocess.run(["git", "-C", source, "add", "."], check=True)
        subprocess.run(["git", "-C", source, "commit", "-qm", "Fixture"], check=True)
        return subprocess.check_output(["git", "-C", source, "rev-parse", "HEAD"], text=True).strip()

    def test_curates_only_exact_git_regular_blobs_without_private_directories(self):
        source = self.repository()
        commit = self.commit(source)
        (source / "deploy/cloudflare/local/token").write_text("private fixture")
        destination = self.root / "curated"
        destination.mkdir()
        hashes = gate.snapshot(source, commit, destination)
        for name in ("deploy/admin/agent.py", "deploy/admin/test_agent.py", "deploy/admin/test_worker.mjs",
                     "tools/private_admin.py", "tools/test_admin_cli.py"):
            self.assertIn(name, hashes)
        self.assertNotIn("deploy/admin/local/private.py", hashes)
        self.assertNotIn("deploy/cloudflare/local.env", hashes)
        self.assertNotIn("deploy/cloudflare/local/private.py", hashes)
        self.assertFalse((destination / "deploy/cloudflare/local").exists())
        self.assertEqual(gate.engine.tree(destination), hashes)
        self.assertEqual((destination / "server/multiplayer_server.py").read_bytes(),
                         (source / "server/multiplayer_server.py").read_bytes())

    def test_selected_symlink_and_dirty_tracked_worktree_are_rejected(self):
        source = self.repository()
        (source / "deploy/cloudflare/escape.py").symlink_to("/private/credential")
        commit = self.commit(source)
        destination = self.root / "curated"
        destination.mkdir()
        with self.assertRaises(ValueError):
            gate.snapshot(source, commit, destination)
        (source / "deploy/cloudflare/escape.py").unlink()
        (source / "deploy/cloudflare/escape.py").write_text("different")
        with self.assertRaises(ValueError):
            gate.snapshot(source, commit, destination)

    def test_sandboxes_have_only_curated_readonly_source_and_disposable_writable_paths(self):
        for name in ('deploy/cloudflare/test_old.py','deploy/admin/test_agent.py','tools/test_admin_cli.py',
                     'deploy/cloudflare/test_outbound443_worker.mjs','deploy/admin/test_worker.mjs'):
            path=self.root/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_text('# Test fixture')
        for language in ("python", "node"):
            argv = gate.container(IMAGE, self.root, language)
            for flag in ("--network=none", "--read-only", "--user=1000:1000", "--cap-drop=ALL",
                         "--security-opt=no-new-privileges:true", "--pull=never"):
                self.assertIn(flag, argv)
            mounts = [value for value in argv if value.startswith("type=bind,")]
            self.assertIn(f"type=bind,src={self.root},dst=/source,readonly",mounts)
            self.assertTrue(all(value.endswith(',readonly') for value in mounts))
            self.assertEqual([value for value in argv if value.startswith("--env=")],
                             ["--env=HOME=/tmp", "--env=PYTHONDONTWRITEBYTECODE=1"])
            self.assertFalse(any("docker.sock" in value or "token" in value or "secret" in value for value in argv))
        python=gate.container(IMAGE,self.root,'python')
        self.assertEqual(['deploy/cloudflare','deploy/admin','tools'],json.loads(python[python.index('--directories')+1]))
        node=gate.container(IMAGE,self.root,'node')
        self.assertIn('/source/deploy/admin/test_worker.mjs',node)
        self.assertIn('/source/deploy/cloudflare/test_outbound443_worker.mjs',node)

    def test_python_requires_baseline_and_zero_skips_or_expected_failures(self):
        self.assertEqual(gate.python_result(PYTHON_OK, 60)["passed"], 60)
        for bad in (b"Ran 59 tests in 1s\nOK\n", b"Ran 60 tests in 1s\nOK (skipped=1)\n",
                    b"Ran 60 tests in 1s\nFAILED (failures=1)\n", b"OK\n"):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                gate.python_result(bad, 60)

    def test_node_requires_real_baseline_pass_totals_with_zero_skip_fail_cancel_todo(self):
        self.assertEqual(gate.node_result(NODE_OK, 20)["passed"], 20)
        for name in ("fail", "cancelled", "skipped", "todo"):
            with self.subTest(name=name), self.assertRaises(ValueError):
                gate.node_result(NODE_OK.replace(("# " + name + " 0").encode(), ("# " + name + " 1").encode()), 20)
        with self.assertRaises(ValueError):
            gate.node_result(NODE_OK.replace(b"# pass 20", b"# pass 19"), 20)

    def test_config_rejects_commands_mutable_images_and_lowered_baselines(self):
        path = self.root / "config.json"
        for changes in ({"command": ["id"]}, {"source": "/private"}, {"node_image": "node:24"},
                        {"minimum_python_tests": 58}, {"minimum_node_tests": 19},
                        {"python_workers":0}, {"python_workers":4}, {"python_workers":True}):
            path.write_text(json.dumps(dict(self.config, **changes)))
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                gate.config_read(path)

    def test_success_receipt_binds_commit_images_source_and_private_logs(self):
        source = self.repository()
        commit = self.commit(source)
        output = self.root / "transport"
        calls = []
        real_run = subprocess.run
        def run(argv, **kwargs):
            if argv[0] != "docker":
                return real_run(argv, **kwargs)
            calls.append(argv)
            if '/trusted/server_qa.py' in argv:
                index=int(argv[argv.index('--worker')+1]);workers=int(argv[argv.index('--workers')+1])
                inventory=[f'test_{module}.Case.test_{case:02}' for module in ('alpha','beta','gamma') for case in range(20)]
                selected=gate.server_qa.partition(inventory,workers)[index]
                report=dict(worker=index,workers=workers,inventory=inventory,selected=selected,executed=selected,
                            tests=len(selected),passed=True,failures=0,errors=0,skipped=0)
                return subprocess.CompletedProcess(argv,0,(gate.server_qa.MARKER+json.dumps(report)+'\n').encode(),b'')
            return subprocess.CompletedProcess(argv, 0, b"" if "--entrypoint=python3" in argv else NODE_OK,
                                               PYTHON_OK if "--entrypoint=python3" in argv else b"")
        with patch.object(gate.subprocess, "run", side_effect=run):
            receipt = gate.check(self.config, source, commit, output)
        self.assertEqual(len([argv for argv in calls if argv[:2] == ["docker", "run"]]), 2)
        self.assertEqual(len([argv for argv in calls if argv[:2] == ["docker", "rm"]]), 2)
        self.assertEqual(receipt["commit"], commit)
        self.assertTrue(receipt["passed"])
        self.assertEqual(receipt["python_image"], IMAGE)
        for language in ("python", "node"):
            log = output / (language + ".private.log")
            self.assertEqual(log.stat().st_mode & 0o777, 0o600)
            self.assertEqual(receipt["results"][language]["log_sha256"], hashlib.sha256(log.read_bytes()).hexdigest())
        self.assertTrue((output / "transport.json").exists())
        calls.clear()
        with patch.object(gate.subprocess, "run", side_effect=run):
            parallel=gate.check(dict(self.config,python_workers=3),source,commit,self.root/'parallel')
        self.assertEqual(parallel['results']['python']['tests'],60)
        self.assertEqual(parallel['results']['python']['workers'],3)
        self.assertEqual(len(parallel['results']['python']['test_ids']),60)
        self.assertEqual(len([argv for argv in calls if argv[:2]==['docker','run']]),4)
        self.assertEqual(len([argv for argv in calls if argv[:2]==['docker','rm']]),4)

    def test_failed_container_keeps_private_log_and_never_writes_passed_receipt(self):
        source = self.repository()
        commit = self.commit(source)
        output = self.root / "transport"
        real_run = subprocess.run
        def run(argv, **kwargs):
            if argv[0] != "docker":
                return real_run(argv, **kwargs)
            return subprocess.CompletedProcess(argv, 1, b"private diagnostic", b"failed")
        with patch.object(gate.subprocess, "run", side_effect=run), self.assertRaises(ValueError):
            gate.check(self.config, source, commit, output)
        self.assertFalse((output / "transport.json").exists())
        self.assertIn(b"private diagnostic", (output / "python.private.log").read_bytes())

    def test_static_fixtures_are_pinned_copied_data_and_cannot_replace_source_code(self):
        fixture = self.root / "PlayerLevelInfo.ini"
        fixture.write_bytes(b"known static table fixture")
        name = "work/apk/luapack_extracted/GameData/PlayerLevelInfo.ini"
        pin = {"path": str(fixture), "sha256": hashlib.sha256(fixture.read_bytes()).hexdigest()}
        path = self.root / "config.json"
        path.write_text(json.dumps(dict(self.config, fixtures={name: pin})))
        config = gate.config_read(path)
        stage = self.root / "stage"
        stage.mkdir()
        files = gate.copy_fixtures(config, stage)
        self.assertEqual(files, {name: pin["sha256"]})
        self.assertEqual((stage / name).read_bytes(), fixture.read_bytes())
        for unsafe in ("server/multiplayer_server.py", "../escape", "work/apk/luapack_extracted/GameData/../../escape"):
            path.write_text(json.dumps(dict(self.config, fixtures={unsafe: pin})))
            with self.subTest(unsafe=unsafe), self.assertRaises(ValueError):
                gate.config_read(path)
        fixture.write_bytes(b"tampered")
        with self.assertRaises(ValueError):
            gate.copy_fixtures(config, self.root / "new-stage")

    def test_timeout_cleans_generated_container_and_cannot_write_success_receipt(self):
        source = self.repository()
        commit = self.commit(source)
        output = self.root / "transport"
        calls = []
        real_run = subprocess.run
        def run(argv, **kwargs):
            if argv[0] != "docker":
                return real_run(argv, **kwargs)
            calls.append(argv)
            if argv[:2] == ["docker", "run"]:
                raise subprocess.TimeoutExpired(argv, kwargs["timeout"])
            return subprocess.CompletedProcess(argv, 0, b"", b"")
        with patch.object(gate.subprocess, "run", side_effect=run), self.assertRaises(ValueError):
            gate.check(self.config, source, commit, output)
        runs=[call for call in calls if call[:2]==['docker','run']]
        cleanups=[call for call in calls if call[:2]==['docker','rm']]
        names={call[call.index('--name')+1] for call in runs}
        self.assertEqual(len(names),2)
        self.assertEqual({call[-1] for call in cleanups},names)
        self.assertTrue(all(name.startswith('private-private-server-qa-') for name in names))
        self.assertFalse((output / "transport.json").exists())
        self.assertTrue((output / "python.private.log").exists())


if __name__ == "__main__":
    unittest.main()

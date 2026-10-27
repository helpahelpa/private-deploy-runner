"""Offline prebuild tests use disposable Git repositories and fake builders."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import broker
import prebuild

COMMIT = "a" * 40


class FakeOperations(broker.Operations):
    def __init__(self, config, source):
        super().__init__(config)
        self.local_source = Path(source)
        self.head = COMMIT
        self.origin = "git@github.com:example/source.git"
        self.dirty = False
        self.built = []
        self.failed = False

    def git(self, *arguments):
        if arguments[-2:] == ("rev-parse", "HEAD"):
            return self.head.encode()
        if "status" in arguments:
            return b" M source.py" if self.dirty else b""
        if arguments[-3:] == ("config", "--get", "remote.origin.url"):
            return self.origin.encode()
        raise AssertionError(arguments)

    def preflight(self):
        pass

    def current(self):
        raise AssertionError("offline prebuild must not query master or GitHub")

    def promote(self, *args):
        raise AssertionError("prebuild must not promote a runtime")

    def finalize(self, *args):
        raise AssertionError("prebuild must not change registry/auth metadata")

    def build(self, commit, version, stage):
        self.built.append((commit, version))
        if self.failed:
            raise broker.BrokerError("fixture build failure")
        cache = self.root / "builds" / commit
        (cache / "release").mkdir(parents=True)
        (cache / "release/manifest.json").write_text("fixture release manifest")
        broker.engine.write_json(cache / "receipt.json", {"sha": commit, "version": version, "files": broker.engine.tree(cache)})
        return cache / "release"


class PrebuildTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source = self.root / "source"
        self.source.mkdir()
        self.config = {"local_root": self.root / "state", "minimum_version": 63,
                       "source": broker.watch.Identity("example/source", 1, 1)}
        self.ops = FakeOperations(self.config, self.source)

    def run_prebuild(self):
        return prebuild.prebuild(self.config, self.source, COMMIT, operations_factory=lambda *args: self.ops)

    def test_build_reserves_version_and_reuses_identical_verified_cache_without_new_allocation(self):
        first = self.run_prebuild()
        self.assertEqual(first["version"], 63)
        self.assertFalse(first["cached"])
        second = self.run_prebuild()
        self.assertTrue(second["cached"])
        self.assertEqual(first["manifest_sha256"], second["manifest_sha256"])
        self.assertEqual(self.ops.built, [(COMMIT, 63)])
        self.assertEqual(json.loads((self.config["local_root"] / "version.json").read_text()), {"last": 63})
        self.assertFalse((self.config["local_root"] / "jobs").exists())

    def test_failed_build_does_not_recycle_its_version_or_create_a_successful_cache(self):
        self.ops.failed = True
        with self.assertRaises(broker.BrokerError):
            self.run_prebuild()
        self.assertIsNone(self.ops.cached(COMMIT))
        self.ops.failed = False
        self.assertEqual(self.run_prebuild()["version"], 64)

    def test_dirty_wrong_head_and_wrong_origin_fail_before_version_allocation(self):
        for field, value in (("dirty", True), ("head", "b" * 40), ("origin", "git@github.com:other/source.git")):
            with self.subTest(field=field):
                previous = getattr(self.ops, field)
                setattr(self.ops, field, value)
                with self.assertRaises(broker.BrokerError):
                    self.run_prebuild()
                setattr(self.ops, field, previous)
        self.assertFalse((self.config["local_root"] / "version.json").exists())
        self.assertFalse(self.ops.built)

    def test_shared_broker_lock_prevents_cache_or_version_mutation_during_live_worker(self):
        with broker.process_lock(self.config["local_root"]):
            with self.assertRaises(broker.watch.WatchError):
                self.run_prebuild()
        self.assertFalse((self.config["local_root"] / "version.json").exists())

    def test_cache_tampering_fails_without_allocating_new_version_or_rebuilding(self):
        self.run_prebuild()
        (self.config["local_root"] / "builds" / COMMIT / "release/manifest.json").write_text("tampered")
        with self.assertRaises(broker.BrokerError):
            self.run_prebuild()
        self.assertEqual(self.ops.built, [(COMMIT, 63)])

    def test_local_git_import_copies_only_commit_blobs_and_never_runs_source_scripts(self):
        repo = self.source
        subprocess.run(["git", "init", "-q", repo], check=True)
        subprocess.run(["git", "-C", repo, "config", "user.name", "Fixture"], check=True)
        subprocess.run(["git", "-C", repo, "config", "user.email", "fixture@example.invalid"], check=True)
        subprocess.run(["git", "-C", repo, "remote", "add", "origin", "git@github.com:example/source.git"], check=True)
        (repo / "malicious.py").write_text("raise RuntimeError('never execute source on host')")
        subprocess.run(["git", "-C", repo, "add", "."], check=True)
        subprocess.run(["git", "-C", repo, "commit", "-qm", "Fixture"], check=True)
        commit = subprocess.check_output(["git", "-C", repo, "rev-parse", "HEAD"], text=True).strip()
        (repo / "untracked-secret").write_text("must stay outside snapshots")
        config = dict(self.config, source_cache=self.root / "cache.git", source_deploy_key=self.root / "key", known_hosts=self.root / "hosts")
        operations = prebuild.LocalOperations(config, repo)
        prebuild.verify_local(operations, commit)
        snapshot = operations.source(commit)
        self.assertEqual((snapshot / "malicious.py").read_bytes(), (repo / "malicious.py").read_bytes())
        self.assertFalse((snapshot / "untracked-secret").exists())
        broker.engine.verify_source(snapshot, commit)
        with self.assertRaises(broker.BrokerError):
            operations.fetch_lfs(commit)

    def test_preflight_failure_does_not_spend_version_or_start_build(self):
        with patch.object(self.ops, "preflight", side_effect=broker.BrokerError("missing authority")), self.assertRaises(broker.BrokerError):
            self.run_prebuild()
        self.assertFalse(self.ops.built)
        self.assertFalse((self.config["local_root"] / "version.json").exists())


if __name__ == "__main__":
    unittest.main()

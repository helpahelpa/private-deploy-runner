"""A release that changes neither the server image nor the assets must not restart the world."""
import contextlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import uuid

import broker
import watch_master

spec = importlib.util.spec_from_file_location('engine_unchanged', Path(__file__).resolve().parents[1] / 'scripts/deploy_engine.py')
e = importlib.util.module_from_spec(spec)
spec.loader.exec_module(e)

A, B = 'a' * 40, 'b' * 40
TOKEN = 'fixture-private-token-' + 'x' * 40
IMAGE = '1' * 64


class FakeOperations:
    def __init__(self):
        self.master = B
        self.active = A
        self.builds, self.promotions, self.publications, self.verifications = [], [], [], []
        self.finalized = []
        self.unchanged = True

    def current(self):
        return self.master

    def preflight(self):
        pass

    def build(self, sha, version, stage, *, request_id=None, force_full_qa=False):
        self.builds.append(sha)
        return Path('/private/release')

    def release_is_active(self, release):
        return self.unchanged

    def promote(self, sha, release, *, replace_same_commit=False):
        self.promotions.append(sha)
        return {'id': 'd' * 32, 'phase': 'healthy', 'restarted': True, 'to': sha,
                'container': 'c' * 64, 'from_container': 'f' * 64, 'release_path': str(release)}

    def publish_unchanged(self, sha, release):
        self.publications.append(sha)
        return {'id': uuid.uuid4().hex, 'phase': 'unchanged', 'restarted': False, 'to': sha,
                'from': self.active, 'container': 'c' * 64, 'image': IMAGE,
                'release_path': str(release), 'previous_release_path': '/private/older'}

    def verify_publication(self, sha, release, proof):
        self.verifications.append(('unchanged', proof['restarted']))
        return proof['restarted'] is False

    def verify_replacement(self, sha, release, proof):
        self.verifications.append(('replacement', proof['restarted']))
        return proof['restarted'] is True

    def status(self):
        return self.master

    def finalize(self, sha):
        self.finalized.append(sha)


class BrokerPublicationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        token = self.root / 'token'
        token.write_text(TOKEN)
        token.chmod(0o600)
        self.config = {'local_root': self.root / 'state', 'token_file': token, 'minimum_version': 63}
        self.ops = FakeOperations()
        self.broker = broker.Broker(self.config, self.ops)
        patches = [patch.object(watch_master, 'save_desired'),
                   patch.object(broker.watch, 'save_desired')]
        for item in patches:
            item.start()
            self.addCleanup(item.stop)

    def run_job(self):
        request_id = '12345-1'
        self.broker.handle({'op': 'submit', 'sha': B, 'request_id': request_id, 'token': TOKEN})
        self.broker.process(broker.job_key(B, request_id))
        return json.loads((self.broker.root / 'jobs' / (B + '--' + request_id + '.json')).read_text())

    def test_unchanged_release_is_adopted_without_promoting_or_restarting(self):
        job = self.run_job()
        self.assertEqual('success', job['status'])
        self.assertEqual([], self.ops.promotions)
        self.assertEqual([B], self.ops.publications)
        self.assertIs(False, job['server_restarted'])
        self.assertEqual([('unchanged', False)], self.ops.verifications)

    def test_changed_artifact_still_uses_the_handoff(self):
        self.ops.unchanged = False
        job = self.run_job()
        self.assertEqual([B], self.ops.promotions)
        self.assertEqual([], self.ops.publications)
        self.assertIs(True, job['server_restarted'])
        self.assertEqual([('replacement', True)], self.ops.verifications)


class EnginePublicationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / 'deployments').mkdir()
        self.runtime = object.__new__(e.Engine)
        self.runtime.c = {'health_timeout_seconds': 5}
        self.runtime.root = self.root
        self.release = self.root / 'release'
        (self.release / 'assets').mkdir(parents=True)
        (self.release / 'assets' / 'update_config.json').write_text('{"server_version": "4.2.0.1"}')
        self.manifest = {'commit': B, 'image': IMAGE}
        self.active = {'release': A, 'tracked': A, 'image': IMAGE, 'container': 'c' * 64,
                       'release_path': str(self.root / 'old'),
                       'assets_sha256': e.assets_digest(self.release)}

    def patched(self, inspect_image=IMAGE):
        @contextlib.contextmanager
        def lock(*_args, **_kwargs):
            yield
        return [patch.object(self.runtime, 'lock', lock),
                patch.object(self.runtime, 'verify', lambda p: (Path(p), self.manifest)),
                patch.object(self.runtime, 'active', lambda: self.active),
                patch.object(self.runtime, 'healthy', lambda *a, **k: {}),
                patch.object(self.runtime, 'inspect',
                             lambda cid, timeout=None: {'State': {'Running': True}, 'Image': inspect_image})]

    def publish(self):
        for item in self.patched():
            item.start()
            self.addCleanup(item.stop)
        return self.runtime.publish_unchanged(str(self.release), A)

    def test_identical_image_and_assets_are_adopted_and_recorded(self):
        event = self.publish()
        self.assertEqual(('unchanged', False), (event['phase'], event['restarted']))
        self.assertEqual(str(self.release), event['release_path'])
        self.assertEqual(event, json.loads((self.root / 'deployments' / (event['id'] + '.json')).read_text()))
        active = json.loads((self.root / 'active.json').read_text())
        self.assertEqual(B, active['tracked'])
        self.assertEqual(A, active['release'])

    def test_changed_assets_require_a_handoff(self):
        (self.release / 'assets' / 'update_config.json').write_text('{"server_version": "4.2.0.2"}')
        with self.assertRaisesRegex(e.DeploymentError, 'handoff is required'):
            self.publish()

    def test_changed_server_image_requires_a_handoff(self):
        self.manifest = dict(self.manifest, image='2' * 64)
        with self.assertRaisesRegex(e.DeploymentError, 'handoff is required'):
            self.publish()

    def test_running_world_must_still_be_the_expected_image(self):
        for item in self.patched(inspect_image='3' * 64):
            item.start()
            self.addCleanup(item.stop)
        with self.assertRaisesRegex(e.DeploymentError, 'expected image'):
            self.runtime.publish_unchanged(str(self.release), A)

    def test_stale_tracked_commit_is_refused(self):
        with self.assertRaisesRegex(e.DeploymentError, 'Stale unchanged publication'):
            self.publish_with_expected(B)

    def publish_with_expected(self, expected):
        for item in self.patched():
            item.start()
            self.addCleanup(item.stop)
        return self.runtime.publish_unchanged(str(self.release), expected)

    def test_tracked_commit_defaults_to_the_running_release(self):
        self.assertEqual(A, self.runtime.tracked({'release': A}))
        self.assertEqual(B, self.runtime.tracked({'release': A, 'tracked': B}))


if __name__ == '__main__':
    unittest.main()

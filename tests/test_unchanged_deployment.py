"""A release that changes neither the server image nor the assets must not restart the world."""
import contextlib
import importlib.util
import json
from pathlib import Path
import tempfile
import types
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
IMAGE = 'sha256:' + '1' * 64


class FakeOperations:
    def __init__(self):
        self.master = B
        self.active = A
        self.builds, self.promotions, self.publications, self.verifications = [], [], [], []
        self.asset_publications = []
        self.assets = False
        self.finalized = []
        self.unchanged = True

    def current(self):
        return self.master

    def preflight(self):
        pass

    def build(self, sha, version, stage, *, request_id=None, force_full_qa=False):
        self.builds.append(sha)
        return Path('/private/release')

    def assets_can_publish(self, release):
        return self.assets

    def publish_assets(self, sha, release):
        self.asset_publications.append(sha)
        return {'id': uuid.uuid4().hex, 'phase': 'assets', 'restarted': False, 'to': sha,
                'from': self.active, 'container': 'c' * 64, 'image': IMAGE,
                'assets_sha256': 'd' * 64, 'assets_release': sha,
                'release_path': str(release), 'previous_release_path': '/private/older'}

    def verify_assets_publication(self, sha, release, proof):
        self.verifications.append(('assets', proof['restarted']))
        return proof['restarted'] is False

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

    def test_changed_assets_are_published_without_restarting(self):
        self.ops.unchanged = False
        self.ops.assets = True
        job = self.run_job()
        self.assertEqual('success', job['status'])
        self.assertEqual([], self.ops.promotions)
        self.assertEqual([B], self.ops.asset_publications)
        self.assertIs(False, job['server_restarted'])
        self.assertEqual('assets', job['publication'])
        self.assertEqual([('assets', False)], self.ops.verifications)

    def test_changed_artifact_still_uses_the_handoff(self):
        self.ops.unchanged = False
        job = self.run_job()
        self.assertEqual([B], self.ops.promotions)
        self.assertEqual([], self.ops.publications)
        self.assertIs(True, job['server_restarted'])
        self.assertEqual([('replacement', True)], self.ops.verifications)


class ClientMaterialTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.active = self.root / 'active'
        self.client = self.root / 'client'
        self.pack = 'Android_90/UpdateRoot/IncrementPack/%s/Client/GameRes/Resources/Client.bytes.bytes'
        for base, version, payload in ((self.active, '4.2.0.76', b'increment'),
                                       (self.client / 'assets', '4.2.0.99', b'increment')):
            path = base / (self.pack % version)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(payload)
        (self.active / 'update_config.json').write_text('{"server_versions": {"Android_90": "4.2.0.76"}}')
        (self.active / 'client.apk').write_bytes(b'apk')
        self.manifest = {'apk_sha256': e.digest(self.active / 'client.apk'),
                         'asset_files': {self.pack % '4.2.0.99': 'digest'}}
        token = self.root / 'token'
        token.write_text(TOKEN)
        token.chmod(0o600)
        self.operations = types.SimpleNamespace(c={'publish_apk': True})

    def unchanged(self):
        return broker.Operations.client_material_unchanged(self.operations, self.active, self.client, self.manifest)

    def test_identical_client_payload_reuses_the_published_version(self):
        self.assertTrue(self.unchanged())

    def test_static_base_pack_beside_the_client_pack_does_not_force_a_new_version(self):
        base = self.active / (self.pack % '4.2.0.60')
        base.parent.mkdir(parents=True, exist_ok=True)
        base.write_bytes(b'static-base-pack')
        self.assertTrue(self.unchanged())

    def test_changed_pack_payload_publishes_a_new_version(self):
        (self.client / 'assets' / (self.pack % '4.2.0.99')).write_bytes(b'changed')
        self.assertFalse(self.unchanged())

    def test_changed_apk_publishes_a_new_version(self):
        self.manifest = dict(self.manifest, apk_sha256='0' * 64)
        self.assertFalse(self.unchanged())

    def test_missing_published_apk_publishes_a_new_version(self):
        (self.active / 'client.apk').unlink()
        self.assertFalse(self.unchanged())


class ServerContentIdentityTests(unittest.TestCase):
    """A rebuild of identical server sources must not look like a new server."""

    def release(self, root, name, image, source):
        base = Path(root) / name
        base.mkdir(parents=True)
        (base / 'server.json').write_text(json.dumps({'commit': name, 'image': image,
                                                      'base': 'python@sha256:' + '1' * 64,
                                                      'source_files': source}))
        return base

    def test_rebuilt_image_with_identical_sources_is_the_same_server(self):
        with tempfile.TemporaryDirectory() as directory:
            runtime = object.__new__(e.Engine)
            source = {'server/multiplayer_server.py': 'a' * 64}
            active_release = self.release(directory, 'old', 'sha256:' + '1' * 64, source)
            new_release = self.release(directory, 'new', 'sha256:' + '2' * 64, source)
            self.assertEqual(e.server_identity(active_release), e.server_identity(new_release))
            self.assertTrue(runtime.same_server(new_release, {'release_path': str(active_release)}))

    def test_changed_sources_are_a_new_server(self):
        with tempfile.TemporaryDirectory() as directory:
            runtime = object.__new__(e.Engine)
            active_release = self.release(directory, 'old', 'sha256:' + '1' * 64,
                                          {'server/multiplayer_server.py': 'a' * 64})
            new_release = self.release(directory, 'new', 'sha256:' + '1' * 64,
                                       {'server/multiplayer_server.py': 'b' * 64})
            self.assertFalse(runtime.same_server(new_release, {'release_path': str(active_release)}))

    def test_missing_receipts_fall_back_to_the_image_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            runtime = object.__new__(e.Engine)
            bare = Path(directory) / 'bare'
            bare.mkdir()
            (bare / 'manifest.json').write_text(json.dumps({'image': 'sha256:' + '3' * 64}))
            self.assertTrue(runtime.same_server(bare, {'release_path': str(bare), 'image': 'sha256:' + '3' * 64}))
            self.assertFalse(runtime.same_server(bare, {'release_path': str(bare), 'image': 'sha256:' + '4' * 64}))


class PublishedShapeTests(unittest.TestCase):
    """An unpublished world with the intended admin runtime is the same shape."""

    class Admin:
        def __init__(self, running, engine, support):
            self.running, self.engine, self.support = running, engine, support

        def enabled(self, cid=None):
            return self.engine if cid is None else self.running

        def supported(self, release):
            return self.support

    def release(self, root, name):
        base = Path(root) / name
        base.mkdir(parents=True)
        (base / 'server.json').write_text(json.dumps({'commit': name, 'image': IMAGE,
                                                      'base': 'python@sha256:' + '1' * 64,
                                                      'source_files': {'server/multiplayer_server.py': 'a' * 64}}))
        return base

    def runtime(self, *, bindings, running_admin=True, engine_admin=True, support=True):
        runtime = object.__new__(e.Engine)
        # The engine config still names an admin publication; the ingress carries the
        # route and the world itself publishes nothing.
        runtime.c = {'https_port': 19543, 'game_port': 19544,
                     'admin_publish_address': '127.0.0.1', 'admin_public_port': 19445}
        runtime.admin = self.Admin(running_admin, engine_admin, support)
        runtime.inspect = lambda cid: {'HostConfig': {'PortBindings': bindings}}
        return runtime

    def test_unpublished_world_is_the_same_shape(self):
        with tempfile.TemporaryDirectory() as directory:
            new, old = self.release(directory, 'new'), self.release(directory, 'old')
            runtime = self.runtime(bindings={})
            self.assertTrue(runtime.same_server(new, {'release_path': str(old), 'container': 'c' * 64}))

    def test_world_host_binding_forces_a_recreation(self):
        with tempfile.TemporaryDirectory() as directory:
            new, old = self.release(directory, 'new'), self.release(directory, 'old')
            runtime = self.runtime(bindings={'9445/tcp': [{'HostIp': '127.0.0.1', 'HostPort': '19445'}]})
            self.assertFalse(runtime.same_server(new, {'release_path': str(old), 'container': 'c' * 64}))

    def test_admin_runtime_mismatch_forces_a_recreation(self):
        with tempfile.TemporaryDirectory() as directory:
            new, old = self.release(directory, 'new'), self.release(directory, 'old')
            for running, engine, support in ((False, True, True), (True, False, True), (True, True, False)):
                with self.subTest(running=running, engine=engine, support=support):
                    runtime = self.runtime(bindings={}, running_admin=running,
                                           engine_admin=engine, support=support)
                    self.assertFalse(runtime.same_server(new, {'release_path': str(old), 'container': 'c' * 64}))

    def test_missing_container_falls_back_to_the_content_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            new, old = self.release(directory, 'new'), self.release(directory, 'old')
            runtime = object.__new__(e.Engine)
            self.assertTrue(runtime.same_server(new, {'release_path': str(old)}))


class AssetsPublicationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / 'deployments').mkdir()
        self.runtime = object.__new__(e.Engine)
        self.runtime.c = {'health_timeout_seconds': 5}
        self.runtime.root = self.root
        self.old = self.release('old', '4.2.0.76', b'old-pack')
        self.new = self.release('new', '4.2.0.99', b'new-pack')
        self.manifest = {'commit': B, 'image': IMAGE}
        self.active = {'release': A, 'tracked': A, 'assets_release': A, 'assets_release_path': str(self.old), 'image': IMAGE,
                       'container': 'c' * 64, 'release_path': str(self.old),
                       'assets_sha256': e.assets_digest(self.old)}

    def release(self, name, version, payload):
        base = self.root / name
        pack = base / 'assets/Android_90/UpdateRoot/IncrementPack' / version / 'Client/GameRes/Resources'
        pack.mkdir(parents=True)
        (pack / 'Client.bytes.bytes').write_bytes(payload)
        (base / 'assets/update_config.json').write_text(json.dumps({'server_versions': {'Android_90': version}}))
        (base / 'server.json').write_text(json.dumps({'image': IMAGE, 'base': 'python@sha256:' + '1' * 64,
                                                     'source_files': {'server/x.py': 'a' * 64}}))
        return base

    def patched(self, *, reload=True, mount=None):
        @contextlib.contextmanager
        def lock(*_args, **_kwargs):
            yield
        return [patch.object(self.runtime, 'lock', lock),
                patch.object(self.runtime, 'verify',
                             lambda p: (Path(p), dict(self.manifest, commit=Path(p).name == 'new' and B or A))),
                patch.object(self.runtime, 'active', lambda: self.active),
                patch.object(self.runtime, 'healthy', lambda *a, **k: {}),
                patch.object(self.runtime, 'check_desired', lambda commit: None),
                patch.object(self.runtime, 'control', lambda *a, **k: {'assets_reload': reload}),
                patch.object(self.runtime, 'container_assets_source',
                             lambda cid, deadline=None: self.runtime.served_assets if mount is None else mount),
                patch.object(self.runtime, 'inspect',
                             lambda cid, timeout=None: {'State': {'Running': True}, 'Image': IMAGE})]

    def publish(self, **options):
        for item in self.patched(**options):
            item.start()
            self.addCleanup(item.stop)
        return self.runtime.publish_assets(str(self.new), A)

    def test_changed_assets_are_published_in_place(self):
        event = self.publish()
        self.assertEqual(('assets', False), (event['phase'], event['restarted']))
        self.assertEqual(e.assets_digest(self.new), event['assets_sha256'])
        served = self.runtime.served_assets
        self.assertTrue((served / 'Android_90/UpdateRoot/IncrementPack/4.2.0.99/Client/GameRes/Resources/Client.bytes.bytes').is_file())
        self.assertTrue((served / 'update_config.json').is_file())
        active = json.loads((self.root / 'active.json').read_text())
        self.assertEqual((B, B, A), (active['tracked'], active['assets_release'], active['release']))
        self.assertEqual(event, json.loads((self.root / 'deployments' / (event['id'] + '.json')).read_text()))
        self.assertEqual(str(self.new), active['assets_release_path'])

    def test_previous_release_files_are_retained_and_older_ones_pruned(self):
        served = self.runtime.served_assets
        self.runtime.sync_assets(str(self.old))
        stale = served / 'Android_90/UpdateRoot/IncrementPack/4.2.0.50/Client/GameRes/Resources/Client.bytes.bytes'
        stale.parent.mkdir(parents=True, exist_ok=True)
        stale.write_bytes(b'stale')
        self.publish()
        self.assertFalse(stale.parent.parent.parent.parent.exists())
        self.assertTrue((served / 'Android_90/UpdateRoot/IncrementPack/4.2.0.76/Client/GameRes/Resources/Client.bytes.bytes').is_file())
        self.assertTrue((served / 'Android_90/UpdateRoot/IncrementPack/4.2.0.99/Client/GameRes/Resources/Client.bytes.bytes').is_file())

    def test_world_without_reload_support_requires_a_handoff(self):
        with self.assertRaisesRegex(e.DeploymentError, 'cannot reload'):
            self.publish(reload=False)

    def test_world_serving_a_release_directory_requires_a_handoff(self):
        with self.assertRaisesRegex(e.DeploymentError, 'serves a release directory'):
            self.publish(mount=self.old / 'assets')

    def test_identical_assets_require_no_publication(self):
        self.active = dict(self.active, assets_sha256=e.assets_digest(self.new))
        with self.assertRaisesRegex(e.DeploymentError, 'identical assets|Identical assets'):
            self.publish()

    def test_changed_server_image_requires_a_handoff(self):
        self.manifest = dict(self.manifest, image='sha256:' + '2' * 64)
        (self.new / 'server.json').write_text(json.dumps({'image': 'sha256:' + '2' * 64,
                                                         'base': 'python@sha256:' + '1' * 64,
                                                         'source_files': {'server/x.py': 'b' * 64}}))
        with self.assertRaisesRegex(e.DeploymentError, 'requires a handoff'):
            self.publish()


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
        (self.release / 'server.json').write_text(json.dumps({'image': IMAGE, 'base': 'python@sha256:' + '1' * 64,
                                                             'source_files': {'server/x.py': 'a' * 64}}))
        (self.release / 'assets' / 'update_config.json').write_text('{"server_version": "4.2.0.1"}')
        self.manifest = {'commit': B, 'image': IMAGE}
        old = self.root / 'old'
        old.mkdir()
        (old / 'server.json').write_text(json.dumps({'image': IMAGE, 'base': 'python@sha256:' + '1' * 64,
                                                    'source_files': {'server/x.py': 'a' * 64}}))
        self.active = {'release': A, 'tracked': A, 'image': IMAGE, 'container': 'c' * 64,
                       'release_path': str(old),
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

    def test_rebuilt_server_with_identical_sources_is_adopted_without_a_restart(self):
        # A rebuild of identical sources yields a new image id; content identity wins.
        self.manifest = dict(self.manifest, image='sha256:' + '9' * 64)
        (self.release / 'server.json').write_text(json.dumps({
            'image': 'sha256:' + '9' * 64, 'base': 'python@sha256:' + '1' * 64,
            'source_files': {'server/x.py': 'a' * 64}}))
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

    def test_changed_server_content_requires_a_handoff(self):
        self.manifest = dict(self.manifest, image='sha256:' + '2' * 64)
        (self.release / 'server.json').write_text(json.dumps({'image': 'sha256:' + '2' * 64,
                                                             'base': 'python@sha256:' + '1' * 64,
                                                             'source_files': {'server/x.py': 'b' * 64}}))
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

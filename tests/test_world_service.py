"""Active-world supervision never bypasses trusted recovery or its handoff lock."""
import json
import os
from pathlib import Path
import shutil
import socket
import sys
import tempfile
import threading
import unittest
import uuid
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import deploy_engine as e
import world_service as w


class WorldServiceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        config = {'local_root': 'state', 'project': 'guardian-fixture', 'data_volume': 'guardian-data',
                  'game_data': 'game', 'certificates': 'certs', 'control': 'control',
                  'asset_origin': 'https://assets.example.invalid', 'https_port': 23443, 'game_port': 23444,
                  'handoff_timeout_seconds': 30, 'health_timeout_seconds': 2,
                  'backup_limit_bytes': 10000000, 'data_compatibility': e.COMPATIBILITY}
        self.config = self.root / 'config.json'
        e.write_json(self.config, config)
        self.engine = e.Engine(self.config)
        self.active = {'release': 'a' * 40, 'image': 'sha256:' + 'b' * 64,
                       'container': 'c' * 64, 'ingress': 'd' * 64,
                       'release_path': str(self.root / 'release'), 'assets_sha256': 'e' * 64}
        e.write_json(self.engine.root / 'active.json', self.active)
        self.clock = Mock(return_value=100)
        self.service = w.WorldService(self.engine, clock=self.clock)
        self.recovery = {key: self.active[key] for key in ('release', 'container', 'ingress')}
        self.status = {'release': self.active['release'], 'compatibility': e.PROTOCOL, 'write_fenced': False}

    def prime(self):
        with patch.object(self.engine, 'recover_active', return_value=self.recovery) as recover:
            self.assertEqual('recovered', self.service.tick())
            recover.assert_called_once_with()


    def test_handoff_lock_contention_never_probes_or_restarts_previous_world(self):
        other = e.Engine(self.config)
        with other.lock(), patch.object(w, 'run') as command, patch.object(self.engine, 'recover_active') as recover:
            self.assertEqual('deployment_in_progress', self.service.tick())
            command.assert_not_called()
            recover.assert_not_called()








    def test_probe_rejects_container_names_and_option_injection(self):
        for value in ('world', '--all', 'c' * 12, None):
            with self.subTest(value=value), patch.object(w, 'run') as command, self.assertRaises(e.DeploymentError):
                self.service.running(value)
            command.assert_not_called()

    def test_service_survives_outage_and_logs_no_private_error_details(self):
        stopped = threading.Event()
        events = []
        service = Mock()
        service.tick.side_effect = [OSError('secret-token /private/config'), 'recovered', 'healthy']
        def wait(_):
            if service.tick.call_count == 3:
                stopped.set()
        with patch.object(stopped, 'wait', side_effect=wait):
            self.assertEqual(0, w.serve(service, stopped=stopped, emit=lambda text, **_: events.append(text)))
        self.assertEqual(['World service: recovery_pending', 'World service: recovered', 'World service: healthy'], events)
        self.assertNotIn('secret', '\n'.join(events))

    def test_once_failure_and_invalid_intervals(self):
        service = Mock()
        service.tick.side_effect = OSError('private')
        self.assertEqual(1, w.serve(service, once=True, emit=lambda *_, **__: None))
        for value in (0, 61):
            with self.assertRaises(e.DeploymentError):
                w.serve(service, poll_seconds=value, once=True)


@unittest.skipUnless(os.environ.get('PRIVATE_ENGINE_TEST_IMAGE') and os.environ.get('PRIVATE_ENGINE_TEST_GAME_DATA'),
                     'Set test image and GameData paths for disposable Docker supervision integration')
class DockerWorldServiceTests(unittest.TestCase):
    # Reuse configuration creation only; the deterministic tests remain above.
    setUp = WorldServiceTests.setUp

    def test_crashed_active_world_and_ingress_recover_without_reviving_old_writer_or_losing_data(self):
        image = os.environ['PRIVATE_ENGINE_TEST_IMAGE']
        self.assertRegex(image, r'^sha256:[0-9a-f]{64}$')
        tag = 'private-guardian-test-' + uuid.uuid4().hex[:12]
        engine = self.engine
        engine.c.update(project=tag, data_volume=tag + '-data',
                        game_data=Path(os.environ['PRIVATE_ENGINE_TEST_GAME_DATA']).resolve())
        engine.network = tag + '-internal'
        engine.ingress_network = tag + '-ingress'
        engine.ingress_name = tag + '-ingress'
        engine.world_alias = tag + '-active-world'
        ports = []
        for _ in range(2):
            with socket.socket() as listener:
                listener.bind(('127.0.0.1', 0))
                ports.append(listener.getsockname()[1])
        engine.c.update(https_port=ports[0], game_port=ports[1])
        cids = []
        def cleanup():
            for cid in cids + [engine.ingress_name]:
                try:
                    engine.docker('rm', '--force', cid)
                except e.DeploymentError:
                    pass
            for args in (('network', 'rm', engine.network), ('network', 'rm', engine.ingress_network),
                         ('volume', 'rm', engine.c['data_volume'])):
                try:
                    engine.docker(*args)
                except e.DeploymentError:
                    pass
        self.addCleanup(cleanup)
        engine.docker('volume', 'create', engine.c['data_volume'])
        certs = self.root / 'fixtures'
        e.make_test_certs(certs)
        for dirname in ('game', 'certs', 'control'):
            (self.root / dirname).mkdir(exist_ok=True)
        for name in ('server.crt', 'server.key', 'ca.crt'):
            shutil.copyfile(certs / name, self.root / 'certs' / name)
        secret = self.root / 'control' / 'secret'
        secret.write_text('disposable-guardian-secret-' + uuid.uuid4().hex)
        secret.chmod(0o600)
        release = self.root / 'release'
        (release / 'assets').mkdir(parents=True)
        (release / 'assets' / 'update_config.json').write_text('{}')
        old = {'commit': 'a' * 40, 'image': image}
        current = dict(old, commit='b' * 40)
        old_cid = engine.start(release, old)
        cids.append(old_cid)
        engine.healthy(old_cid, release, old, w.time.monotonic() + 10)
        engine.docker('stop', '--time', '2', old_cid)
        cid = engine.start(release, current)
        cids.append(cid)
        engine.healthy(cid, release, current, w.time.monotonic() + 10)
        engine.docker('exec', cid, 'python', '-I', '-c',
                      "import sqlite3;db=sqlite3.connect('/data/guardian-fixture.sqlite3');"
                      "db.execute('CREATE TABLE earned(value)');db.execute('INSERT INTO earned VALUES(137)');db.commit()")
        engine.record_active(cid, release, current)
        service = w.WorldService(engine)
        # Release attestation is an explicit synthetic fixture, as in the
        # engine integration tests; all real container/isolation/control/data
        # checks and exact-CID recovery execute unchanged.
        with patch.object(engine, 'verify', return_value=(release, current)):
            self.assertEqual('recovered', service.tick())
            engine.docker('kill', cid)
            engine.docker('stop', '--time', '2', engine.ingress_name)
            self.assertEqual('recovered', service.tick())
            self.assertEqual('healthy', service.tick())
        self.assertFalse(engine.inspect(old_cid)['State']['Running'])
        self.assertEqual(cid, engine.active()['container'])
        self.assertEqual(b'137', engine.docker('exec', cid, 'python', '-I', '-c',
                         "import sqlite3;print(sqlite3.connect('/data/guardian-fixture.sqlite3').execute('SELECT value FROM earned').fetchone()[0])").strip())


if __name__ == '__main__':
    unittest.main()

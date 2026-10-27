"""Per-user persistent world service installation without touching systemd."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('install_services', ROOT / 'scripts/install_services.py')
services = importlib.util.module_from_spec(spec)
spec.loader.exec_module(services)


class ServiceInstallationTests(unittest.TestCase):
    def test_world_supervisor_enabled_before_broker_and_watcher_without_startup_docker_dependency(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config = root / 'services.json'
            config.write_text(json.dumps({'engine_config': '/config/engine.json', 'broker_config': '/config/broker.json',
                                          'watcher_config': '/config/watcher.json', 'python_dependencies': '/opt/dependencies',
                                          'tool_path': '/usr/bin:/bin'}))
            with patch.object(services.Path, 'home', return_value=root), patch.object(services.subprocess, 'run') as command:
                services.install(config, activate=True)
            units = root / '.config/systemd/user'
            world = (units / 'private-world.service').read_text()
            broker = (units / 'private-deploy-broker.service').read_text()
            watch = (units / 'private-deploy-watch.service').read_text()
            self.assertIn('Restart=always', world)
            self.assertIn('world_service.py', world)
            self.assertIn('--config "/config/engine.json"', world)
            self.assertIn('WantedBy=default.target', world)
            self.assertIn('After=private-world.service', broker)
            self.assertIn('Wants=private-world.service', broker)
            self.assertNotIn('ExecStartPre=', broker)
            self.assertIn('After=private-deploy-broker.service', watch)
            self.assertEqual(['systemctl', '--user', 'daemon-reload'], command.call_args_list[0].args[0])
            self.assertEqual(['systemctl', '--user', 'enable', '--now', 'private-world.service',
                              'private-deploy-broker.service', 'private-deploy-watch.service'], command.call_args_list[1].args[0])
            self.assertTrue(all(path.stat().st_mode & 0o777 == 0o600 for path in units.iterdir()))

    def test_unsafe_unit_values_rejected(self):
        for value in ('config\nExecStart=malicious', '%h/private', 'a\x00b'):
            with self.subTest(value=value), self.assertRaises(ValueError):
                services.quoted(value)


if __name__ == '__main__':
    unittest.main()

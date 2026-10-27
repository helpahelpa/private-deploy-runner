"""Container lifecycle and Java namespace boundaries; no live world operations."""
import importlib.util
import os
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import zipfile

spec = importlib.util.spec_from_file_location('client_cleanup_builder', Path(__file__).resolve().parents[1] / 'scripts/build_client.py')
b = importlib.util.module_from_spec(spec)
spec.loader.exec_module(b)


class ClientCleanupTests(unittest.TestCase):
    def setUp(self):
        self.args = ['docker', 'run', '--rm', '--network=none', 'fixture-image', 'fixture-test']

    def completed(self, code=0, stderr=b''):
        return SimpleNamespace(returncode=code, stdout=b'fixture-result', stderr=stderr)

    def test_success_removes_owned_cid_and_adds_unique_labels(self):
        commands = []
        def process(argv, **kwargs):
            commands.append(argv)
            if argv[:2] == ['docker', 'run']:
                Path(argv[argv.index('--cidfile') + 1]).write_text('a' * 64)
            return self.completed()
        original = self.args[:]
        with patch.object(b.subprocess, 'run', side_effect=process):
            self.assertEqual(b'fixture-result', b.sandbox_run(self.args, timeout=1).stdout)
        self.assertEqual(original, self.args)
        self.assertIn('private.private-role=client-qa', commands[0])
        self.assertRegex(commands[0][commands[0].index('--name') + 1], r'^private-private-client-qa-[0-9a-f]{32}$')
        self.assertEqual(['docker', 'rm', '--force', 'a' * 64], commands[-1])
        self.assertFalse(Path(commands[0][commands[0].index('--cidfile') + 1]).exists())

    def test_timeout_removes_cid_and_preserves_failure(self):
        commands = []
        def process(argv, **kwargs):
            commands.append(argv)
            if argv[:2] == ['docker', 'run']:
                Path(argv[argv.index('--cidfile') + 1]).write_text('b' * 64)
                raise subprocess.TimeoutExpired(argv, kwargs['timeout'])
            return self.completed()
        with patch.object(b.subprocess, 'run', side_effect=process):
            with self.assertRaises(subprocess.TimeoutExpired):
                b.sandbox_run(self.args, timeout=1)
        self.assertEqual(['docker', 'rm', '--force', 'b' * 64], commands[-1])

    def test_startup_timeout_without_cid_uses_generated_name(self):
        commands = []
        def process(argv, **kwargs):
            commands.append(argv)
            if argv[:2] == ['docker', 'run']:
                raise subprocess.TimeoutExpired(argv, kwargs['timeout'])
            return self.completed()
        with patch.object(b.subprocess, 'run', side_effect=process):
            with self.assertRaises(subprocess.TimeoutExpired):
                b.sandbox_run(self.args, timeout=1)
        self.assertEqual(commands[0][commands[0].index('--name') + 1], commands[-1][-1])

    def test_invalid_cid_cannot_select_cleanup_target(self):
        commands = []
        def process(argv, **kwargs):
            commands.append(argv)
            if argv[:2] == ['docker', 'run']:
                Path(argv[argv.index('--cidfile') + 1]).write_text('untrusted-target')
            return self.completed()
        with patch.object(b.subprocess, 'run', side_effect=process):
            b.sandbox_run(self.args, timeout=1)
        self.assertEqual(commands[0][commands[0].index('--name') + 1], commands[-1][-1])

    def test_daemon_cleanup_errors_fail_closed_but_already_removed_is_expected(self):
        for error, expected in ((b'Cannot connect to Docker daemon', True), (b'Error response from daemon: No such container: fixture', False)):
            def process(argv, **kwargs):
                return self.completed(1, error) if argv[:2] == ['docker', 'rm'] else self.completed()
            with self.subTest(error=error), patch.object(b.subprocess, 'run', side_effect=process):
                if expected:
                    with self.assertRaisesRegex(ValueError, 'cleanup failed'):
                        b.sandbox_run(self.args, timeout=1)
                else:
                    self.assertEqual(0, b.sandbox_run(self.args, timeout=1).returncode)

    def test_cleanup_timeout_fails_closed(self):
        def process(argv, **kwargs):
            if argv[:2] == ['docker', 'rm']:
                raise subprocess.TimeoutExpired(argv, kwargs['timeout'])
            return self.completed()
        with patch.object(b.subprocess, 'run', side_effect=process):
            with self.assertRaisesRegex(ValueError, 'cleanup exceeded'):
                b.sandbox_run(self.args, timeout=1)

    def test_runtime_identity_and_runtime_commands_cannot_enter_helper(self):
        for args in (['docker', 'start', 'live'], ['docker', 'run', '--name', 'live', 'image'], ['docker', 'run', '--cidfile=/private/cid', 'image']):
            with self.subTest(args=args), self.assertRaises(ValueError):
                b.sandbox_run(args, timeout=1)

    def test_namespace_guard_requires_activity_and_excludes_original_stub(self):
        accepted = ['Lprivateworld/PrivateActivity;', 'Lprivateworld/Bridge;', 'Lprivateworld/PrivateActivity$1;']
        self.assertEqual(accepted, b.validate_bridge_classes(accepted))
        for names in ([], ['Lprivateworld/Bridge;'], ['Lprivateworld/PrivateActivity;', 'Lcom/fl/private/UnityPlayerNativeActivity;'], ['Lprivateworld/PrivateActivity;', 'Lother/Injected;']):
            with self.subTest(names=names), self.assertRaisesRegex(ValueError, 'non-bridge'):
                b.validate_bridge_classes(names)


@unittest.skipUnless(os.environ.get('PRIVATE_CLIENT_CLEANUP_DOCKER') == '1', 'Enable restricted Docker cleanup regression explicitly')
class RealClientSandboxTests(unittest.TestCase):
    def test_self_stopped_code_is_removed_after_one_second_timeout(self):
        real_run = subprocess.run
        commands, observed = [], {}
        def recorded(argv, **kwargs):
            commands.append(argv)
            try:
                return real_run(argv, **kwargs)
            except subprocess.TimeoutExpired as error:
                observed['stdout'] = error.stdout or b''
                raise
        image = os.environ['PRIVATE_CLIENT_CLEANUP_IMAGE']
        args = ['docker', 'run', '--rm', '--init', '--pull=never', '--network=none', '--read-only',
                '--user=1000:1000', '--cap-drop=ALL', '--security-opt=no-new-privileges', '--memory=64m',
                '--pids-limit=16', '--entrypoint=python3', image, '-I', '-c',
                "import os,signal;print('client-qa-self-stopped',flush=True);os.kill(os.getpid(),signal.SIGSTOP)"]
        name = None
        try:
            with patch.object(b.subprocess, 'run', side_effect=recorded):
                with self.assertRaises(subprocess.TimeoutExpired):
                    b.sandbox_run(args, timeout=1)
            run = commands[0]
            name = run[run.index('--name') + 1]
            self.assertIn(b'client-qa-self-stopped', observed.get('stdout', b''), 'Code must actually self-stop before timeout')
            inspection = real_run(['docker', 'inspect', name], capture_output=True, timeout=10)
            self.assertNotEqual(0, inspection.returncode)
            remaining = real_run(['docker', 'ps', '--all', '--quiet', '--filter', 'label=private.private-qa-id=' + name.rsplit('-', 1)[1]], capture_output=True, timeout=10)
            self.assertEqual(0, remaining.returncode)
            self.assertEqual(b'', remaining.stdout.strip())
        finally:
            if name:
                real_run(['docker', 'rm', '--force', name], capture_output=True, timeout=10)


@unittest.skipUnless(os.environ.get('PRIVATE_CLIENT_CLEANUP_APK'), 'Enable the current delivered DEX fixture explicitly')
class CurrentClientDexTests(unittest.TestCase):
    def test_current_client_dex_passes_restored_reviewed_guard(self):
        import sys
        sys.path[:0] = [str(b.VENDOR / 'launch-build'), str(b.VENDOR / 'server')]
        import prepare_multiplayer_client as trusted
        with zipfile.ZipFile(os.environ['PRIVATE_CLIENT_CLEANUP_APK']) as apk:
            names = trusted.dex_classes(apk.read('classes2.dex'))
        self.assertGreater(len(names), 10)
        self.assertEqual(names, b.validate_bridge_classes(names))


if __name__ == '__main__':
    unittest.main()

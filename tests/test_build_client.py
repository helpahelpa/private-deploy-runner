"""Security regression tests for the private client build boundary."""
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / 'scripts/build_client.py'
spec = importlib.util.spec_from_file_location('private_build_client', SCRIPT)
build = importlib.util.module_from_spec(spec)
spec.loader.exec_module(build)


class ClientBoundaryTests(unittest.TestCase):
    def repository(self, root):
        subprocess.run(['git', 'init', '-q', root], check=True)
        subprocess.run(['git', '-C', root, 'config', 'user.email', 'fixture@example.invalid'], check=True)
        subprocess.run(['git', '-C', root, 'config', 'user.name', 'Fixture'], check=True)

    def commit(self, root):
        subprocess.run(['git', '-C', root, 'add', '.'], check=True)
        subprocess.run(['git', '-C', root, 'commit', '-qm', 'Fixture'], check=True)
        return subprocess.check_output(['git', '-C', root, 'rev-parse', 'HEAD'], text=True).strip()

    def test_exact_git_blobs_ignore_dirty_worktree_and_never_execute_hooks(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repo = root / 'repo'
            self.repository(repo)
            (repo / 'prepare_multiplayer_client.py').write_text('raise SystemExit("host execution forbidden")')
            (repo / 'Build.csproj').write_text('<Project><Target Name="Malicious" /></Project>')
            (repo / 'source.java').write_text('original')
            commit = self.commit(repo)
            (repo / 'source.java').write_text('dirty')
            snapshot = root / 'snapshot'
            snapshot.mkdir()
            pins = build.snapshot(repo, commit, snapshot)
            self.assertEqual((snapshot / 'source.java').read_text(), 'original')
            self.assertIn('Build.csproj', pins)
            self.assertEqual(pins['source.java'], build.digest(snapshot / 'source.java'))

    def test_lfs_data_is_materialized_only_when_commit_pointer_hash_matches(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repo = root / 'repo'
            self.repository(repo)
            payload = b'original binary fixture'
            import hashlib
            checksum = hashlib.sha256(payload).hexdigest()
            (repo / 'original.dll').write_text('version https://git-lfs.github.com/spec/v1\noid sha256:' + checksum + '\nsize ' + str(len(payload)) + '\n')
            commit = self.commit(repo)
            (repo / 'original.dll').write_bytes(payload)
            snapshot = root / 'snapshot'
            snapshot.mkdir()
            build.snapshot(repo, commit, snapshot)
            self.assertEqual((snapshot / 'original.dll').read_bytes(), payload)
            (repo / 'original.dll').write_bytes(b'tampered fixture')
            with self.assertRaisesRegex(ValueError, 'LFS object fingerprint'):
                build.snapshot(repo, commit, root / 'another')

    def test_source_symlink_cannot_exfiltrate_private_host_file(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repo = root / 'repo'
            self.repository(repo)
            (repo / 'read-private').symlink_to('/private-signing-key')
            commit = self.commit(repo)
            with self.assertRaisesRegex(ValueError, 'regular files'):
                build.snapshot(repo, commit, root / 'snapshot')

    def test_only_java_and_cs_production_blobs_enter_compiler(self):
        entries = {'launch-build/multiplayer-client/PrivateActivity.java': '1',
                   'launch-build/multiplayer-client/Bridge.java': '2',
                   'launch-build/multiplayer-client/WireTest.java': '3',
                   'launch-build/multiplayer-client/TlsProbe.java': '4',
                   'launch-build/coop-client/Runtime.cs': '5',
                   'launch-build/coop-client/build.csproj': '6',
                   'launch-build/prepare_multiplayer_client.py': '7'}
        self.assertEqual(set(build.production_sources(entries)), {
            'launch-build/multiplayer-client/PrivateActivity.java',
            'launch-build/multiplayer-client/Bridge.java', 'launch-build/coop-client/Runtime.cs'})
        entries['launch-build/coop-client/@injected.cs'] = '8'
        with self.assertRaisesRegex(ValueError, 'filename'):
            build.production_sources(entries)

    def test_sandbox_has_no_network_privileges_socket_or_signer(self):
        command = build.container_command({'image': 'sha256:' + '1' * 64},
            [('/tmp/source', '/source'), ('/tmp/trusted', '/trusted')], ['/trusted/test.py', '[]'])
        for required in ('--network=none', '--read-only', '--user=1000:1000',
                         '--cap-drop=ALL', '--security-opt=no-new-privileges', '--pull=never'):
            self.assertIn(required, command)
        self.assertTrue(all('docker.sock' not in arg and 'signing' not in arg for arg in command))
        self.assertTrue(all(arg.endswith(',readonly') for arg in command if arg.startswith('type=bind')))
        with self.assertRaisesRegex(ValueError, 'immutable'):
            build.container_command({'image': 'mutable:latest'}, [], ['-c', 'pass'])

    def test_signing_input_must_be_pinned_regular_file(self):
        with tempfile.TemporaryDirectory() as directory:
            file = Path(directory) / 'key'
            file.write_bytes(b'fixture')
            config = {'path': str(file), 'sha256': build.digest(file)}
            self.assertEqual(build.checked_input(config), file)
            file.write_bytes(b'replaced')
            with self.assertRaisesRegex(ValueError, 'fingerprint'):
                build.checked_input(config)
            alias = file.with_name('alias')
            alias.symlink_to(file)
            with self.assertRaisesRegex(ValueError, 'fingerprint'):
                build.checked_input({'path': str(alias), 'sha256': build.digest(file)})


if __name__ == '__main__':
    unittest.main()

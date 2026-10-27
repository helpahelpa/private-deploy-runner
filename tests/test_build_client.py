"""Security regression tests for the private client build boundary."""
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import zipfile

SCRIPT = Path(__file__).resolve().parents[1] / 'scripts/build_client.py'
sys.path.insert(0, str(SCRIPT.parent))
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

    def test_download_credential_is_optional_pinned_and_private(self):
        self.assertIsNone(build.apk_download_credentials({}))
        with tempfile.TemporaryDirectory() as directory:
            credential = Path(directory) / 'download.json'
            credential.write_text(json.dumps({'username': 'user', 'password': 'fixture-download-password'}))
            credential.chmod(0o600)
            config = {'apk_download_credentials': {'path': str(credential), 'sha256': build.digest(credential)}}
            self.assertEqual(credential, build.apk_download_credentials(config))
            credential.chmod(0o644)
            with self.assertRaisesRegex(ValueError, 'private file permissions'):
                build.apk_download_credentials(config)
            credential.chmod(0o600)
            credential.write_text('rotated fixture')
            with self.assertRaisesRegex(ValueError, 'fingerprint'):
                build.apk_download_credentials(config)

    def test_download_credential_cannot_enter_trusted_or_toolchain_mounts(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory);vendor = root / 'trusted';vendor.mkdir()
            credential = root / 'download.json';credential.write_text('fixture')
            inputs = {'key': root / 'key', 'cert': root / 'cert'}
            build.validate_build_mounts({}, inputs, vendor, credential)
            with self.assertRaisesRegex(ValueError, 'outside trusted tooling'):
                build.validate_build_mounts({}, inputs, vendor, vendor / 'download.json')
            with self.assertRaisesRegex(ValueError, 'exclude private packaging identity'):
                build.validate_build_mounts({'toolchains': [{'path': str(root), 'target': '/toolchain/jdk'}]}, inputs, vendor, credential)
            config = {'image': 'sha256:' + '1' * 64, 'apk_download_credentials': {'path': str(credential), 'sha256': build.digest(credential)}}
            command = build.container_command(config, [(vendor, '/trusted')], ['/trusted/test.py'])
            self.assertFalse(any(str(credential) in arg or 'fixture' in arg for arg in command))

    def test_download_credential_and_signer_copies_are_rejected_as_source_fixtures(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            key = root / 'key';key.write_bytes(b'fixture-signing-key')
            credential = root / 'download.json';credential.write_bytes(b'fixture-download-credential')
            fixture = root / 'unrelated-name'
            for private in (key, credential):
                fixture.write_bytes(private.read_bytes())
                with self.assertRaisesRegex(ValueError, 'never enter test fixtures'):
                    build.validate_fixture_identity(fixture, key, credential)
            fixture.write_bytes(b'ordinary-source-fixture')
            build.validate_fixture_identity(fixture, key, credential)

    def test_packaged_download_authorization_must_match_private_input(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory);credential = root / 'download.json';apk = root / 'client.apk'
            credential.write_text(json.dumps({'username': 'user', 'password': 'fixture-download-password'}))
            expected = b'username=user\npassword=fixture-download-password\n'
            def serializer(value):
                self.assertEqual({'username': 'user', 'password': 'fixture-download-password'}, value)
                return expected
            for content in (None, b'wrong-fixture', expected):
                with zipfile.ZipFile(apk, 'w') as packaged:
                    if content is not None:packaged.writestr('assets/privateworld/apk-download.properties', content)
                if content == expected:
                    build.verify_download_credential_payload(apk, credential, serializer)
                else:
                    with self.assertRaisesRegex(ValueError, 'authorization payload'):
                        build.verify_download_credential_payload(apk, credential, serializer)


if __name__ == '__main__':
    unittest.main()

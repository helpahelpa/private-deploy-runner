"""Security regression tests for the private client build boundary."""
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import zipfile

SCRIPT = Path(__file__).resolve().parents[1] / 'scripts/build_client.py'
sys.path.insert(0, str(SCRIPT.parent))
spec = importlib.util.spec_from_file_location('private_build_client', SCRIPT)
build = importlib.util.module_from_spec(spec)
spec.loader.exec_module(build)


class ClientBoundaryTests(unittest.TestCase):

    def test_broad_qa_identity_covers_source_fixtures_harness_config_and_all_mounted_toolchain_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory);vendor = root / 'vendor';vendor.mkdir();harness = vendor / 'regression.py';harness.write_text('reviewed')
            tools = root / 'tools';tools.mkdir();runtime = tools / 'unlisted-runtime.dll';runtime.write_bytes(b'runtime1')
            fixture = root / 'fixture';fixture.write_bytes(b'fixture1')
            config = {'image': 'sha256:' + '1' * 64, 'toolchains': [{'path': str(tools), 'target': '/toolchain/jdk'}]}
            source = {'launch-build/test_fixture.py': 'a', 'server/shared.py': 'b', 'README.md': 'c',
                      'server/test_feature.py': 'd', 'deploy/cloudflare/relay.py': 'e', 'future.config': 'f'}
            def identity(**overrides):
                values = dict(tree=source, fixtures={'fixture': 'fixture1'}, inputs={'fixture': fixture}, vendor=vendor,
                              config=config, compiled={'dex': 'one'})
                values.update(overrides)
                return build.qa_identity(**values)
            before = identity()
            for name in source:
                changed = dict(source);changed[name] = 'changed'
                if name in ('README.md', 'server/test_feature.py', 'deploy/cloudflare/relay.py'):
                    self.assertEqual(identity(tree=changed), before)
                else:self.assertNotEqual(identity(tree=changed), before)
            self.assertNotEqual(identity(tree=dict(source, **{'unknown/new.file': 'new'})), before)
            removed = dict(source);del removed['server/test_feature.py']
            self.assertNotEqual(identity(tree=removed), before)
            self.assertNotEqual(identity(fixtures={'fixture': 'changed'}), before)
            self.assertNotEqual(identity(compiled={'dex': 'changed'}), before)
            changed = dict(config, image='sha256:' + '2' * 64);self.assertNotEqual(identity(config=changed), before)
            harness.write_text('updated harness');self.assertNotEqual(identity(), before);harness.write_text('reviewed')
            runtime.write_bytes(b'runtime2');self.assertNotEqual(identity(), before);runtime.write_bytes(b'runtime1')
            fixture.write_bytes(b'fixture2');self.assertNotEqual(identity(), before)

    def test_qa_harness_change_does_not_change_material_native_apk_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory);vendor = root / 'vendor';vendor.mkdir();harness = vendor / 'regression.py';harness.write_text('qa1')
            tool = root / 'compiler';tool.write_bytes(b'compiler')
            names = ('android', 'csc', 'dotnet', 'java', 'javac', 'r8')
            config = {'image': 'sha256:' + '1' * 64, 'compile': {name: '/toolchain/' + name for name in names}}
            args = ({'Bridge.java': 'production'}, {'base': tool}, vendor, {name: tool for name in names}, config)
            before = build.apk_fingerprint(*args)
            harness.write_text('qa2')
            self.assertEqual(build.apk_fingerprint(*args), before)

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
            (repo / 'empty.bin').write_bytes(b'')
            (repo / 'binary.bin').write_bytes(b'\x00\n\xff\n')
            (repo / 'duplicate.bin').write_bytes(b'\x00\n\xff\n')
            (repo / 'docs').mkdir();(repo / 'docs/only.md').write_text('excluded documentation')
            (repo / 'deploy/cloudflare').mkdir(parents=True)
            (repo / 'deploy/cloudflare/only.py').write_text('raise RuntimeError("must stay hidden")')
            commit = self.commit(repo)
            (repo / 'source.java').write_text('dirty')
            snapshot = root / 'snapshot'
            snapshot.mkdir()
            pins = build.snapshot(repo, commit, snapshot)
            self.assertEqual((snapshot / 'source.java').read_text(), 'original')
            self.assertEqual((snapshot / 'empty.bin').read_bytes(),b'')
            self.assertEqual((snapshot / 'binary.bin').read_bytes(),b'\x00\n\xff\n')
            self.assertEqual((snapshot / 'duplicate.bin').read_bytes(),b'\x00\n\xff\n')
            self.assertIn('Build.csproj', pins)
            self.assertEqual(pins['source.java'], build.digest(snapshot / 'source.java'))
            qa_snapshot=root/'qa-snapshot'
            build.snapshot(repo,commit,qa_snapshot,qa=True)
            self.assertEqual(b'\x00\n\xff\n',(qa_snapshot/'binary.bin').read_bytes())
            self.assertFalse((qa_snapshot/'docs').exists())
            self.assertFalse((qa_snapshot/'deploy').exists())

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

    def test_packaging_source_change_invalidates_the_material_apk_identity(self):
        """Release 98 reused the cached APK after a packaging change; it must not."""
        digest = {name: 'digest-' + name for name in build.PACKAGING_FILES}
        self.assertEqual(len(build.PACKAGING_FILES), len(build.packaging_sources(digest)))
        with self.assertRaisesRegex(ValueError, 'packaging source is missing'):
            build.packaging_sources({'Bridge.java': 'x'})
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); vendor = root / 'vendor'; vendor.mkdir()
            tool = root / 'compiler'; tool.write_bytes(b'compiler')
            names = ('android', 'csc', 'dotnet', 'java', 'javac', 'r8')
            config = {'image': 'sha256:' + '1' * 64, 'compile': {name: '/toolchain/' + name for name in names}}
            inputs, tools = {'base': tool}, {name: tool for name in names}
            material = dict({'Bridge.java': 'production'}, **build.packaging_sources(digest))
            before = build.apk_fingerprint(material, inputs, vendor, tools, config)
            changed = dict(material, **{'source/launch-build/multiplayer_manifest.py': 'different'})
            self.assertNotEqual(build.apk_fingerprint(changed, inputs, vendor, tools, config), before)
            self.assertEqual(build.apk_fingerprint(material, inputs, vendor, tools, config), before)

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

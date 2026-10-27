"""Signed-native-content reuse, version consumption, provenance and public contract."""
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import build_client
import native_apk

A, B = 'a' * 40, 'b' * 40


class NativeApkTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.apk = self.root / 'signed.apk'
        self.apk.write_bytes(b'fixture-signed-APK-immutable-bytes')
        self.store = native_apk.Store(self.root / 'cache', minimum_version=68)
        self.manifest = {'package': 'example.privateworld', 'apk_version_code': 68,
            'apk_version_name': '4.2.0.68', 'signing_certificate_sha256': 'f' * 64}
        self.report = dict(self.manifest, apk_sha256=native_apk.digest(self.apk))
        self.key = '1' * 64

    def publish(self):
        return self.store.publish(self.key, A, self.apk, self.manifest, self.report)

    def test_reused_signed_bytes_keep_android_version_and_original_source_provenance(self):
        with self.store.locked():
            self.assertEqual(self.store.reserve(21), 68)
            original = self.publish()
        # A subsequent server/docs/assets release references the same native
        # input key, without reserving or fabricating a new signed version.
        with self.store.locked():
            reused = self.store.lookup(self.key)
        self.assertEqual(reused['path'].read_bytes(), self.apk.read_bytes())
        self.assertEqual(reused['metadata'], original['metadata'])
        self.assertEqual(reused['source_commit'], A)
        self.assertNotEqual(reused['source_commit'], B)
        self.assertEqual(json.loads((self.store.root / 'version.json').read_text()), {'last': 68})
        with self.assertRaises(ValueError):
            self.publish()

    def test_failed_signing_reservation_is_not_recycled_after_restart(self):
        with self.store.locked():
            self.assertEqual(self.store.reserve(21), 68)
        restarted = native_apk.Store(self.store.root, minimum_version=1)
        with restarted.locked():
            self.assertEqual(restarted.reserve(21), 69)
            self.assertEqual(restarted.reserve(100), 101)
        self.assertIsNone(restarted.lookup(self.key))

    def test_cache_rejects_tampered_bytes_metadata_symlinks_and_invalid_keys(self):
        entry = self.publish()
        entry['path'].write_bytes(b'tampered')
        with self.assertRaises(ValueError):
            self.store.lookup(self.key)
        entry['path'].write_bytes(self.apk.read_bytes())
        receipt = entry['path'].with_name('receipt.json')
        value = json.loads(receipt.read_text())
        value['metadata']['version_code'] += 1
        receipt.write_text(json.dumps(value))
        with self.assertRaises(ValueError):
            self.store.lookup(self.key)
        for key in ('../private', 'A' * 64, True, None):
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.store.lookup(key)
        alias = self.root / 'alias'
        alias.symlink_to(self.store.root, target_is_directory=True)
        with self.assertRaises(ValueError):
            native_apk.Store(alias)

    def test_public_update_contract_contains_only_actual_artifact_identity(self):
        value = native_apk.update_metadata(self.manifest, self.apk)
        self.assertEqual(value, {'schema': 1, 'package': 'example.privateworld', 'version_code': 68,
            'version_name': '4.2.0.68', 'sha256': native_apk.digest(self.apk),
            'size': self.apk.stat().st_size, 'url': '/client.apk', 'signing_cert_sha256': 'f' * 64})
        self.assertEqual(set(value), {'schema', 'package', 'version_code', 'version_name',
                                     'sha256', 'size', 'url', 'signing_cert_sha256'})
        for field, bad in (('version_code', True), ('version_code', 0), ('version_code', 1 << 31),
                           ('package', '../private'), ('sha256', 'x' * 64), ('size', 0),
                           ('size', 256 * 1024 * 1024 + 1), ('url', 'https://other.example/client.apk')):
            with self.subTest(field=field, bad=bad), self.assertRaises(ValueError):
                native_apk.validate_metadata(dict(value, **{field: bad}))

    def test_exhausted_or_malformed_native_counter_fails_closed(self):
        path = self.store.root / 'version.json'
        for last in (True, -1, 2147483647):
            path.write_text(json.dumps({'last': last}))
            with self.subTest(last=last), self.assertRaises(ValueError):
                self.store.reserve(21)


class MaterialInputTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.vendor = self.root / 'trusted'
        self.vendor.mkdir()
        for name in ('launch-build/manifest.py', 'launch-build/packager.py', 'server/signer.py',
                     'compile.py', 'csc.py', 'test.py', 'README.md'):
            path = self.vendor / name
            path.parent.mkdir(exist_ok=True)
            path.write_text(name)
        self.inputs = {}
        for name in ('base_apk', 'client_source', 'template', 'helper', 'ca', 'key', 'cert', 'System.dll'):
            self.inputs[name] = self.root / name
            self.inputs[name].write_text(name)
        self.tools = {name: self.root / ('tool-' + name) for name in ('java', 'csc', 'pwsh')}
        for name, path in self.tools.items():
            path.write_text(name)
        self.config = {'image': 'sha256:' + '1' * 64, 'connection': {'game': 'https://play.example/game'},
            'compile': {'java': '/tools/java', 'csc': '/tools/compiler', 'minimum_client_tests': 257,
                        'required_test_ids': ['existing.test'], 'test_runtime': 'net9.0', 'pwsh': '/tools/pwsh'}}
        self.tree = {'launch-build/multiplayer-client/PrivateActivity.java': 'a' * 64,
            'launch-build/multiplayer-client/Bridge.java': 'b' * 64,
            'launch-build/coop-client/Runtime.cs': 'c' * 64,
            'server/world.py': 'd' * 64, 'README.md': 'e' * 64,
            'launch-build/multiplayer-client/WireTest.java': 'f' * 64}

    def key(self):
        return build_client.apk_fingerprint(build_client.production_sources(self.tree),
            self.inputs, self.vendor, self.tools, self.config)

    def test_docs_server_qa_and_increment_release_changes_keep_material_key(self):
        original = self.key()
        self.tree['server/world.py'] = '1' * 64
        self.tree['README.md'] = '2' * 64
        self.tree['launch-build/multiplayer-client/WireTest.java'] = '3' * 64
        self.config.update({'version': '4.2.0.999', 'test_commands': [['new-tests']], 'test_timeout': 20})
        self.config['compile']['minimum_client_tests'] = 300
        self.config['compile']['required_test_ids'] = ['new.test']
        (self.vendor / 'test.py').write_text('new QA driver')
        (self.vendor / 'README.md').write_text('new operator documentation')
        self.tools['pwsh'].write_text('new test-only PowerShell')
        self.assertEqual(self.key(), original)

    def test_each_material_java_managed_manifest_trust_endpoint_signer_change_invalidates(self):
        for source in ('launch-build/multiplayer-client/Bridge.java', 'launch-build/coop-client/Runtime.cs'):
            original = self.key()
            previous = self.tree[source]
            self.tree[source] = '9' * 64
            self.assertNotEqual(self.key(), original, source)
            self.tree[source] = previous
        for path in [*self.inputs.values(), self.vendor / 'launch-build/manifest.py',
                     self.vendor / 'compile.py', self.vendor / 'server/signer.py', *[self.tools[n] for n in ('java', 'csc')]]:
            original, previous = self.key(), path.read_bytes()
            path.write_bytes(previous + b'changed')
            self.assertNotEqual(self.key(), original, path.name)
            path.write_bytes(previous)
        original = self.key()
        self.config['connection']['game'] = 'https://next.example/game'
        self.assertNotEqual(self.key(), original)
        self.config['connection']['game'] = 'https://play.example/game'
        self.config['compile']['csc'] = '/tools/next-compiler'
        self.assertNotEqual(self.key(), original)

    def test_download_credential_rotation_rebuilds_but_relocation_keeps_material_key(self):
        absent = self.key()
        credential = self.root / 'download.json'
        credential.write_text(json.dumps({'username': 'user', 'password': 'fixture-download-password'}))
        credential.chmod(0o600)
        self.config['apk_download_credentials'] = {'path': str(credential), 'sha256': build_client.digest(credential)}
        first = self.key()
        self.assertNotEqual(absent, first)
        relocated = self.root / 'relocated.json'
        relocated.write_bytes(credential.read_bytes());relocated.chmod(0o600)
        self.config['apk_download_credentials']['path'] = str(relocated)
        self.assertEqual(first, self.key())
        relocated.write_text(json.dumps({'username': 'user', 'password': 'rotated-fixture-download-password'}))
        self.config['apk_download_credentials']['sha256'] = build_client.digest(relocated)
        self.assertNotEqual(first, self.key())


if __name__ == '__main__':
    unittest.main()

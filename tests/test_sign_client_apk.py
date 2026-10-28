"""Host signing boundary: an unsigned sandbox APK may only be signed after checks."""
import struct
import unittest
import zipfile
from pathlib import Path
import tempfile

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
import datetime

import sign_client_apk as signer


def _pool(values):
    data, offsets = bytearray(), []
    for value in values:
        offsets.append(len(data))
        encoded = value.encode('utf-16-le')
        data += struct.pack('<H', len(encoded) // 2) + encoded + b'\0\0'
    start = 28 + 4 * len(values)
    data += b'\0' * (-(start + len(data)) % 4)
    return (struct.pack('<HHI5I', 1, 28, start + len(data), len(values), 0, 0, start, 0)
            + struct.pack('<' + 'I' * len(offsets), *offsets) + data)


def _element(values, name, attributes, end=False, index=0):
    value_index = values.index(name)
    if end:
        return struct.pack('<HHIIIII', 0x103, 16, 24, 0, 0xffffffff, 0xffffffff, value_index)
    encoded = b''.join(
        struct.pack('<IIIHBBI', 0xffffffff, values.index(key), raw, 8, 0, kind, data)
        for key, kind, raw, data in attributes)
    header = struct.pack('<HHIIIIIHHHHHH', 0x102, 16, 36 + len(encoded), 0, 0xffffffff,
                         0xffffffff, value_index, 20, 20, len(attributes), 0, 0, 0)
    return header + encoded


def axml(package='com.fl.mhsy.privateworld', version_code=75, version_name='4.2.0.75',
         min_sdk=24, target_sdk=24):
    """Minimal binary XML carrying the fields the signer validates."""
    names = ['manifest', 'uses-sdk', 'package', 'versionCode', 'versionName',
             'minSdkVersion', 'targetSdkVersion']
    strings = [package, version_name]
    values = names + strings
    anyvalue = values.index(package), values.index(version_name)
    body = (_element(values, 'manifest', [('package', 3, anyvalue[0], anyvalue[0]),
                                          ('versionCode', 0x10, 0xffffffff, version_code),
                                          ('versionName', 3, anyvalue[1], anyvalue[1])])
            + _element(values, 'uses-sdk', [('minSdkVersion', 0x10, 0xffffffff, min_sdk),
                                            ('targetSdkVersion', 0x10, 0xffffffff, target_sdk)])
            + _element(values, 'uses-sdk', [], end=True)
            + _element(values, 'manifest', [], end=True))
    content = _pool(values) + body
    return struct.pack('<HHI', 3, 8, 8 + len(content)) + content


def identity():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'fixture')])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=30)).sign(key, hashes.SHA256()))
    return key, cert


def minimal_dex(class_name='Lprivateworld/PrivateActivity;'):
    """Just enough of a DEX for the class-boundary check."""
    raw = bytearray(200)
    raw[:8] = b'dex\n035\0'
    struct.pack_into('<I', raw, 56, 1)      # string_ids_size
    struct.pack_into('<I', raw, 60, 112)    # string_ids_off
    struct.pack_into('<I', raw, 64, 1)      # type_ids_size
    struct.pack_into('<I', raw, 68, 116)    # type_ids_off
    struct.pack_into('<I', raw, 96, 1)
    struct.pack_into('<I', raw, 100, 120)
    struct.pack_into('<I', raw, 112, 152)
    struct.pack_into('<I', raw, 116, 0)
    struct.pack_into('<I', raw, 120, 0)
    encoded = class_name.encode()
    raw[152:152 + len(encoded) + 2] = bytes([len(encoded)]) + encoded + b'\0'
    return bytes(raw)


EXPECTED = {'package': 'com.fl.mhsy.privateworld', 'version_code': 75, 'version_name': '4.2.0.75'}


class SigningBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.root = Path(self.directory.name)
        self.addCleanup(self.directory.cleanup)
        self.key, self.cert = identity()
        self.key_path = self.root / 'key.pem'
        self.key_path.write_bytes(self.key.private_bytes(serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        self.cert_path = self.root / 'cert.pem'
        self.cert_path.write_bytes(self.cert.public_bytes(serialization.Encoding.PEM))

    def apk(self, name='client.unsigned.apk', manifest=None, entries=None):
        path = self.root / name
        with zipfile.ZipFile(path, 'w') as build:
            build.writestr('AndroidManifest.xml', manifest or axml())
            build.writestr('classes.dex', b'dex\n035\0fixture-original')
            build.writestr('assets/privateworld.properties', b'host=localhost\n')
            for entry, data in (entries or {}).items():
                build.writestr(entry, data)
        return path

    def sign(self, apk, output='client.apk', expected=None):
        return signer.sign(apk, self.root / output, self.key_path, self.cert_path, expected or EXPECTED)

    def test_valid_apk_is_signed_verified_and_reported(self):
        evidence = self.sign(self.apk())
        self.assertEqual(24, evidence['facts']['targetSdkVersion'])
        self.assertEqual(3, evidence['signed_entries'])
        self.assertEqual(evidence['sha256'], signer.sha((self.root / 'client.apk').read_bytes()))
        with zipfile.ZipFile(self.root / 'client.apk') as packed:
            self.assertEqual({'META-INF/MANIFEST.MF', 'META-INF/CERT.SF', 'META-INF/CERT.RSA'},
                             {name for name in packed.namelist() if name.startswith('META-INF/')})

    def test_signature_is_deterministic_for_identical_payload(self):
        first = self.sign(self.apk(), 'first.apk')
        second = self.sign(self.apk('copy.unsigned.apk'), 'second.apk')
        self.assertEqual(first['sha256'], second['sha256'])

    def test_install_floor_and_jit_ceiling_are_enforced(self):
        for target, label in ((22, 'below the Android 16 floor'), (29, 'above the Mono JIT ceiling')):
            with self.subTest(target=target):
                with self.assertRaisesRegex(ValueError, 'target SDK'):
                    self.sign(self.apk(manifest=axml(target_sdk=target)))
                (self.root / 'client.apk').unlink(missing_ok=True)

    def test_package_version_and_minimum_sdk_must_match_the_release(self):
        with self.assertRaisesRegex(ValueError, 'package differs'):
            self.sign(self.apk(manifest=axml(package='com.fl.mhsy.other')))
        with self.assertRaisesRegex(ValueError, 'versionCode differs'):
            self.sign(self.apk(manifest=axml(version_code=76)), 'v.apk')
        with self.assertRaisesRegex(ValueError, 'versionName differs'):
            self.sign(self.apk(manifest=axml(version_name='4.2.0.76')), 'n.apk')
        with self.assertRaisesRegex(ValueError, 'minimum SDK'):
            self.sign(self.apk(manifest=axml(min_sdk=9)), 'm.apk')

    def test_signed_input_entries_and_missing_payload_are_refused(self):
        with self.assertRaisesRegex(ValueError, 'META-INF'):
            self.sign(self.apk(entries={'META-INF/CERT.SF': b'stale'}))
        path = self.root / 'incomplete.apk'
        with zipfile.ZipFile(path, 'w') as build:
            build.writestr('AndroidManifest.xml', axml())
        with self.assertRaisesRegex(ValueError, 'missing required entries'):
            self.sign(path, 'i.apk')

    def test_tampered_apk_fails_verification_after_signing(self):
        self.sign(self.apk())
        signed = self.root / 'client.apk'
        with zipfile.ZipFile(signed) as packed:
            entries = {name: packed.read(name) for name in packed.namelist()}
        entries['assets/privateworld.properties'] = b'host=attacker\n'
        with zipfile.ZipFile(signed, 'w') as build:
            for name, data in entries.items():
                build.writestr(name, data)
        with self.assertRaisesRegex(ValueError, 'digest mismatch'):
            signer.verify_signed(signed, self.cert)

    def test_download_authorization_must_match_the_pinned_input(self):
        credential = self.root / 'download.json'
        credential.write_text('{"username": "user", "password": "fixture secret"}')
        expected = dict(EXPECTED, download_credential=credential)
        with self.assertRaisesRegex(ValueError, 'authorization payload mismatch'):
            self.sign(self.apk(), expected=expected)
        wanted = signer.credential_payload({'username': 'user', 'password': 'fixture secret'})
        self.sign(self.apk('cred.apk', entries={'assets/privateworld/apk-download.properties': wanted}),
                  'cred.apk.signed', expected)
        self.assertTrue((self.root / 'cred.apk.signed').is_file())

    def test_supplementary_dex_must_stay_inside_the_bridge_boundary(self):
        self.sign(self.apk('good.apk', entries={'classes2.dex': minimal_dex()}), 'good.signed.apk')
        for payload, message in ((b'not a dex', 'not a dex'),
                                 (minimal_dex('Lcom/example/Payload;'), 'non-bridge class')):
            with self.subTest(message=message):
                with self.assertRaisesRegex(ValueError, message):
                    self.sign(self.apk('bad.apk', entries={'classes2.dex': payload}), 'bad.signed.apk')


if __name__ == '__main__':
    unittest.main()

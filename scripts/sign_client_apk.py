#!/usr/bin/env python3
"""Sign an assembled, unsigned client APK on the trusted host.

The packaging code and the APK payload come from an isolated container that
never sees a signing identity. This module is the only place the private key is
read: it re-validates the payload's invariants, signs with the v1 (PKCS#7)
scheme, and then verifies the result from the written bytes before reporting.
"""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import struct
import sys
import zipfile

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

MANIFEST = 'AndroidManifest.xml'
MIN_SDK_FLOOR = 24
TARGET_SDK_MIN = 24
TARGET_SDK_MAX = 28
REQUIRED_ENTRIES = ('classes.dex', 'assets/privateworld.properties')
OID_SIGNED_DATA = '1.2.840.113549.1.7.2'
OID_DATA = '1.2.840.113549.1.7.1'
OID_SHA256 = '2.16.840.1.101.3.4.2.1'
OID_RSA = '1.2.840.113549.1.1.1'
OID_ATTR_CONTENT_TYPE = '1.2.840.113549.1.9.3'
OID_ATTR_MESSAGE_DIGEST = '1.2.840.113549.1.9.4'
DIGEST_ATTR = 'SHA-256-Digest'


def sha(data):
    return hashlib.sha256(data).hexdigest()


# ----------------------------------------------------------------- binary XML
def _u32(data, offset):
    return struct.unpack_from('<I', data, offset)[0]


def _axml_chunks(raw):
    if raw[:4] != b'\x03\0\x08\0' or _u32(raw, 4) != len(raw):
        raise ValueError('Expected complete Android binary XML')
    pos, result = 8, []
    while pos < len(raw):
        kind, header, size = struct.unpack_from('<HHI', raw, pos)
        if size < header or pos + size > len(raw):
            raise ValueError('Invalid binary XML chunk')
        result.append((kind, raw[pos:pos + size]))
        pos += size
    return result


def _axml_strings(chunk):
    if struct.unpack_from('<HH', chunk) != (1, 28):
        raise ValueError('Unsupported binary XML string pool')
    count, styles, flags, start, style_start = struct.unpack_from('<5I', chunk, 8)
    if styles or style_start:
        raise ValueError('Styled manifest strings are unsupported')
    utf8, result = bool(flags & 0x100), []
    for index in range(count):
        position = start + _u32(chunk, 28 + index * 4)
        if utf8:
            size = chunk[position]
            position += 2 if size & 0x80 else 1
            size = chunk[position]
            position += 1
            if size & 0x80:
                size = ((size & 0x7f) << 8) | chunk[position]
                position += 1
            result.append(chunk[position:position + size].decode('utf-8'))
        else:
            size = struct.unpack_from('<H', chunk, position)[0]
            position += 2
            result.append(chunk[position:position + size * 2].decode('utf-16-le'))
    return result


def apk_manifest_facts(raw):
    """Read the signing-relevant manifest fields from a packaged APK."""
    chunks = _axml_chunks(raw)
    pools = [chunk for kind, chunk in chunks if kind == 1]
    if len(pools) != 1:
        raise ValueError('Expected one manifest string pool')
    values = _axml_strings(pools[0])
    facts = {}
    for kind, chunk in chunks:
        if kind != 0x102:
            continue
        name = values[_u32(chunk, 20)]
        if name not in ('manifest', 'uses-sdk'):
            continue
        start, width, count = struct.unpack_from('<HHH', chunk, 24)
        if width != 20:
            raise ValueError('Unexpected manifest attribute width')
        for index in range(count):
            at = 16 + start + index * 20
            key = values[_u32(chunk, at + 4)]
            if name == 'manifest' and key in ('package', 'versionCode', 'versionName'):
                facts[key] = values[_u32(chunk, at + 16)] if chunk[at + 15] == 3 else _u32(chunk, at + 16)
            if name == 'uses-sdk' and key in ('minSdkVersion', 'targetSdkVersion'):
                facts[key] = _u32(chunk, at + 16)
    required = {'package', 'versionCode', 'versionName', 'minSdkVersion', 'targetSdkVersion'}
    if set(facts) != required:
        raise ValueError('Incomplete manifest version information')
    return facts


# ------------------------------------------------------------------- DER/PKCS7
def _der_len(size):
    if size < 0x80:
        return bytes([size])
    body = size.to_bytes((size.bit_length() + 7) // 8, 'big')
    return bytes([0x80 | len(body)]) + body


def tlv(tag, value):
    return bytes([tag]) + _der_len(len(value)) + value


def der_oid(dotted):
    parts = [int(x) for x in dotted.split('.')]
    out = bytes([40 * parts[0] + parts[1]])
    for part in parts[2:]:
        chunks = [part & 0x7F]
        part >>= 7
        while part:
            chunks.append((part & 0x7F) | 0x80)
            part >>= 7
        out += bytes(reversed(chunks))
    return out


def der_int(number):
    body = number.to_bytes(max(1, (number.bit_length() + 8) // 8), 'big')
    return tlv(0x02, body)


def algorithm(dotted):
    return tlv(0x30, tlv(0x06, der_oid(dotted)) + tlv(0x05, b''))


def attribute(dotted, values):
    return tlv(0x30, tlv(0x06, der_oid(dotted)) + tlv(0x31, b''.join(values)))


def _read_tlv(data, position):
    if position >= len(data):
        raise ValueError('Truncated DER element')
    tag = data[position]
    length = data[position + 1]
    header = 2
    if length & 0x80:
        width = length & 0x7f
        if not 1 <= width <= 4 or position + 2 + width > len(data):
            raise ValueError('Invalid DER length')
        length = int.from_bytes(data[position + 2:position + 2 + width], 'big')
        header = 2 + width
    body = position + header
    if body + length > len(data):
        raise ValueError('Truncated DER element')
    return tag, position, body, body + length


def _children(data, position, end):
    result = []
    while position < end:
        tag, start, body, stop = _read_tlv(data, position)
        result.append((tag, start, body, stop))
        position = stop
    return result


def build_rsa(sf, key, cert):
    digest = hashlib.sha256(sf).digest()
    attrs = b''.join((attribute(OID_ATTR_CONTENT_TYPE, [tlv(0x06, der_oid(OID_DATA))]),
                      attribute(OID_ATTR_MESSAGE_DIGEST, [tlv(0x04, digest)])))
    signed_attrs = tlv(0x31, attrs)
    signature = key.sign(signed_attrs, padding.PKCS1v15(), hashes.SHA256())
    signer_info = tlv(0x30, der_int(1)
                      + tlv(0x30, cert.issuer.public_bytes() + der_int(cert.serial_number))
                      + algorithm(OID_SHA256) + tlv(0xA0, attrs) + algorithm(OID_RSA)
                      + tlv(0x04, signature))
    signed_data = tlv(0x30, der_int(1) + tlv(0x31, algorithm(OID_SHA256))
                      + tlv(0x30, tlv(0x06, der_oid(OID_DATA)))
                      + tlv(0xA0, cert.public_bytes(serialization.Encoding.DER))
                      + tlv(0x31, signer_info))
    return tlv(0x30, tlv(0x06, der_oid(OID_SIGNED_DATA)) + tlv(0xA0, signed_data))


def verify_rsa(rsa_der, sf, certificate):
    """Verify the detached PKCS#7 signature over the signature file."""
    outer = _children(rsa_der, 0, len(rsa_der))
    if len(outer) != 1 or outer[0][0] != 0x30:
        raise ValueError('Unsupported APK signature container')
    content_info = _children(rsa_der, outer[0][2], outer[0][3])
    if len(content_info) != 2 or content_info[0][0] != 0x06 or content_info[1][0] != 0xA0:
        raise ValueError('Unsupported APK signature container')
    wrapped = _children(rsa_der, content_info[1][2], content_info[1][3])
    if len(wrapped) != 1 or wrapped[0][0] != 0x30:
        raise ValueError('Unsupported APK signature container')
    signed_data = _children(rsa_der, wrapped[0][2], wrapped[0][3])
    if len(signed_data) < 4 or signed_data[-1][0] != 0x31:
        raise ValueError('Unsupported APK signature container')
    signers = _children(rsa_der, signed_data[-1][2], signed_data[-1][3])
    if len(signers) != 1 or signers[0][0] != 0x30:
        raise ValueError('Unsupported APK signature container')
    fields = _children(rsa_der, signers[0][2], signers[0][3])
    attrs = [item for item in fields if item[0] == 0xA0]
    signature = [item for item in fields if item[0] == 0x04]
    if len(attrs) != 1 or len(signature) != 1:
        raise ValueError('Unsupported APK signature container')
    signed_attrs = bytes([0x31]) + rsa_der[attrs[0][1] + 1:attrs[0][3]]
    certificate.public_key().verify(rsa_der[signature[0][2]:signature[0][3]], signed_attrs,
                                    padding.PKCS1v15(), hashes.SHA256())
    digest = hashlib.sha256(sf).digest()
    found = False
    for tag, start, body, stop in _children(rsa_der, attrs[0][2], attrs[0][3]):
        values = _children(rsa_der, body, stop)
        if len(values) == 2 and values[0][0] == 0x06 and values[1][0] == 0x31:
            oid = _decode_oid(rsa_der[values[0][2]:values[0][3]])
            if oid == OID_ATTR_MESSAGE_DIGEST:
                inner = _children(rsa_der, values[1][2], values[1][3])
                if len(inner) != 1 or rsa_der[inner[0][2]:inner[0][3]] != digest:
                    raise ValueError('Signed message digest does not match the signature file')
                found = True
    if not found:
        raise ValueError('Signature is missing its message digest')


def _decode_oid(data):
    if not data:
        raise ValueError('Invalid OID')
    parts = [data[0] // 40, data[0] % 40]
    value = 0
    for byte in data[1:]:
        value = (value << 7) | (byte & 0x7f)
        if not byte & 0x80:
            parts.append(value)
            value = 0
    return '.'.join(str(part) for part in parts)


# ---------------------------------------------------------------------- v1 JAR
def _fold(value):
    raw = value.encode('utf-8')
    chunks, first, index = [], True, 0
    while index < len(raw):
        limit = 72 if first else 71
        chunk = raw[index:index + limit]
        chunks.append(chunk if first else b' ' + chunk)
        index += limit
        first = False
    return b'\r\n'.join(chunks) + b'\r\n'


def build_manifest(entries):
    out = b'Manifest-Version: 1.0\r\nCreated-By: MHLocalSigner\r\n\r\n'
    blocks = {}
    for name, digest_hex in entries:
        text = base64.b64encode(bytes.fromhex(digest_hex)).decode()
        block = _fold('Name: %s' % name) + _fold('%s: %s' % (DIGEST_ATTR, text)) + b'\r\n'
        blocks[name] = block
        out += block
    return out, blocks


def build_sf(manifest_bytes, blocks):
    digest = base64.b64encode(hashlib.sha256(manifest_bytes).digest()).decode()
    out = (b'Signature-Version: 1.0\r\nCreated-By: MHLocalSigner\r\n'
           + _fold('%s-Manifest: %s' % (DIGEST_ATTR, digest)) + b'\r\n')
    for name, block in blocks.items():
        text = base64.b64encode(hashlib.sha256(block).digest()).decode()
        out += _fold('Name: %s' % name) + _fold('%s: %s' % (DIGEST_ATTR, text)) + b'\r\n'
    return out


def dex_classes(raw):
    """Read class definitions, not referenced names, from the supplementary DEX."""
    if not raw.startswith(b'dex\n'):
        raise ValueError('Supplementary payload is not a dex file')
    strings, types = struct.unpack_from('<I', raw, 60)[0], struct.unpack_from('<I', raw, 68)[0]
    count, definitions = struct.unpack_from('<II', raw, 96)
    result = []
    for index in range(count):
        cls = struct.unpack_from('<I', raw, definitions + index * 32)[0]
        string = struct.unpack_from('<I', raw, types + cls * 4)[0]
        offset = struct.unpack_from('<I', raw, strings + string * 4)[0]
        while raw[offset] & 128:
            offset += 1
        offset += 1
        result.append(raw[offset:raw.index(b'\0', offset)].decode('utf-8'))
    return result


def credential_payload(config):
    """The embedded APK-download authorization, reproduced from the pinned input."""
    if not isinstance(config, dict) or set(config) != {'username', 'password'} or config['username'] != 'user':
        raise ValueError('Invalid APK download authorization input')
    password = config['password']
    if not isinstance(password, str) or not 1 <= len(password) <= 512 or any(
            ord(c) < 32 or ord(c) > 126 for c in password):
        raise ValueError('Invalid APK download authorization input')
    password = password.replace('\\', '\\\\')
    for char in ' =:#!':
        password = password.replace(char, '\\' + char)
    return ('username=user\npassword=' + password + '\n').encode('ascii')


def validate_payload(path, expected):
    """Refuse to sign anything that does not match the reviewed invariants."""
    with zipfile.ZipFile(path) as apk:
        names = apk.namelist()
        if len(names) != len(set(names)):
            raise ValueError('Duplicate APK entries')
        if any(name.startswith('META-INF/') for name in names):
            raise ValueError('Unsigned APK may not carry META-INF entries')
        bad = apk.testzip()
        if bad is not None:
            raise ValueError('Corrupt APK entry: ' + str(bad))
        missing = [name for name in REQUIRED_ENTRIES if name not in names]
        if missing:
            raise ValueError('APK is missing required entries: ' + ', '.join(missing))
        facts = apk_manifest_facts(apk.read(MANIFEST))
        checks = {'package': expected['package'], 'versionCode': expected['version_code'],
                  'versionName': expected['version_name']}
        for key, value in checks.items():
            if facts[key] != value:
                raise ValueError('APK manifest ' + key + ' differs from the signed release metadata')
        if facts['minSdkVersion'] < MIN_SDK_FLOOR:
            raise ValueError('APK minimum SDK is below the supported floor')
        if not TARGET_SDK_MIN <= facts['targetSdkVersion'] <= TARGET_SDK_MAX:
            raise ValueError('APK target SDK is outside the installable and JIT-safe range')
        credential = expected.get('download_credential')
        if credential is not None:
            wanted = credential_payload(json.loads(Path(credential).read_bytes()))
            entry = 'assets/privateworld/apk-download.properties'
            if entry not in names or apk.read(entry) != wanted:
                raise ValueError('APK download authorization payload mismatch')
        for name in ('assets/privateworld-ca.crt', 'assets/privateworld.properties'):
            if name in names and b'PRIVATE KEY' in apk.read(name):
                raise ValueError('Private material in APK')
        if 'classes2.dex' in names:
            classes = dex_classes(apk.read('classes2.dex'))
            if 'Lprivateworld/PrivateActivity;' not in classes or any(
                    not name.startswith('Lprivateworld/') for name in classes):
                raise ValueError('Supplementary DEX contains a missing activity or non-bridge class/stub')
        facts['entries'] = len(names)
        return facts


def verify_signed(path, certificate):
    """Re-read the written APK and verify every v1 digest and the signature."""
    with zipfile.ZipFile(path) as apk:
        names = apk.namelist()
        if apk.testzip() is not None:
            raise ValueError('Signed APK is corrupt')
        for required in ('META-INF/MANIFEST.MF', 'META-INF/CERT.SF', 'META-INF/CERT.RSA'):
            if required not in names:
                raise ValueError('Signed APK is missing ' + required)
        manifest = apk.read('META-INF/MANIFEST.MF')
        sf = apk.read('META-INF/CERT.SF')
        rsa_der = apk.read('META-INF/CERT.RSA')
        expected = base64.b64encode(hashlib.sha256(manifest).digest()).decode()
        if ('%s-Manifest: %s' % (DIGEST_ATTR, expected)).encode() not in sf:
            raise ValueError('Signature file does not describe this manifest')
        listed = set()
        for block in manifest.split(b'\r\n\r\n'):
            name = None
            for line in block.split(b'\r\n'):
                if line.startswith(b'Name: '):
                    name = line[6:].decode('utf-8')
                elif line.startswith(DIGEST_ATTR.encode() + b': ') and name is not None:
                    want = base64.b64decode(line.split(b': ', 1)[1])
                    if hashlib.sha256(apk.read(name)).digest() != want:
                        raise ValueError('Entry digest mismatch: ' + name)
                    listed.add(name)
        payload = {name for name in names if not name.startswith('META-INF/')}
        if listed != payload:
            raise ValueError('Signed manifest does not cover every APK entry')
        verify_rsa(rsa_der, sf, certificate)
        return {'entries': len(names), 'signed_entries': len(listed)}


def sign(unsigned, output, key_path, cert_path, expected):
    unsigned, output = Path(unsigned), Path(output)
    key = serialization.load_pem_private_key(Path(key_path).read_bytes(), password=None)
    certificate = x509.load_pem_x509_certificate(Path(cert_path).read_bytes())
    if key.public_key().public_numbers() != certificate.public_key().public_numbers():
        raise ValueError('Signing key and certificate do not match')
    facts = validate_payload(unsigned, expected)
    if output.exists():
        raise ValueError('Use a new output filename; signed APKs are immutable')
    with zipfile.ZipFile(unsigned) as source:
        entries = [(info.filename, sha(source.read(info.filename))) for info in source.infolist()]
        manifest, blocks = build_manifest(entries)
        sf = build_sf(manifest, blocks)
        rsa_der = build_rsa(sf, key, certificate)
        output.parent.mkdir(parents=True, exist_ok=True)
        temporary = output.with_name('.pending-' + output.name)
        try:
            with zipfile.ZipFile(temporary, 'w') as target:
                for info in source.infolist():
                    copy = zipfile.ZipInfo(info.filename, date_time=info.date_time)
                    copy.compress_type = info.compress_type
                    copy.external_attr = info.external_attr
                    target.writestr(copy, source.read(info.filename))
                for name, data in (('META-INF/MANIFEST.MF', manifest), ('META-INF/CERT.SF', sf),
                                   ('META-INF/CERT.RSA', rsa_der)):
                    copy = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
                    copy.compress_type = zipfile.ZIP_DEFLATED
                    copy.external_attr = 0o644 << 16
                    target.writestr(copy, data)
            os.replace(temporary, output)
        finally:
            temporary.unlink(missing_ok=True)
    evidence = verify_signed(output, certificate)
    evidence.update({'facts': facts, 'sha256': sha(output.read_bytes()),
                     'signing_certificate_sha256': sha(certificate.public_bytes(serialization.Encoding.DER)),
                     'unsigned_sha256': sha(unsigned.read_bytes()), 'scheme': 'v1-only SHA256withRSA PKCS7'})
    return evidence


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--unsigned', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--key', type=Path, required=True)
    parser.add_argument('--cert', type=Path, required=True)
    parser.add_argument('--package', required=True)
    parser.add_argument('--version-code', type=int, required=True)
    parser.add_argument('--version-name', required=True)
    parser.add_argument('--download-credential', type=Path)
    parser.add_argument('--report', type=Path)
    args = parser.parse_args()
    evidence = sign(args.unsigned, args.output, args.key, args.cert, {
        'package': args.package, 'version_code': args.version_code,
        'version_name': args.version_name, 'download_credential': args.download_credential})
    if args.report:
        args.report.write_text(json.dumps(evidence, indent=2, sort_keys=True) + '\n')
    print(json.dumps({'package': evidence['facts']['package'], 'sha256': evidence['sha256'],
                      'targetSdkVersion': evidence['facts']['targetSdkVersion'],
                      'signed_entries': evidence['signed_entries']}, sort_keys=True))
    return 0


if __name__ == '__main__':
    sys.exit(main())

"""Private content-addressed signed APK store and independent Android version counter."""
from contextlib import contextmanager
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import tempfile

HEX = re.compile(r"[0-9a-f]{64}\Z")
COMMIT = re.compile(r"[0-9a-f]{40}\Z")
PACKAGE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)+\Z")
MAX_APK = 256 * 1024 * 1024


def digest(path):
    value = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            value.update(chunk)
    return value.hexdigest()


def fingerprint(production, inputs, tooling, compilers, compile_config, connection, image):
    """Only material APK inputs, deliberately independent of source/asset releases."""
    data = {'schema': 1, 'production': production, 'inputs': inputs, 'tooling': tooling,
            'compilers': compilers, 'compile': compile_config, 'connection': connection, 'image': image}
    return hashlib.sha256(json.dumps(data, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def atomic_json(path, value):
    descriptor, temporary = tempfile.mkstemp(prefix='.pending-', dir=path.parent)
    try:
        with os.fdopen(descriptor, 'w') as stream:
            json.dump(value, stream, sort_keys=True)
            stream.write('\n')
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        Path(temporary).unlink(missing_ok=True)


def validate_metadata(value):
    if (not isinstance(value, dict) or set(value) != {'schema', 'package', 'version_code', 'version_name', 'sha256', 'size', 'url', 'signing_cert_sha256'}
            or type(value.get('schema')) is not int or value['schema'] != 1
            or not isinstance(value.get('package'), str) or not PACKAGE.fullmatch(value['package'])
            or type(value.get('version_code')) is not int or not 1 <= value['version_code'] <= 2147483647
            or not isinstance(value.get('version_name'), str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._+-]{0,63}', value['version_name'])
            or type(value.get('size')) is not int or not 0 < value['size'] <= MAX_APK
            or not isinstance(value.get('sha256'), str) or not HEX.fullmatch(value['sha256'])
            or not isinstance(value.get('signing_cert_sha256'), str) or not HEX.fullmatch(value['signing_cert_sha256'])
            or value.get('url') != '/client.apk'):
        raise ValueError('Invalid signed APK metadata')
    return value


def update_metadata(manifest, apk):
    """Portable public contract; never includes input paths or private build settings."""
    return validate_metadata({'schema': 1, 'package': manifest['package'],
        'version_code': manifest['apk_version_code'], 'version_name': manifest['apk_version_name'],
        'sha256': digest(apk), 'size': Path(apk).stat().st_size, 'url': '/client.apk',
        'signing_cert_sha256': manifest['signing_certificate_sha256']})


class Store:
    def __init__(self, directory, minimum_version=1):
        candidate = Path(directory).absolute()
        if any(path.is_symlink() for path in (candidate, *candidate.parents)):
            raise ValueError('Invalid signed APK cache')
        self.root = candidate
        if type(minimum_version) is not int or not 1 <= minimum_version <= 2147483647:
            raise ValueError('Invalid minimum Android version')
        self.minimum = minimum_version
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        if self.root.is_symlink():
            raise ValueError('Invalid signed APK cache')

    @contextmanager
    def locked(self):
        descriptor = os.open(self.root / 'lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        with os.fdopen(descriptor, 'r+') as stream:
            fcntl.flock(stream, fcntl.LOCK_EX)
            yield self

    def lookup(self, key):
        if not isinstance(key, str) or not HEX.fullmatch(key):
            raise ValueError('Invalid APK input fingerprint')
        directory = self.root / key
        if not directory.exists() and not directory.is_symlink():
            return None
        if directory.is_symlink() or not directory.is_dir():
            raise ValueError('Invalid signed APK cache')
        receipt, apk = directory / 'receipt.json', directory / 'client.apk'
        if receipt.is_symlink() or apk.is_symlink() or not receipt.is_file() or not apk.is_file():
            raise ValueError('Incomplete signed APK cache')
        value = json.loads(receipt.read_text())
        if not isinstance(value, dict) or type(value.get('schema')) is not int or value['schema'] != 1:
            raise ValueError('Invalid signed APK cache receipt')
        metadata = validate_metadata(value.get('metadata'))
        report = value.get('build_report')
        if (not isinstance(report, dict) or any(report.get(name) != metadata[field] for name, field in
                (('package', 'package'), ('apk_sha256', 'sha256'), ('apk_version_code', 'version_code'),
                 ('apk_version_name', 'version_name'), ('signing_certificate_sha256', 'signing_cert_sha256')))):
            raise ValueError('Signed APK cache metadata mismatch')
        if (value.get('input_sha256') != key or not isinstance(value.get('source_commit'), str)
                or not COMMIT.fullmatch(value['source_commit']) or metadata['size'] != apk.stat().st_size
                or metadata['sha256'] != digest(apk) or not isinstance(value.get('build_report'), dict)):
            raise ValueError('Signed APK cache fingerprint mismatch')
        return dict(value, path=apk)

    def reserve(self, base_version):
        """Persist before signing. Failed builds consume their version permanently."""
        if type(base_version) is not int or not 0 <= base_version < 2147483647:
            raise ValueError('Invalid base Android version')
        path = self.root / 'version.json'
        if path.is_symlink():
            raise ValueError('Invalid Android version counter')
        state = json.loads(path.read_text()) if path.exists() else {'last': 0}
        if not isinstance(state, dict) or set(state) != {'last'}:
            raise ValueError('Invalid Android version counter')
        previous = state['last']
        if type(previous) is not int or not 0 <= previous <= 2147483647:
            raise ValueError('Invalid Android version counter')
        version = max(previous + 1, base_version + 1, self.minimum)
        if version > 2147483647:
            raise ValueError('Android version counter exhausted')
        atomic_json(path, {'last': version})
        return version

    def publish(self, key, source_commit, apk, manifest, report):
        if not COMMIT.fullmatch(source_commit) or not HEX.fullmatch(key):
            raise ValueError('Invalid APK provenance')
        metadata = update_metadata(manifest, apk)
        destination = self.root / key
        if destination.exists() or destination.is_symlink():
            raise ValueError('Signed APK cache entries are immutable')
        with tempfile.TemporaryDirectory(prefix='.apk-', dir=self.root) as directory:
            temporary = Path(directory) / 'entry'
            temporary.mkdir(mode=0o700)
            shutil.copyfile(apk, temporary / 'client.apk')
            (temporary / 'client.apk').chmod(0o600)
            atomic_json(temporary / 'receipt.json', {'schema': 1, 'input_sha256': key,
                'source_commit': source_commit, 'metadata': metadata, 'build_report': report})
            os.replace(temporary, destination)
        return self.lookup(key)

"""Immutable byte-transform outputs, separate from QA evidence and signed APKs."""
import hashlib
import importlib
import json
import os
from pathlib import Path
import re
import shutil
import sys
import sysconfig
import tempfile

import client_qa

LIMIT = 32 * 1024 * 1024


def patch_policy(vendor):
    """Reviewed pure PE transforms: package code, parser libraries and Python."""
    vendor = Path(vendor)
    files = {}
    identities = {}
    def add(name, path):
        value = client_qa.digest(path)
        files[str(path.resolve())] = value
        identities[name] = value
    add('cache-policy', Path(__file__))
    add('cache-primitives', Path(client_qa.__file__))
    for owner in ('launch-build', 'server'):
        for path in sorted((vendor / owner).rglob('*.py')):
            if '__pycache__' not in path.parts:
                add('trusted/' + path.relative_to(vendor).as_posix(), path)
    for name in ('dnfile', 'dncil', 'pefile'):
        module = importlib.import_module(name)
        if hasattr(module, '__path__'):
            for index, folder in enumerate(module.__path__):
                folder = Path(folder)
                for path in sorted(folder.rglob('*')):
                    if path.is_file() and '__pycache__' not in path.parts:
                        add(name + '/' + str(index) + '/' + path.relative_to(folder).as_posix(), path)
        else:
            add(name, Path(module.__file__))
    standard = Path(sysconfig.get_path('stdlib'))
    for path in sorted(standard.rglob('*')):
        if (path.is_file() and path.suffix in ('.py', '.so')
                and not {'__pycache__', 'site-packages', 'dist-packages'} & set(path.relative_to(standard).parts)):
            add('python/' + path.relative_to(standard).as_posix(), path)
    add('python-executable', Path(sys.executable))
    return {'schema': 1, 'python': sys.version, 'implementation': sys.implementation.cache_tag,
            'files': identities}, files


class Store:
    def __init__(self, root):
        self.guard = client_qa.Store(root)
        self.root = self.guard.root

    def transform(self, stage, policy, raw, compute, *, verify=None):
        if not isinstance(stage, str) or not re.fullmatch(r'[a-z][a-z0-9_-]{0,63}', stage):
            raise ValueError('Invalid build artifact stage')
        if not isinstance(raw, bytes) or len(raw) > LIMIT:
            raise ValueError('Invalid build artifact input')
        input_sha256 = hashlib.sha256(raw).hexdigest()
        policy_sha256 = client_qa.fingerprint(policy)
        identity = {'schema': 1, 'stage': stage, 'input_sha256': input_sha256,
                    'policy_sha256': policy_sha256}
        key = client_qa.fingerprint(identity)
        path = self.root / key
        with self.guard.locked():
            if path.exists() or path.is_symlink():
                if path.is_symlink() or not path.is_dir() or {p.name for p in path.iterdir()} != {
                        'metadata.json', 'payload.bin', 'seal.json'}:
                    raise ValueError('Invalid build artifact cache entry')
                for name, maximum in (('metadata.json', 16384), ('payload.bin', LIMIT), ('seal.json', 16384)):
                    item = path / name
                    if item.is_symlink() or not item.is_file() or item.stat().st_size > maximum:
                        raise ValueError('Unsafe build artifact cache file')
                expected = {name: client_qa.digest(path / name) for name in ('metadata.json', 'payload.bin')}
                metadata = json.loads((path / 'metadata.json').read_text())
                if (json.loads((path / 'seal.json').read_text()) != expected
                        or metadata != dict(identity, key=key, output_sha256=expected['payload.bin'],
                                            bytes=(path / 'payload.bin').stat().st_size)):
                    raise ValueError('Build artifact cache integrity mismatch')
                if verify:
                    verify()
                return (path / 'payload.bin').read_bytes(), {'input_sha256': key,
                    'output_sha256': expected['payload.bin'], 'reused': True}
            output = compute(raw)
            if not isinstance(output, bytes) or len(output) > LIMIT:
                raise ValueError('Invalid computed build artifact')
            if client_qa.fingerprint(policy) != policy_sha256:
                raise ValueError('Build artifact policy changed during computation')
            if verify:
                verify()
            output_sha256 = hashlib.sha256(output).hexdigest()
            temporary = Path(tempfile.mkdtemp(prefix='.pending-', dir=self.root))
            try:
                (temporary / 'payload.bin').write_bytes(output)
                (temporary / 'metadata.json').write_text(json.dumps(dict(identity, key=key,
                    output_sha256=output_sha256, bytes=len(output)), sort_keys=True))
                (temporary / 'seal.json').write_text(json.dumps({name: client_qa.digest(temporary / name)
                    for name in ('metadata.json', 'payload.bin')}, sort_keys=True))
                for item in temporary.iterdir():
                    item.chmod(0o600)
                os.replace(temporary, path)
            finally:
                if temporary.exists():
                    shutil.rmtree(temporary)
        return output, {'input_sha256': key, 'output_sha256': output_sha256, 'reused': False}

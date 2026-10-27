"""Broad verified client QA reuse and isolated full-suite partitioning."""
from contextlib import contextmanager
from concurrent.futures import ThreadPoolExecutor
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import tempfile
import unittest

HEX = re.compile(r'[0-9a-f]{64}\Z')
COMMIT = re.compile(r'[0-9a-f]{40}\Z')


def digest(path):
    result = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            result.update(block)
    return result.hexdigest()


def tree_identity(root):
    """Every mounted byte, including link identities; image covers image paths."""
    root = Path(root)
    values = {'.': {'directory': True, 'mode': root.stat().st_mode & 0o777}}
    for path in sorted(root.rglob('*')):
        name = path.relative_to(root).as_posix()
        if path.is_symlink():
            values[name] = {'link': os.readlink(path)}
        elif path.is_file():
            values[name] = {'sha256': digest(path), 'mode': path.stat().st_mode & 0o777}
        elif path.is_dir():
            values[name] = {'directory': True, 'mode': path.stat().st_mode & 0o777}
        else:
            raise ValueError('Unsupported client QA mount input')
    return values


def fingerprint(material):
    return hashlib.sha256(json.dumps(material, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def run_parallel(commands, workers, run):
    if type(workers) is not int or not 1 <= workers <= 3:
        raise ValueError('Invalid client QA worker limit')
    with ThreadPoolExecutor(max_workers=workers, thread_name_prefix='client-qa') as pool:
        futures = [pool.submit(run, command) for command in commands]
        return [future.result() for future in futures]


def load_cached(store, key, force_full_qa=False):
    if type(force_full_qa) is not bool:
        raise ValueError('Force full client QA requires a boolean')
    with store.locked():
        return None if force_full_qa else store.lookup(key)


def parse_result(stdout):
    markers = [line.split(b'=', 1)[1] for line in stdout.splitlines()
               if line.startswith(b'PRIVATE_CLIENT_TEST_RESULT=')]
    if len(markers) != 1:
        raise ValueError('Exactly one trusted client QA summary is required')
    result = json.loads(markers[0])
    if not isinstance(result, dict):
        raise ValueError('Invalid trusted client QA summary')
    return result


def selected_suite(suite, index, count):
    if type(index) is not int or type(count) is not int or not 1 <= count <= 3 or not 0 <= index < count:
        raise ValueError('Invalid client QA partition')
    def flatten(item):
        if isinstance(item, unittest.TestSuite):
            for child in item:
                yield from flatten(child)
        else:
            yield item
    cases = list(flatten(suite))
    discovered = sorted(case.id() for case in cases)
    if len(set(discovered)) != len(discovered):
        raise ValueError('Duplicate discovered client tests')
    admitted = set(discovered[index::count])
    return unittest.TestSuite(case for case in cases if case.id() in admitted), discovered


def validate_results(commands, required=(), minimum=1):
    ids = []
    discovery = None
    shards = []
    if (not isinstance(commands, list) or not commands or type(minimum) is not int or minimum < 1
            or not isinstance(required, (list, tuple)) or any(not isinstance(name, str) for name in required)):
        raise ValueError('Missing client QA results')
    for command in commands:
        if not isinstance(command, dict):
            raise ValueError('Invalid client QA command result')
        result = command.get('result')
        if (command.get('exit_code') != 0 or not isinstance(result, dict) or result.get('passed') is not True
                or any(result.get(key) != 0 for key in ('failures', 'errors', 'skipped'))
                or not isinstance(result.get('test_ids'), list)
                or any(not isinstance(name, str) for name in result['test_ids'])
                or result.get('tests') != len(result['test_ids'])):
            raise ValueError('Invalid client QA result')
        ids.extend(result['test_ids'])
        if 'shard_count' in result:
            count, index = result['shard_count'], result.get('shard_index')
            found = result.get('discovered_test_ids')
            if (type(count) is not int or type(index) is not int or not 1 <= count <= 3 or not 0 <= index < count
                    or not isinstance(found, list) or any(not isinstance(name, str) for name in found)
                    or found != sorted(set(found)) or sorted(result['test_ids']) != found[index::count]
                    or (discovery is not None and discovery != found)):
                raise ValueError('Client QA partition coverage mismatch')
            discovery = found
            shards.append((index, count))
    if (len(ids) != len(set(ids)) or len(ids) < minimum or not set(required) <= set(ids)
            or (discovery is not None and (sorted(ids) != discovery
                or sorted(shards) != [(index, len(shards)) for index in range(len(shards))]))):
        raise ValueError('Incomplete client QA coverage')
    return {'tests': len(ids), 'test_ids': sorted(ids), 'failures': 0, 'errors': 0, 'skipped': 0, 'passed': True}


class Store:
    def __init__(self, directory):
        self.root = Path(directory).absolute()
        if any(path.is_symlink() for path in (self.root, *self.root.parents)):
            raise ValueError('Invalid client QA cache')
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)

    @contextmanager
    def locked(self):
        fd = os.open(self.root / 'lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'a') as stream:
            fcntl.flock(stream, fcntl.LOCK_EX)
            yield self

    def lookup(self, key):
        if not isinstance(key, str) or not HEX.fullmatch(key):
            raise ValueError('Invalid client QA cache identity')
        path = self.root / key
        if not path.exists() and not path.is_symlink():
            return None
        if path.is_symlink() or not path.is_dir():
            raise ValueError('Invalid client QA cache entry')
        for name in ('receipt.json', 'tests.log', 'seal.json'):
            item = path / name
            if item.is_symlink() or not item.is_file() or item.stat().st_size > 64 * 1024 * 1024:
                raise ValueError('Incomplete client QA cache entry')
        seal = json.loads((path / 'seal.json').read_text())
        if seal != {name: digest(path / name) for name in ('receipt.json', 'tests.log')}:
            raise ValueError('Client QA cache checksum mismatch')
        receipt = json.loads((path / 'receipt.json').read_text())
        if (not isinstance(receipt, dict) or set(receipt) != {'schema', 'input_sha256', 'tested_source_commit',
                'commands', 'required_test_ids', 'minimum_tests'}
                or receipt.get('schema') != 1 or receipt.get('input_sha256') != key
                or not isinstance(receipt.get('tested_source_commit'), str)
                or not COMMIT.fullmatch(receipt['tested_source_commit'])):
            raise ValueError('Invalid client QA cache receipt')
        validate_results(receipt['commands'], receipt['required_test_ids'], receipt['minimum_tests'])
        return dict(receipt, log=(path / 'tests.log').read_bytes())

    def publish(self, key, commit, commands, log, required, minimum):
        validate_results(commands, required, minimum)
        if not isinstance(commit, str) or not COMMIT.fullmatch(commit):
            raise ValueError('Invalid tested client source identity')
        if self.lookup(key) is not None:
            return
        temporary = Path(tempfile.mkdtemp(prefix='.pending-', dir=self.root))
        try:
            receipt = {'schema': 1, 'input_sha256': key, 'tested_source_commit': commit,
                       'commands': commands, 'required_test_ids': list(required), 'minimum_tests': minimum}
            (temporary / 'receipt.json').write_text(json.dumps(receipt, sort_keys=True))
            (temporary / 'tests.log').write_bytes(log)
            (temporary / 'seal.json').write_text(json.dumps({name: digest(temporary / name)
                                                           for name in ('receipt.json', 'tests.log')}))
            for item in temporary.iterdir():
                item.chmod(0o600)
            os.replace(temporary, self.root / key)
        finally:
            if temporary.exists():
                shutil.rmtree(temporary)

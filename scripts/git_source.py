"""Bounded raw Git object reads; no checkout, filters, hooks or source execution."""
import os
from pathlib import Path
import re
import subprocess

OID = re.compile(r'[0-9a-f]{40}\Z')


def read_blobs(repository, objects, *, maximum_blob=32*1024*1024, maximum_total=512*1024*1024):
    objects = list(objects)
    if any(not isinstance(oid, str) or not OID.fullmatch(oid) for oid in objects):
        raise ValueError('Invalid source object identity')
    if not objects:
        return []
    environment = {key: value for key, value in os.environ.items() if not key.startswith('GIT_')}
    environment.update(GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL='/dev/null', GIT_TERMINAL_PROMPT='0')
    command = ['git', '-c', 'core.hooksPath=/dev/null', '-c', 'core.fsmonitor=false',
               '-c', 'credential.helper=', '-C', str(Path(repository).resolve()), 'cat-file']
    requests = ''.join(oid + '\n' for oid in objects).encode('ascii')
    def run(option):
        result = subprocess.run([*command, option], input=requests, capture_output=True,
                                env=environment, timeout=120)
        if result.returncode:
            raise ValueError('Source object read failed')
        return result.stdout
    records = run('--batch-check').splitlines()
    if len(records) != len(objects):
        raise ValueError('Source object metadata mismatch')
    sizes, total = [], 0
    for oid, record in zip(objects, records):
        parts = record.split()
        if len(parts) != 3 or parts[:2] != [oid.encode(), b'blob'] or not parts[2].isdigit():
            raise ValueError('Source must contain regular file blobs')
        size = int(parts[2]);total += size
        if size > maximum_blob or total > maximum_total:
            raise ValueError('Source object size limit exceeded')
        sizes.append(size)
    payload = run('--batch')
    values, cursor = [], 0
    for oid, size in zip(objects, sizes):
        header = oid.encode() + b' blob ' + str(size).encode() + b'\n'
        if not payload.startswith(header, cursor):
            raise ValueError('Source object header mismatch')
        cursor += len(header)
        value = payload[cursor:cursor+size];cursor += size
        if len(value) != size or payload[cursor:cursor+1] != b'\n':
            raise ValueError('Truncated source object')
        cursor += 1;values.append(value)
    if cursor != len(payload):
        raise ValueError('Unexpected source object data')
    return values

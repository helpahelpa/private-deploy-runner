"""Sealed whole-module evidence; source subsets are physically enforced mounts."""
import ast
from concurrent.futures import ThreadPoolExecutor
from functools import lru_cache
import hashlib
from pathlib import Path
import os
import re

import client_qa
import component_inputs

# These modules exercise binary transforms using retained fixtures. Other/new
# modules deliberately keep the full client boundary until reviewed in isolation.
BINARY_MODULES = frozenset(('test_tempering_build_adapters', 'test_patch_clone_coop',
    'test_tempering_ui', 'test_device_identifier', 'test_shared_activity_hp',
    'test_dev_shortcuts', 'test_tempering_diagnostic', 'test_local_accounts'))


@lru_cache(maxsize=256)
def imported_modules(content):
    # The cache key is the actual bytes, never a timestamp or mutable file path.
    # Return only import names, allowing the much larger AST to be released.
    return tuple(imported for node in ast.walk(ast.parse(content))
        for imported in ([alias.name for alias in node.names] if isinstance(node, ast.Import)
                         else [node.module or ''] if isinstance(node, ast.ImportFrom) else []))


def server_batches(inventory):
    groups = [[] for _ in range(8)]
    for module in modules(inventory):
        groups[int(hashlib.sha256(module.encode()).hexdigest()[:8], 16) % len(groups)].append(module)
    return [group for group in groups if group]


def modules(inventory):
    if not isinstance(inventory, list) or not inventory or inventory != sorted(set(inventory)):
        raise ValueError('Invalid QA module inventory')
    result = {}
    for name in inventory:
        if not isinstance(name, str) or len(name.rsplit('.', 2)) != 3:
            raise ValueError('Invalid QA test identity')
        module = name.rsplit('.', 2)[0]
        if not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*', module):
            raise ValueError('Unsafe QA module identity')
        result.setdefault(module, []).append(name)
    return result


def closure(root, tree, seeds, owners):
    """Read imports as data; missing dynamic dependencies stay hidden and fail QA."""
    selected, pending = set(), list(seeds)
    while pending:
        name = pending.pop()
        if name in selected or name not in tree:
            continue
        selected.add(name)
        if not name.endswith('.py'):
            continue
        for imported in imported_modules((Path(root) / name).read_bytes()):
            relative = imported.replace('.', '/')
            for owner in owners:
                for candidate in (owner + '/' + relative + '.py', owner + '/' + relative + '/__init__.py'):
                    if candidate in tree and candidate not in selected:
                        pending.append(candidate)
    return selected


def client_inputs(root, tree, module):
    if module not in BINARY_MODULES:
        selected = closure(root, tree, ['launch-build/' + module + '.py'], ('launch-build', 'server', 'work'))
        return {name: value for name, value in component_inputs.client_source(tree).items()
                if not (name.startswith('launch-build/test_') and name.endswith('.py')) or name in selected}
    selected = closure(root, tree, ['launch-build/' + module + '.py'], ('launch-build', 'work'))
    selected.update(name for name in tree if name.startswith(('work/', 'output/')))
    selected.update(component_inputs.fallback_source(tree))
    return {name: tree[name] for name in sorted(selected)}


def server_inputs(root, tree, module):
    # All production server modules remain shared. Test helpers are a transitive
    # import closure; unrelated test files are hidden beneath a directory mount.
    selected = closure(root, tree, ['server/' + module + '.py'], ('server',))
    selected.update(name for name in tree if not name.startswith('server/test_'))
    return {name: tree[name] for name in sorted(selected)}


def materialize(source, destination, names):
    destination = Path(destination)
    destination.mkdir()
    for name in names:
        path = destination / name
        path.parent.mkdir(parents=True, exist_ok=True)
        os.link(Path(source) / name, path)
    (destination / 'server/logs').mkdir(parents=True, exist_ok=True)
    return destination


def run(inventory, keys, store, commit, execute, *, workers, force=False, weights=None,
        required=(), minimum=1, batches=None):
    expected = modules(inventory)
    if set(keys) != set(expected) or type(workers) is not int or not 1 <= workers <= 4:
        raise ValueError('Incomplete QA module plan')
    records, pending = {}, []
    for module in expected:
        cached = client_qa.load_cached(store, keys[module], force)
        if cached:
            commands, log, tested = cached['commands'], cached['log'], cached['tested_source_commit']
            if len(commands) != 1:
                raise ValueError('Ambiguous cached QA module evidence')
            total = client_qa.validate_results(commands, expected[module], len(expected[module]))
            if total['test_ids'] != expected[module]:
                raise ValueError('Cached QA module inventory mismatch')
            records[module] = (commands, log, tested, True)
        else:
            pending.append(module)
    weights = weights or {}
    if batches is not None:
        flattened = [name for batch in batches for name in batch]
        if sorted(flattened) != sorted(expected) or len(flattened) != len(set(flattened)):
            raise ValueError('Incomplete QA execution groups')
    planned = ([[name] for name in pending] if batches is None else
               [[name for name in batch if name in pending] for batch in batches])
    planned = sorted((batch for batch in planned if batch),
        key=lambda batch: (-sum(weights.get(name, len(expected[name])) for name in batch), batch))
    def fresh(batch):
        values = ({batch[0]: execute(batch[0], expected[batch[0]])} if batches is None else
                  execute(batch, {name: expected[name] for name in batch}))
        if set(values) != set(batch):
            raise ValueError('Incomplete QA execution group results')
        results = {}
        for module, (command, log) in values.items():
            total = client_qa.validate_results([command], expected[module], len(expected[module]))
            if total['test_ids'] != expected[module]:
                raise ValueError('Fresh QA module inventory mismatch')
            results[module] = ([command], log, commit, False)
        return results
    with ThreadPoolExecutor(max_workers=workers, thread_name_prefix='qa-module') as pool:
        futures = [pool.submit(fresh, batch) for batch in planned]
        try:
            for future in futures:
                records.update(future.result())
        except BaseException:
            for future in futures:
                future.cancel()
            raise
    commands, logs, provenance = [], [], []
    for module in expected:
        values, log, tested, reused = records[module]
        commands.extend(values);logs.append(log)
        provenance.append({'module': module, 'input_sha256': keys[module],
            'test_ids': expected[module], 'tests': len(expected[module]),
            'tested_source_commit': tested, 'reused': reused,
            'reason': 'verified inputs unchanged' if reused else 'force full QA' if force else 'inputs not verified'})
    totals = client_qa.validate_results(commands, required, minimum)
    if totals['test_ids'] != inventory:
        raise ValueError('Incomplete aggregate QA module coverage')
    origins = {item['tested_source_commit'] for item in provenance}
    return {'qa': totals, 'commands': commands, 'logs': logs, 'modules': provenance,
            'reused': all(item['reused'] for item in provenance),
            'tested_source_commit': next(iter(origins)) if len(origins) == 1 else None,
            'fresh_tests': sum(item['tests'] for item in provenance if not item['reused'])}


def publish(store, result, commit):
    # Call only after the caller verifies its frozen inputs and sandbox cleanup.
    offset = 0
    with store.locked():
        for index, item in enumerate(result['modules']):
            if not item['reused']:
                store.publish(item['input_sha256'], commit, [result['commands'][offset]],
                    result['logs'][index], item['test_ids'], item['tests'])
            offset += 1

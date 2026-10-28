"""High-level client/server inputs match what their isolated suites can read."""
from pathlib import PurePosixPath

SERVER_FIXTURES = frozenset(('launch-build/qa_stage2_combat_fixture.py',
                             'launch-build/dev_tools.py', 'launch-build/screenshot_preview.py'))


def client_source(tree):
    # The invitation client integration imports this one server test helper.
    # Server production remains shared: those integrations must run when it changes.
    return {name: value for name, value in tree.items()
            if (PurePosixPath(name).suffix != '.md' or PurePosixPath(name).name == 'AGENTS.md')
            and not name.startswith('deploy/cloudflare/')
            and not (name.startswith('server/test_') and name != 'server/test_account_auth.py')}


def fallback_source(tree):
    # Known component owners have narrower readable mounts below. Unrecognized
    # roots/configuration stay in every component key. The complete path inventory
    # additionally invalidates both components on additions, deletions and renames.
    owners = ('server/', 'launch-build/', 'work/', 'output/', 'deploy/cloudflare/', 'deploy/multiplayer/')
    return {name: value for name, value in tree.items()
            if PurePosixPath(name).name == 'AGENTS.md'
            or (not name.startswith(owners) and PurePosixPath(name).suffix != '.md')}


def identity(tree, component):
    if component == 'client':
        source = client_source(tree)
    elif component == 'server':
        source = {name: value for name, value in tree.items()
                  if name in SERVER_FIXTURES or name.startswith('server/')}
    else:
        raise ValueError('Unknown source component')
    return {'schema': 1, 'paths': sorted(tree), 'source': source, 'fallback': fallback_source(tree)}

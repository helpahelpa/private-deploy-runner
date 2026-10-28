# CI performance

The deployment gate still requires complete passing evidence, fresh transport and
admission checks, a healthy replacement, synchronized launch pins, and a stopped
predecessor. A rollback remains a failed deployment. Source code stays inside
restricted containers; the host only reads raw Git objects and runs trusted tools.

## Input boundaries

QA evidence is cached by complete test module, with a separate whole-server image
and suite cache and an independent material-input signed APK cache. No individual
test method is cached or separated from its class/module fixtures. Every attempt
rediscovers the complete client and server inventories inside restricted containers.
An unchanged complete client suite also has a sealed shortcut: after fresh
discovery matches, it bypasses module planning and restores the same original
module provenance. Any complete-input change falls back to finer module reuse.
The controller requires an exact, duplicate-free union of fresh and reused IDs,
all required cases, and zero errors, failures, skips or expected failures.

Client modules normally see shared production client/server inputs and their
transitively imported test helpers. Unrelated client test modules are hidden by
a read-only directory overlay. Eight reviewed expensive binary-transform modules
(`qa_tasks.BINARY_MODULES`) instead receive only their Python import closure,
retained work/output fixtures and conservative unknown configuration inputs.
Their server and Java/C# sources are physically absent. An undeclared dynamic
dependency therefore fails execution rather than silently escaping the key.
New modules default to the broader client boundary. Excluded files and their
empty parent directories are removed, so excluded path additions cannot leave
observable inputs outside the key. Imported helper-test changes
invalidate their consumers. Fixture, harness, toolchain and immutable image inputs
remain conservatively shared. Worker count is scheduling-only; mounted weights
and executable scheduling/harness policy remain hashed.

Server module keys use eight stable groups, assigned by a hash of the module
name. Each group mount contains all shared production server modules and the
transitive test-helper closure of that group; other tests are hidden. This lets
missing modules in a group share one container startup and data import. A test
edit invalidates its group and any groups importing it as a helper. Adding a
module affects its assigned group without rebalancing every group. Receipts list
each module's readable group explicitly. Shared runtime, static game data/text and
the three reviewed client-side fixtures invalidate all server modules.
A complete unchanged server can still reuse its image and prior suite receipt;
its current discovered inventory is checked before acceptance.

New, removed or renamed tests are handled through fresh discovery; readable file
additions/deletions alter the affected module key. Unrecognized configuration and
agent instructions stay conservative inputs. Source is read as data on the host;
AST import inspection never imports source code. Parsed import names are reused
by exact file content, and common toolchain/configuration identities are hashed
once before constructing individual module keys. All source execution remains in
restricted containers without signing identities or cache mounts.

Each sealed module entry records its input digest, exact passing IDs, private log
and original tested commit. Mixed-cache receipts retain provenance per module,
not an invented single original commit. Logs show fresh modules, reused modules
and fresh test counts. Cache corruption, missing/duplicate IDs, changed discovery,
failed tests or failed cleanup fail the build. Evidence is published only after
frozen-input checks; later packaging/deployment failures still fail the workflow.

## Scheduling and measurements

Client modules stay intact so expensive class/module fixtures run once. A bounded
pool of four isolated containers takes the longest estimated missing modules first,
with deterministic name tie-breaking. Each container records complete module time,
including setup and cleanup. Cached modules occupy no worker slot. Server groups
use a bounded pool of two; each group executes only missing modules. Noncached
standalone server/transport execution
retains its complete-module partitioning.

Update `scripts/client-qa-weights.json` from a successful forced run's
`client-tests.json` command results (`module_seconds`). Keep weights positive and
finite; timings guide scheduling only and never determine test selection. The
weights and executable scheduler are included in the QA identity. Avoid more workers until
resource measurements justify their repeated startup and memory cost.

Server QA uses two workers with complete modules. Transport uses three capped
Python workers when `python_workers: 3` is configured, plus an independent Node
check. Python workers each receive one CPU and 1 GiB; suites retain independent
temporary filesystems and the same network/privilege restrictions. Every worker
is joined and cleaned up before a failure can return. All Python transport tests
must appear exactly once, meet the total floor, and have zero failures or skips.
Client workers are capped at two CPUs and 2 GiB each; their combined memory cap
is 8 GiB. Choose the worker count after measuring available headroom for production
and server/transport QA.

Source preparation uses bounded `git cat-file --batch-check` and `--batch` reads.
Object kind, identity, declared size, returned framing and complete output are
validated; path/mode checks and pinned LFS hydration remain in the callers.
No Git checkout filters or source build hooks execute on the host.

The transport's RFC6455 masking uses native byte translation in four mask lanes
instead of Python loops over every byte. The large-download check still transfers
the full 169 MiB and verifies TLS, backpressure, framing and the final digest.

Compare full-run wall time, slowest client worker, fresh transport duration and
source preparation. Keep queue time separate. Use an unchanged-source warm run to
measure cache overhead. Do not add concurrent benchmark load to a comparison run.

## Full validation and rollback

Use the existing **Force full QA** workflow option to bypass every module and whole-component result
cache. It still preserves an unchanged signed APK. Transport and live deployment
checks always run fresh. Corrupt cache evidence fails closed.

For an input-boundary regression, force full QA and restore the last reviewed
boundary/sandbox policy together. For scheduling changes, revert the scheduler
and weights together. Reverting CI policy does not authorize restoring player
data or older production source. Deployments continue using the normal fenced
handoff and persistent data volume.

## Verified deployment results

The 2026-10-28 forced run completed in **5m22s**, compared with **7m50s** for the
previous fresh run with the same 1,041 source-check inventory (about 32% shorter).
It executed all 219 client, 740 server, 59 Python transport and 23 Worker checks.
The slowest client worker fell from 333.5 to 199.9 seconds. Fresh transport checks
finished in 16.1 seconds, retaining the full 169 MiB streaming scenario.

The subsequent warm run completed in **1m24s**, reusing verified whole-client and
whole-server QA evidence while executing all 82 transport checks fresh. Both runs
performed a real container replacement, verified a healthy successor and stopped
predecessor, preserved player data, and reused the exact signed APK.

These are individual observed job durations, including deployment verification;
queue time is separate. They are not guarantees for future changes or cache states.

- [Previous fresh baseline](https://github.com/helpahelpa/private-deploy-runner/actions/runs/40609700011)
- [Optimized forced deployment](https://github.com/helpahelpa/private-deploy-runner/actions/runs/40613397366)
- [Optimized warm deployment](https://github.com/helpahelpa/private-deploy-runner/actions/runs/40614243843)

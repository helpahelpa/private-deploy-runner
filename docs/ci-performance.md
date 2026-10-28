# CI performance

The deployment gate still requires complete passing evidence, fresh transport and
admission checks, a healthy replacement, synchronized launch pins, and a stopped
predecessor. A rollback remains a failed deployment. Source code stays inside
restricted containers; the host only reads raw Git objects and runs trusted tools.

## Input boundaries

There are two QA result caches: whole client and whole server. No individual test
results are cached. The signed native package has a separate material-input cache;
changing QA or documentation must not create an Android update.

Client QA reads client source/tools/fixtures and shared production server code.
Its invitation integration imports `server/test_account_auth.py`; that helper is
also included. Other server tests, transport source and Markdown documentation
are removed from its source mount and excluded from its result fingerprint.
Agent instructions remain an input. These exclusions are enforced by the mount,
not just omitted from a cache key. Updating a consumer test invalidates its entire
component; a newly required missing input therefore fails before reusable evidence
can be published.

Server QA reads committed server modules/contracts, test JSON, static game tables,
and three client-side fixture dependencies: `qa_stage2_combat_fixture.py`,
`dev_tools.py`, and `screenshot_preview.py`. If those helpers acquire another local
dependency, review it and add it to `component_inputs.SERVER_FIXTURES`. Do not mount
a broader directory without adding all its readable inputs to the fingerprint.

Both fingerprints include the complete source path inventory. Additions, removals
and renames conservatively invalidate both components, including new test files.
Unrecognized roots and configuration remain shared inputs. Shared production,
fixtures, policy, harness, toolchain, image and configuration changes invalidate
the relevant whole component. Receipt provenance distinguishes reused evidence
from fresh execution and records the original tested commit.
Fresh client QA evidence is retained after the complete suite and frozen-input
verification pass, before packaging. A later packaging failure still fails the
workflow; retrying can reuse the verified QA while repeating packaging and its
artifact checks.

## Scheduling and measurements

Client modules stay intact so expensive class/module fixtures run once. The
trusted scheduler assigns the longest estimated modules first to the least loaded
of four workers, with deterministic name/index tie-breaking. Unknown modules get
a conservative estimate. Each worker records complete module wall time, including
setup and cleanup; the controller checks identical discovery and exact coverage.

Update `scripts/client-qa-weights.json` from a successful forced run's
`client-tests.json` command results (`module_seconds`). Keep weights positive and
finite; timings guide scheduling only and never determine test selection. The
weights and scheduler are included in the QA identity. Avoid more workers until
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

Use the existing **Force full QA** workflow option to bypass both component result
caches. It still preserves an unchanged signed APK. Transport and live deployment
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

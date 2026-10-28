# Deployment controller

This public repository owns the deployment workflow and its runner. Host settings,
credentials, and raw diagnostics remain in private local configuration. Approved
contributors can propose changes through pull requests; anyone can inspect the
reviewed scripts and sanitized Actions logs.
Only the owner should be able to update `master`. The game repository has no self-hosted runner, dispatch credential,
deployment workflow, or host configuration. A contributor who can push game code
can request its ordinary deployment through a master push; that code cannot choose
a host command, checkout ref, workflow path, or deployment configuration.

The host watcher polls source `master` every ten seconds using existing host-side
`gh` authentication. It verifies the configured repository and owner numeric IDs,
then dispatches this repository's fixed `deploy.yml` workflow. The workflow runs
only on a repository-scoped runner with the `private-deploy` label. Use a generic
container hostname for that runner and do not give it the Docker socket, host home,
host credentials, signing key, or deployment tools.

The workflow checks out only this controller with a pinned official
checkout action and disabled credential persistence. Its token has read-only
contents/actions permissions. `scripts/pipeline.py` receives `SOURCE_SHA` through
the environment and reads `/config/pipeline.json`. The runner-side controller is
an IPC client to a trusted host broker through `/ipc`; the private runner
configuration contains only the IPC socket and authentication-file paths. The
host broker must independently validate the strict lowercase 40-character SHA,
allowlisted source identity, and current source master before running its fixed
pipeline. Source code and tests run only inside the restricted build container,
without GitHub tokens or host credentials. A successful workflow must mean the
requested SHA actually passed QA and a healthy replacement container became
active with the previous server stopped; a stale request must fail.

Use **Actions → Main deployment → Run workflow** to run the entire pipeline.
Leave `source_sha` blank to resolve current source `master` on the trusted host.
An explicit SHA must still be current `master`. Each GitHub run and retry gets
its own numeric `run-id`/`run-attempt` identity, immutable logs, tested artifacts,
and deployment receipt. Each attempt assembles a new release and replaces the
server even if that commit is already active. By default, it can reuse verified
client/server test modules when their isolated input fingerprints match.
An unchanged complete client bypasses module planning after fresh discovery;
an unchanged server reuses its verified image and suite evidence.
Materially unchanged signed APKs
remain byte-identical through the separate native APK cache.

Select **Force full QA** to bypass both component test caches and rerun the full
client and server suites. Push-triggered runs use normal component reuse. A
retry retains the original run's QA setting; start a new run to change it.
Forced QA still reuses an unchanged signed APK and does not create an Android
update just to rerun tests. Transport checks and final deployment verification
run on every attempt.

Client QA is configured for four independent restricted containers, and server
QA for two. Every attempt discovers the full suite in an isolated container,
then bounded workers execute complete modules whose verified inputs changed.
The trusted controller checks that their combined result includes
every expected test exactly once with no skips, failures, or errors. Workers
have separate temporary filesystems; failed workers fail the entire build.
Client workers keep complete modules together and use recorded durations, including
fixture setup and cleanup, rather than distributing equal numbers of methods.
Server modules share eight stable isolated input groups to amortize startup;
a test edit invalidates its group and helper consumers. The three transport
Python modules also run independently, alongside Node, on
every attempt. Phase and worker timings are included in the build logs.
Logs identify cache hits, fresh test runs, worker totals, and the original tested
commit. Reused evidence is never presented as newly executed tests.

The cache fingerprints include admitted source and tests, copied fixtures,
trusted harness/build policy, pinned tools and images, and relevant private
configuration. Client integration tests can read shared server code, so those
inputs invalidate the client modules that can read them. Eight expensive binary
transform modules use narrower source mounts and can reuse evidence across shared
server or Java/C# changes. Cache entries are sealed only
after success, hash-checked before reuse, and kept outside source/test mounts.
Corrupt evidence fails the build. Server admission invariants, artifact hashes,
handoff, live replacement health, and the stopped predecessor are checked for
every deployment, including cache hits.

Documentation and unrelated server-test/transport content are excluded from the
client sandbox and its QA fingerprint. Server QA mounts only its three reviewed
client-side fixture dependencies. New, deleted and renamed tests enter fresh
discovery; changed production paths invalidate the modules that can read them.
Unknown configuration stays in every module key. See
[CI performance and input boundaries](docs/ci-performance.md) for maintenance,
measurement and rollback instructions.

The workflow stays running until registry synchronization and independent live
replacement verification finish. Build/test errors, failed handoff, unhealthy
replacement, registry errors, code rollback, and interrupted attempts fail the
run. A healthy old server restored by rollback never makes the failed run green.
Same-commit redeployment uses the normal fenced handoff and data-preserving
snapshot checks, creates a new container, and verifies that its predecessor stopped.

A commit that changes neither the server image nor the release assets - a
documentation-only change, or anything that leaves both artifacts byte-identical -
is adopted without touching the running world. The engine records the release
receipt with `restarted: false`, moves the tracked commit forward while the
server release stays the commit whose image is running, verifies the active
container is still healthy and still the expected image, and the job reports
`server_restarted: false`. `status` therefore separates `managed_release` (the
latest adopted commit) from `server_release` (the running image), and a later
image-changing commit still performs the fenced handoff from that server release.
Set `require_request_id_for_submit: true` in production broker configuration.
Historical pre-upgrade workflows then fail closed instead of replaying a cached
success; create a new run using the current workflow to get the new behavior.
Historical status and log reads remain available.

## Build and test logs

The workflow displays separate **Build and test server, client and transport**,
**Replace the active server**, and **Verify healthy replacement and stopped
previous server** steps. Builds and tests overlap in restricted containers, so
the first step reports that combined phase accurately. Expand each step for
live compiler, image-build, individual test output, and handoff/health milestones.
Its summary also records the resolved commit, attempt and current phase.
Failures retain their
sanitized diagnostic output before the job fails. Successful client regressions
also retain their original output in the immutable private build cache.

The host sends only a sanitized journal through authenticated, cursor-based IPC.
Known private strings, credentials, PEM blocks, addresses, emails, user paths, and
terminal controls are filtered before a line enters that journal. Raw diagnostics
remain private. Logs are bounded to 2 MiB and are available in GitHub's normal job
log download; the source container receives neither the journal nor credentials.

Cached components clearly label reused results; **Force full QA** executes all
client and server tests again. For a historical SHA-only job, run with `logs_only` enabled
and its original source SHA. The **Show recorded build and test logs** step reads
logs without building, deploying, changing job status, or checking out game code.
Its run name starts with `logs-`, so the automatic watcher cannot mistake it for
a deployment. Ordinary automatic runs keep `logs_only` disabled.

Set `publish_status` in private watcher configuration to publish `deployment/Main`
on the source commit. Pending, success, and failure states link to the actual
deployment run; recorded-log runs never become deployment results. Status delivery
uses a durable outbox, so a temporary GitHub failure does not dispatch another
deployment. Public Actions logs contain sanitized build and test output; raw
diagnostics remain on the host.

## Controller changes and access

`.github/CODEOWNERS` assigns review to the owner. `master.ruleset.json` prepares
the corresponding owner-only update rule, required owner review, and protection
against deletion and force pushes. Apply it through GitHub's repository rulesets
API and verify enforcement. A public repository supports this protection on
GitHub Free. Contributors can push their own branches and open pull requests;
only the owner can update protected `master`. The CODEOWNERS file alone does not
restrict writes. Audit all reachable history and historical Actions output before
making a previously private controller public.

Repository identity stays pinned to the configured numeric repository and owner
IDs. Set `control_private: false` in the host's watcher and broker configurations,
and `repository_private: false` in runner setup configuration, for a public
controller. Their defaults require a private controller. Both settings reject a
visibility mismatch; public visibility never permits a different repository or
owner. Set `control_repository_private: false` in private registry configuration
so local deployment receipts describe the controller accurately. The game source
repository and credentials can remain private.

The only workflow trigger is manual dispatch. Fork pull requests do not run on
the self-hosted runner. Keep the runner scoped to this repository and require
owner review for changes to workflows and these controls.

## Watcher setup

Copy `watcher.config.example.json` to private host configuration and replace its
example identities with GitHub's numeric repository and owner IDs. Set
`state_file` to durable private storage. Set the watcher's optional
`desired_commit_file` to the same absolute private path required by the engine.
The watcher atomically publishes verified master there on every poll, including
during a running build, without rewriting an unchanged SHA. Set
`attempt_bindings` to the broker's private `attempts` directory so manual runs
and same-run retry attempts update source commit status, including failure of
a redeployment of an already deployed commit. An older success cannot overwrite
the new attempt's pending or failed status. Keep actual machine names, network
addresses, filesystem locations, and credentials out of tracked files. The host
account's `gh` identity needs to read the source repository and dispatch/read
actions in this controller repository. Never copy that authentication into either
the source checkout or runner container.

Application-specific client, relay, and launcher snapshots stay outside this
public repository, in ignored `local/trusted-tooling/`. Provision the reviewed
client snapshot under `local/trusted-tooling/client-build`, or set `trusted_tooling`
in private client configuration to its absolute path. The builder fingerprints
the snapshot and uses its fixed compiler/test adapters; game source cannot replace
these host tools. Provisioning and reviewing these private dependencies is an
operator step. See [client build configuration](docs/client-build.md).

The reviewed private relay snapshot is owner-controlled infrastructure.
It is updated manually after relay QA; source pushes cannot replace a host-network
gateway, change its private configuration, or publish a Worker deployment.

Run the watcher as a persistent host service with automatic restart:

```sh
python3 scripts/watch_master.py --config /config/watcher.json
```

`--once` performs one poll for service diagnostics. Status messages are generic;
GitHub response bodies and subprocess output remain captured. There is no inbound
webhook, public port, or source-repository secret.

The watcher holds an exclusive file lock and atomically persists a mode-0600
state file before dispatch. Restarts reconcile an existing workflow run instead
of dispatching again. An ambiguous API response waits for workflow visibility
before retrying. Only a completed successful workflow updates `deployed_sha`.
Failed runs and invisible dispatches retry at most `max_attempts` times per SHA;
an exhausted SHA waits for a new push or a deliberate operator reset of its
private failure entry while the watcher is stopped. Keep the rest of the state
intact when resetting a failure entry. Do not reset state during a live deployment.

If several pushes arrive while deployment is running, the latest observed master
is deployed next. The watcher rechecks master immediately before dispatch and
never cancels a live deployment or handoff. The workflow also uses a fixed
concurrency group with `cancel-in-progress: false`. Preserve the current earned
save and preferences across QA and activation; restore those after QA while
retaining the latest tested server and appropriate client.

## Host broker and runner IPC

Provision private copies of `broker.config.example.json` and
`pipeline.config.example.json`. The broker runs on the host:

```sh
python3 scripts/broker.py --config /config/broker.json
```

The runner receives its small pipeline configuration read-only at
`/config/pipeline.json`, an IPC directory, and a read-only authentication token.
Use a random token of 32–256 characters. Give the runner access to the socket's
group (mode 0660) and token without exposing other host files. Broker replies
contain commit, status, and a fixed stage name. Requests are bounded to 4096
bytes and accept exactly `op`, `sha`, and `token` for `submit` and `status`.
The read-only `logs` operation also requires an integer `cursor` and returns a
bounded page from that job's sanitized journal. There is no command,
filesystem-path, or configuration input.

The host configuration identifies a dedicated bare source cache, read-only
source deploy key, pinned SSH known-hosts file, trusted client build configuration,
and deployment engine configuration. The broker validates the numeric GitHub
identities and independently resolves source master before build and promotion.
Before starting a build, it checks that the engine's private configuration has
an absolute `desired_commit_file`. Immediately before promotion it independently
reverifies master and publishes that exact SHA to the shared authority file;
the engine checks this authority again before handoff.
It reads regular source blobs into a clean repository without running checkout
hooks, filters, source scripts, or source project build hooks on the host. The
server and client builders own their restricted containers and QA checks.

Git LFS pointers stay unchanged in that clean worktree. The broker checks each
referenced object's SHA256 and declared size, then copies it into the checkout's
canonical `.git/lfs/objects` store for the trusted client snapshotter. Individual
objects are bounded to 256 MiB and a commit's unique objects to 2 GiB. Existing
objects can be seeded in the bare cache's `lfs/objects` directory or an optional
private `lfs_object_store` directory. Missing objects require `lfs_binary` with
an absolute `path` and `sha256` pin for the trusted Git LFS executable. Its fetch
uses the fixed source SSH URL, read-only deploy key, pinned known-hosts file,
disabled credential helpers, and fixed endpoint/storage configuration. Source
`.lfsconfig` settings and attribute filters cannot select a command or endpoint.

Optional `static_assets` has `path` and `tree_sha256` fields. Compute the pin as
SHA256 of `json.dumps(deploy_engine.tree(path), sort_keys=True).encode()` using
the trusted engine. The broker verifies that complete base asset tree, overlays
the tested client assets, and publishes the signed APK as `assets/client.apk`
when `publish_apk` is true. It recreates provenance for the complete merged tree
before assembly. Immutable build receipts bind every cached file to its SHA.

The signed APK is content-addressed separately from the incremental asset release.
Server-only, documentation, test or asset-release changes keep the exact APK bytes
and Android version; all exact-commit QA still runs. Material native inputs reserve
a new durable Android version only on a signed-APK cache miss. The public
`/apk-update.json` describes the real signed artifact and certificate without host
settings. See [client build configuration](docs/client-build.md) for cache migration,
version seeding and provenance.

Version allocations begin at `minimum_version` (at least 62), increase durably,
and are never recycled after a failed build. The example reserves 62 for operator
bootstrap and starts automated builds at 63. The engine must already have an
adopted active world before ordinary promotion. An optional `registry_config`
enables only the fixed private `scripts/sync_registry.py --config ... --commit ...`
hook; source payloads cannot select an executable or arguments. The hook runs
after promotion and during verified successful recovery.

One broker worker serializes jobs. Within a job, the fixed server and client
builds run concurrently. Optional `transport_config` adds a third fixed gate
using `check_transport.py` and an operator-owned configuration like
`transport.config.example.json`. It runs exact-commit Python relay and Node worker
tests in pinned local images, with no network, read-only curated source, temporary
logs, and no credentials or other host mounts. Only top-level Cloudflare Python
and JavaScript files, server Python/contracts, and the test certificate helper
enter this sandbox. At least 59 Python and 20 Node tests must pass with zero skips;
the receipt binds commit, source hashes, image pins, counts, and private log hashes.
The private transport configuration also pins required recovered GameData tables
with `fixtures`: each destination under `work/apk/luapack_extracted/GameData/`
maps to an absolute input `path` and `sha256`. These are regular data files copied
into the curated tree, then exposed read-only; the original directory is never
mounted. Pin the complete required recovered data set (the example shows one
entry of that mapping). Fixtures cannot replace server or test code, and are
bounded to 32 MiB per file and 128 MiB total. Their hashes enter the receipt.
All three operations finish before assembly or promotion. Existing immutable
caches remain valid; fresh builds with `transport_config` require its successful
receipt, which is included in the complete cache's file hashes.

An owner can prepare a clean local commit before publishing it with
`python3 scripts/prebuild.py --config /config/broker.json --source /checkout/game --commit <full-sha>`.
Stop the watcher and broker first; this command takes the same exclusive broker
lock, reserves the same monotonic version counter, and invokes the same isolated
builds and immutable cache assembly. It verifies the local HEAD, tracked tree,
and source repository origin. Only the fixed source-cache fetch is redirected to
local Git objects; missing LFS objects fail rather than fetching over the network.
It never promotes a world, queries master, updates a registry, or installs an APK.
Restart the broker and watcher after preparation. A subsequent push of that exact
commit uses the already verified cache and still passes normal deployment checks.

On restart, queued work and interrupted builds
resume with their reserved version. A crash during promotion is accepted as
successful only if the exact requested SHA is healthy and the registry hook
passes. Otherwise the job remains failed with private `recovery_required` state;
an operator must inspect runtime recovery before clearing that flag. A historical
successful receipt is rechecked against the currently active healthy release.
Failed promotions synchronize registry metadata with the actual healthy rollback
release while retaining a failed job result. Interrupted handoffs also synchronize
the healthy active release; only the exact requested SHA can become successful.
An unhealthy runtime or failed registry recovery blocks automatic replay.
Do not interrupt a live promotion to clear or rewrite state.

After an operator rewrites author metadata, optional private `history_aliases`
maps the deployed original commit to its rewritten equivalent. The broker checks
that both commits have exactly the same Git tree, then requires future releases
to descend from that equivalent commit. Keep the running release and original QA
receipts intact; record the metadata equivalence separately. Game source cannot
configure aliases or authorize a content-changing history replacement.

For an operator's Windows session, provide the intended WSL distribution name
explicitly. Preview the validated task configuration before registration:

```powershell
.\scripts\keepalive.ps1 -Distribution ExampleDistro -NoRegister
.\scripts\keepalive.ps1 -Distribution ExampleDistro
```

Replace `ExampleDistro` with the operator's chosen distribution. The second
command registers and starts the limited, interactive logon task
`PRIVATE-Deployment-Controller`. It runs only `wsl.exe --distribution ... --exec
/usr/bin/sleep infinity`, keeping WSL-hosted user services available. The task
has no execution-time limit and restarts failures after one minute (up to 999
consecutive attempts). `-NoRegister` only returns the validated task configuration;
it neither starts WSL nor changes Task Scheduler. Distribution names accept only letters, digits, dots, underscores,
and hyphens. Registration is an explicit operator step after runtime adoption.

## Local checks

The watcher and its tests use only Python's standard library:

```sh
PYTHONPATH=scripts python3 -m unittest discover -s tests -v
```

Tests simulate the GitHub/`gh` boundary and cover restart reconciliation, duplicate
prevention, stale observations, latest-push selection, live handoff preservation,
failed-run retries, identity rejection, private atomic state, and workflow
credential/trigger restrictions. They do not contact GitHub or change a running
deployment. Any package-manager commands used for other controller work must use
the Socket Firewall wrapper (`sfw` or its approved wrappers).

The 2026-10-28 test-quality audit removed 107 weak or duplicate tests: 50 client,
26 server, 3 transport, and 28 controller cases. It also removed coupled SQL,
private-cache, and collaborator-call assertions from 44 otherwise useful server
tests. A follow-up independent Sol/Opus review removed three proven duplicates
and refined weak assertions while retaining the important scenarios. The retained
deployment suites contain 219 client, 740 server, 59 Python
transport, 23 Worker, and 242 controller tests. The separate 11-case portable
release suite is retained. Test baselines reflect this explicit curation;
zero-skip source QA, complete worker coverage, account/session admission and live
replacement verification remain required.

The user subsequently requested removing four maintained-APK compatibility and
binary-preservation cases from that retained client inventory. Those cases and
their unused setup were removed; they are not skipped or replaced by mocks.

Tests should exercise public behavior using independent expected outcomes.
Source-substring/AST snapshots, private implementation choreography, internal
mock call counts, and handwritten simulations that mirror the implementation
are poor substitutes. External transport, clock and randomness fixtures remain
useful boundaries. Binary format, ABI, refusal, and unchanged-payload checks are
retained where the generated game artifact itself is the public contract.

## Runtime and reboot

The runner container uses `runner/Dockerfile`, UID1000, a read-only root, dropped
capabilities, no-new-privileges, and a dedicated runner-state volume. Its only
host bindings are read-only IPC and client configuration directories. It has no
Docker socket, source checkout, signing key, or host authentication. Register it
only against this controller repository; never share it with the game repository.

`scripts/install_services.py --config /config/services.json --activate` installs
per-user world guardian, broker, and watcher services from private paths. The service configuration
contains `engine_config`, `broker_config`, `watcher_config`, `python_dependencies`,
and `tool_path`. Enable user lingering so services start when the Linux environment
starts. The guardian retries through Docker outages and validates and starts only
the recorded active world and trusted ingress. It checks every ten seconds,
rechecks release integrity every minute, and yields during deployment. Old release
containers have no automatic restart policy. Recovery preserves the current data
volume and never restores a database snapshot.

Docker Desktop can lose its WSL bind mappings when the Linux environment restarts.
For a stopped, fully validated active container with exact Desktop-translated
mounts, recovery first re-registers its configured bind paths using a disposable
container and the pinned release image. Every helper bind is read-only; the helper
has no network or application data volume and runs only a fixed isolated Python
no-op. Bounded cleanup removes that helper before recovery starts the original
world container. A failed validation or helper operation leaves recovery pending.

On a Windows Docker Desktop host, enable Docker Desktop startup at sign-in and
register the WSL keepalive logon task described above. This recovers the services
after Windows sign-in; it does not provide startup before anyone signs in. An
unattended server needs a Linux host or a separately provisioned boot-time Docker
service. Test service recovery with disposable world containers before activation;
restarting the guardian itself must leave the live world's container untouched.

The world runs only on an internal network. A fixed trusted TCP ingress exposes
loopback ports and forwards only to the active world alias; it has no mounts,
credentials, or application code. External Cloudflare routing stays independent.

The signed APK is available at `/client.apk` after deployment. Existing players
keep their account/session and install an APK upgrade when required by changed
Java or managed helper code. Deployment does not silently claim that an APK was
installed on every device. The local launcher keeps its installed APK checksum
and optional per-install proxy while receiving fresh world/ingress container
pins. Its PowerShell implementation is a separately reviewed private snapshot,
never copied automatically from game source.

## Provisioning order

1. Provision pinned Python dependencies, JDK, Android compiler tools, .NET and
   PowerShell outside tracked files. `scripts/build_sandbox_image.py` verifies a
   dependency tree and builds `runner/client.Dockerfile` without package installs
   or build network. Freeze its immutable image ID in the private client config.
2. Build `runner/Dockerfile` with network disabled using the pinned official
   runner base. `scripts/setup_runner.py --config /config/runner.json` requires
   the private numeric repository identity, immutable image ID, local_root, ipc
   and runner_config paths. Its `approved_collaborator_ids` list permits reviewed
   numeric user IDs with standard write permissions; unexpected collaborators or
   elevated roles are rejected. Leaving the list empty permits only the owner.
   `--verify-only` audits an existing runner without registering another one.
3. Supply `engine.config.example.json` in private configuration. Build/assemble a
   tested initial release; `deploy_engine.py adopt --bootstrap` requires the
   exact current container/image/commit and preserves the existing named volume.
4. Supply broker/watcher/service configurations, install the reviewed private
   launcher snapshot, synchronize Main pins, then activate services. Seed watcher
   deployed_sha with the verified adopted commit to avoid a redundant rollout.
5. Push source master and verify the private workflow, exact active SHA, public
   assets/APK, preserved accounts and local launcher binding.

Changes to controller code require private review and an explicit host update.
A game push never updates host control scripts or the Windows launcher.

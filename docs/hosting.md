# Hosting the world and the deployment pipeline

Everything below is what this installation actually runs today, so an operator can
rebuild it on another machine. Paths use `/home/user0/...` as the current example;
they are all private configuration values, not code constants.

## 1. What runs

| Component | How | Needs |
|---|---|---|
| World (`mhsy-main-world-world-<commit>-<id>`) | Docker container, image built from `server/` (`python:3.14-alpine` base) | 2 GB RAM, 1 CPU, `--pids-limit 256`, read-only root, volume `mhsy-main-world-data`, bind `control/`, `GameData/`, `served/assets/`, certs |
| Ingress (`mhsy-main-world-ingress`) | tiny Python TCP proxy container on its own bridge | 128 MB, publishes `127.0.0.1:19543`/`19544` |
| Public edge (`mhsy-main-edge-public-gateway-1`) | `deploy/cloudflare` compose service | 512 MB, publishes `<lan-ip>:443`, terminates TLS, bridges `/game`, proxies assets, Basic-auths `/client.apk` |
| Admin relay + admin egress (`mhsy-main-world-admin-relay`, `mhsy-main-admin-egress`) | containers, outbound 443 to Cloudflare | 128 MB each, admin API over the private domain |
| Broker (`scripts/broker.py`) | host process (systemd user unit `private-deploy-broker`) | Python 3.12+, Docker CLI, ~200 MB RAM idle |
| Watcher (`scripts/watch_master.py`) | host process (`private-deploy-watch`) | Python 3.12+, GitHub token |
| GitHub runner (`private-deploy-runner`) | Docker container (`ghcr.io/actions/actions-runner`) | labels `self-hosted, Linux, X64, private-deploy`, volume `private-runner-state` |

## 2. Host baseline

- **OS**: Linux x86_64 with systemd. Today: Ubuntu on WSL2; native Linux is simpler (the code carries Docker-Desktop WSL path-translation shims that are only needed there).
- **CPU/RAM**: 4 vCPU / 8 GB is comfortable. Build peaks: client QA containers (4 GB + 2 GB each, `qa_workers` 2) + server QA containers + the world.
- **Disk**: Docker images 18 GB, volumes 2.5 GB, `local/` 89 GB today of which **76 GB is `local/broker` build scratch** (safe to prune). A fresh host needs ~25 GB plus player data.
- **Docker**: Engine with BuildKit, `docker compose` v2. Not Docker Desktop.
- **Python**: 3.12+ on the host for broker/watcher/engine (`cryptography` only; `dnfile`/`dncil`/`Pillow` live inside the pinned QA image).
- **git + ssh** to clone both repositories, `curl`, `openssl`.

## 3. Toolchains and pinned images

The client pipeline mounts four toolchains into its sandbox
(`client-build.private.json → toolchains`):

| Mount | Content |
|---|---|
| `/toolchain/jdk` | JDK 21 (javac/java, `jarsigner`) |
| `/toolchain/dotnet` | .NET SDK 9 (`dotnet`, `csc.dll`) |
| `/toolchain/android` | Android build-tools receipt (`android-35.jar`, `r8`) |
| `/toolchain/pwsh` | PowerShell 7 |

Pinned images that must be present locally (builds run with `--pull=false`):

```
sha256:83e0aa83…   client QA sandbox (python + dnfile/dncil/cryptography/Pillow)
python:3.14-alpine@sha256:f6a589d4…   server base image
python:3.14-slim-trixie               admin images
ghcr.io/actions/actions-runner        self-hosted runner
```

Move them with `docker save`/`docker load` (or push to a private registry the new
host can reach).

## 4. Network

- **Inbound TCP 443** from Cloudflare to the public edge. No UDP. Router forwards 443 to the host; bind the published port to the LAN address when another service owns 443 elsewhere.
- **Outbound 443**: Cloudflare (edge/admin/game), GitHub (runner, repos), `cf` CLI when used.
- **Outbound 22/443** to GitHub for `git` and the runner.
- **Cloudflare side** (already configured, see `deploy/cloudflare/README.md`): proxied A record for the gameplay host, SSL mode **Full**, Basic challenge enforced by the gateway for `/client.apk`, and WAF skip rules for non-browser transports.
- The retired outbound relay needs nothing: no Worker, no Durable Object, no `cloudflared`.
- To retire Cloudflare's proxying entirely (it keeps only the zone's nameservers)
  and front the game with an operator-owned reverse proxy, follow
  [reverse-proxy-handoff.md](reverse-proxy-handoff.md). The same document covers
  moving the admin API off the Worker transport: it is published from the world
  container and served through the same proxy, authenticated only by its admin
  API key (mTLS / IP allowlist remain optional follow-ups).

## 5. Private state and secrets

Never committed; must be re-provisioned or copied with modes intact.

**Credentials and identities**

| Item | Current location |
|---|---|
| APK signing key + certificate | `mhsy-offline-revival/deploy/multiplayer/local/privateworld-signing-{key,cert}.pem` |
| World TLS: `ca.crt`, `server.crt`, `server.key` | `mhsy-offline-revival/deploy/multiplayer/local/certs/` |
| APK download credential (Basic auth for `/client.apk`) | `mhsy-deploy-runner/local/startup-apk-download/credentials.private.json` |
| Broker IPC token | `mhsy-deploy-runner/local/ipc/token` |
| World control secret | `mhsy-deploy-runner/local/control/secret` |
| Source deploy key (git) | `broker.private.json → source_deploy_key` |
| GitHub token for the watcher (actions:write on the control repo) | `watcher.private.json` profile/token file |
| Cloudflare OAuth session for `cf` | `~/.config/cloudflare/config/default.json` |

**Build inputs** (`client-build.private.json → inputs`): base APK, clean29 client
envelope, public CA, `helper` DLL + manifest, `mscorlib/UnityEngine/System/LitJson`,
`md5_4201.bin` template, APK download credential pin.
**Other private trees**: `local/trusted-tooling/client-build` (reviewed compiler +
test harness), `local/build-fixtures` (fixture store), `local/toolchains/pwsh`,
`deploy/multiplayer/local/*` (static asset bases), `work/apk/luapack_extracted/GameData` (14 MB).

**Persistent runtime state**

| Item | What it is |
|---|---|
| Docker volume `mhsy-main-world-data` | **the player save**: `world.sqlite3`, `auth.sqlite3` |
| Docker volume `mhsy-main-admin-state`, `mhsy-main-server-logs` | admin state, durable logs |
| Docker volume `private-runner-state` | GitHub runner registration |
| `local/engine/` | `active.json`, `deployments/`, `served/assets` (176 MB, what clients download) |
| `local/state/` | `desired-master`, `watcher.json`, `active-runtime.json` |
| `local/broker/` | jobs, attempts, builds (76 GB, prunable), `components/` caches |

## 6. Absolute paths to rewrite

| Config | Keys |
|---|---|
| `engine.private.json` | `local_root`, `certificates`, `control`, `game_data`, `data_volume`, `https_port`, `game_port`, `timezone`, `desired_commit_file`, `runtime_registry` |
| `broker.private.json` | `local_root`, `client_config`, `engine_config`, `transport_config`, `registry_config`, `source`, `source_cache`, `token_file`, `socket_path`, `static_assets.path`, `game_data` |
| `registry.private.json` | `main_config`, `distribution_apk`, `fingerprint` — today `/mnt/c/mhsy-local/...` (Windows launcher pins) |
| `watcher.private.json` | `state_file`, `desired_commit_file`, `attempt_bindings` |
| `client-build.private.json` | `toolchains[].path`, `inputs[].path`, `apk_download_credentials.path`, `fixture_store` |
| `deploy/cloudflare/local/public-edge.env` | `PUBLIC_BIND`, `GATEWAY_CERT_DIR`, `APK_CREDENTIAL_FILE`, `INGRESS_*` |
| systemd units | `WorkingDirectory`, `ExecStart` |

`registry.private.json` is the one piece tied to Windows: `sync_registry.py` writes
the launcher pins in `C:\mhsy-local\`. On a Linux-only host either mount that share
(formerly `/mnt/c`) or drop `registry_config` and maintain the launcher pins by hand.

## 7. Migration order

1. Provision OS, Docker, Python, toolchains; `docker load` the pinned images.
2. Clone both repositories; copy the private configs, secrets, tooling snapshot, fixtures. Keep `0600`/`0700` modes.
3. Copy volumes: `docker run --rm -v mhsy-main-world-data:/from -v /tmp/x:/to alpine cp -a /from/. /to/` with the world stopped; same for admin state and logs.
4. Copy `local/engine/` (served assets + `active.json`) and `local/state/`, or rebuild and let the pipeline hand the world over.
5. Rewrite absolute paths (§6). Verify with `python3 scripts/deploy_engine.py status --config local/engine.private.json` — it must report the running release and a healthy world.
6. Start the world unit, then the public edge (`docker compose up -d public-gateway`), then broker and watcher.
7. Re-register the GitHub runner with labels `self-hosted, Linux, X64, private-deploy`; the workflow selects it only by those labels.
8. Move the router's 443 forward to the new host. DNS does not change (Cloudflare terminates).
9. Verify: `/healthz` 200, `/apk-update.json` 200, `/client.apk` 401 without credentials and 200 with, `GET /game` + `Upgrade` 101, and one client login.
10. Keep the old host installed until a real deployment has run end to end, then retire it.

## 8. What stays on Windows

BlueStacks Main/DEV, adb, the DEV shortcuts, and `C:\mhsy-local\main-world.json`
(the launcher pins container ids, so it must be refreshed after the world moves —
`saved` `containers[].id` are per-container). The pipeline's DEV/QA tools
(`dev_tools.py`, `qa_runner.py`, screenshot helpers) also stay next to the emulators.

## 9. Environment pitfall on the current host

This machine resolves the gameplay domain to a **fake IP** (`198.18.5.17`) and
routes through a local proxy. Bulk transfers through that path stall at 16 KB on
roughly half of attempts (the installer download fails intermittently, the origin
itself serves the same file at 76 MB/s over the LAN). A host with ordinary direct
internet does not have this problem — worth checking first on the new machine,
because it also explains the BlueStacks "update available, cannot download".

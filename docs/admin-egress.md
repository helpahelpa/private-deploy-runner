# Fixed-destination admin egress bridge

`scripts/admin_egress.py` is trusted infrastructure, not application snapshot
code. It uses Python 3.11+ stdlib only and imports no project modules. The
implementation does not provision Docker resources or read credentials.

## Security / integration contract

- The **world stays attached only to `private-world-internal`**. The admin
  agent keeps sharing the world's network namespace to reach loopback 9445.
- Only the new bridge joins both `private-world-internal` and a separate
  ordinary Docker bridge (suggested name `private-admin-egress`). Do not
  attach the world to that egress network or change Main/DEV while testing.
- Give the bridge a reserved internal-network IP. `--bind-ip` must be **that
  exact IP**, not the egress IP, a Docker service name, or a wildcard. The
  program rejects unspecified/multicast addresses and will fail startup if
  the address is not local. It cannot infer which Docker network is internal;
  the provisioner must verify the IP/network mapping.
- No `-p`, `-P`, `ports:`, host networking, privileged mode, Docker socket,
  credential mount, application snapshot mount, or host directory mount.
  Ensure the egress network supplies the default route; on recent Docker use
  the egress attachment's `gw-priority=1` and internal attachment's default 0.
- Configure exactly one canonical lowercase ASCII admin hostname, after
  inspecting the dedicated Cloudflare admin route. Do not use the gameplay
  hostname or a wildcard. Matching is byte-exact: uppercase, trailing dots,
  IDNA aliases, IP ATYPs, domain-encoded IPs, other names/ports, BIND and UDP
  ASSOCIATE are rejected **before any DNS lookup or upstream connection**.
- The client must send SOCKS5 **domain ATYP** for that name and port **443**
  (SOCKS5 remote-DNS / `socks5h` semantics). A locally resolved IP fails closed.
- Optionally configure one fixed existing **no-auth SOCKS5** upstream, using
  `--upstream-host` and `--upstream-port` together. This performs the same
  strict RFC 1928 exchange used by `Relay.open_upstream`, but is standalone.
  It never falls back to direct connectivity on proxy failure. Omit both
  flags for direct DNS/TCP to the fixed hostname:443. A numeric proxy address
  avoids local DNS dependency; derive the existing router endpoint privately
  in the provisioner if needed, never print its address or surrounding config.
- No secrets are needed by the bridge. No proxy credentials, API/admin
  credentials, tokens, environment files, or authentication arguments are
  supported. TLS verification and admin authentication remain end-to-end in
  the admin agent. The bridge forwards opaque bytes; it does not terminate
  TLS, inspect HTTP, expose an HTTP control API, or enforce a particular URL.
- There is no runtime request/error/body/endpoint logging. Startup OS failures
  exit 1 without printing exception text; invalid CLI configuration exits 2.
  Avoid Docker inspection output containing private configuration in CI logs.

## Fixed runtime command (provisioner supplies values)

For an image whose entrypoint is the Python script below:

```sh
--bind-ip "$INTERNAL_BRIDGE_IP" --port 1080 \
--allowed-host "$DEDICATED_ADMIN_HOST" \
--upstream-host "$FIXED_SOCKS_HOST" --upstream-port "$FIXED_SOCKS_PORT"
```

The hostname and fixed proxy endpoint are configuration, not secrets. Do not
put raw credentials on a command line. The parent owns selecting those values,
network provisioning, deployment, and runtime configuration changes.

Defaults: 16 admitted sessions (configurable 8–256), 10 seconds total handshake
including upstream connect/negotiation, 120 seconds session-wide inactivity,
10 seconds per write/drain, 1 second per socket close. Each timeout accepts a
finite positive value up to 3600 seconds. Excess connections close immediately
without spawning waiting session tasks. TCP half-close preserves the reverse
stream until completion or timeout. SIGTERM/SIGINT cancel sessions and close
both sockets. Port zero is available only to the imported test API, not CLI.

## Minimal image advice (parent builds and pins; not deployed here)

Use a build context containing **only** the reviewed script and this recipe;
no repository snapshot, private config, package installation, or network build
steps. The locally available base tested below is pinned by digest:

```dockerfile
FROM python:3.14-slim-trixie@sha256:82abc9f53600280b0757126f83c5a7d47088592d2acb6b4c0b9e97f76865508c
COPY --chmod=0444 admin_egress.py /app/admin_egress.py
USER 65532:65532
ENTRYPOINT ["python", "-I", "-B", "/app/admin_egress.py"]
```

Build with networking disabled and no base pull after verifying the pinned
base is present. Record the resulting **image ID** and invoke that ID with
`--pull=never`, not a mutable tag. This recipe is packaging advice; the child
only tested the source in the pinned base, not a newly built/deployed image.
The parent may choose another reviewed pinned stdlib Python image and rerun
the same suite.

Recommended runtime constraints: `--read-only --user=65532:65532
--cap-drop=ALL --security-opt=no-new-privileges:true --pids-limit=64
--memory=128m --cpus=1 --log-driver=none`, no writable paths or host mounts.
The script needs neither a shell nor packages nor persistent storage. Attach
both networks at creation (or before start) and bind only the internal IP;
do not briefly start a wildcard listener on the ordinary bridge. Use a
restart policy appropriate to the parent's supervised service. No healthcheck
should send credentials or create an HTTP/control listener.

## Offline socket tests — tested exact container command

From the deploy-runner repository root:

```sh
docker run --rm --pull=never --network=none --read-only \
  --user=65532:65532 --cap-drop=ALL \
  --security-opt=no-new-privileges:true --pids-limit=64 --memory=128m --cpus=1 \
  --mount="type=bind,src=$PWD/scripts/admin_egress.py,dst=/source/scripts/admin_egress.py,readonly" \
  --mount="type=bind,src=$PWD/tests/test_admin_egress.py,dst=/source/tests/test_admin_egress.py,readonly" \
  sha256:82abc9f53600280b0757126f83c5a7d47088592d2acb6b4c0b9e97f76865508c \
  python -I -B -W error -m unittest discover \
    -s /source/tests -p test_admin_egress.py -v
```

Only the two public files are mounted for tests. All sockets use loopback,
including a real local no-auth SOCKS fixture; no DNS or Internet is needed.
Coverage includes exact destination forwarding, pre-upstream rejection,
malformed/truncated input and upstream replies, eight simultaneous sessions
and slot reuse, handshake/idle/write bounds, one-way activity, half-close,
shutdown/cancellation, configuration validation, and a real CLI subprocess
that forwards bytes, exits on SIGTERM, and emits no stdout/stderr.

The suite does **not** assert live Cloudflare routing, credentials, TLS origin
identity, Docker network isolation/default-route selection, or production
router connectivity. Those remain the parent's separate deployment gates.

Local alternative:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -W error -m unittest discover \
  -s tests -p test_admin_egress.py -v
```

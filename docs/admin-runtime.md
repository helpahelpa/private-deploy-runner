# Optional admin runtime

The trusted engine accepts an optional `admin_runtime` object in private runtime
configuration. Omitting it preserves the original world configuration. Enabling
it requires an already reviewed admin-capable server release and separately
provisioned state/log volumes, relay image, private files and outbound path.

Required fields are `state_volume`, `log_volume`, `environment`, `relay_image`,
`edge_origin`, `relay_secret_file` and `routes_file`. The relay image must be an
immutable `sha256:` image ID already present locally. Paths resolve relative to
the private engine configuration. Secret files must have no group/other access.
`origin_server_name`, if supplied, must be `localhost`.

The engine supplies fixed admin flags for `/admin/admin.sqlite3`, the configured
environment, `/app/server/logs` and loopback TLS port 9445. The state and log
volumes must differ from each other and the world volume. Logs replace the old
volatile log tmpfs; `/tmp` remains temporary. The relay has only read-only secret,
route-policy and origin-CA file mounts. It has no host ports, signing keys or data
volume. No admin listener is exposed through the gameplay ingress.

The world retains its single internal Docker network. `upstream_proxy` may select
one credential-free SOCKS5 bridge reachable on that internal network. Production
uses a separately supervised restricted egress bridge; see [admin-egress.md](admin-egress.md).
`egress_identity_file` selects its private identity receipt, containing the name,
image ID, exact command/healthcheck, internal/outbound networks, internal bind IP,
alias and port. The engine verifies that receipt and the running container's
isolation, destination policy and health before activation and during supervision.
It never creates or restarts this parent-managed bridge. Relay secrets, route
files and the egress identity receipt are frozen by checksum; reviewed changes
require reloading the private configuration.

The engine owns the admin relay lifecycle. Each replacement gets a newly pinned
relay sharing that exact world's network namespace. A stopped relay can be
restarted without replacing its world. Restarting a world requires recreating
its relay even when the world container ID is unchanged: Linux can replace the
network namespace independently of that ID. Health verifies TLS and unauthenticated
admission **from the relay namespace**, not merely from the world itself.
The active registry records the relay identity, which the world supervisor checks.

For the first rollout, the existing registry's lack of an admin marker explicitly
means legacy configuration. Its current world remains validated with the old
mounts and flags. A new ordinary promotion requires a receipt containing the admin
production sources. Automatic code rollback restores the predecessor's runtime
selection; an explicit rollback to a pre-admin receipt omits unsupported admin
flags. State/log volumes remain intact and are never restored from an older copy.
Admin access is unavailable while legacy code runs. Deployment failure remains a
failure even when code recovery succeeds.

These local runtime checks do not attest live Cloudflare routing or API-key
permissions. A separately approved end-to-end check must cover the dedicated
Worker, restricted egress, real relay, HTTPS API, CLI and log download. Coordinate
controller reloads with the deployment queue; never restart it during handoff.

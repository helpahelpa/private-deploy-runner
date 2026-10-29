# Handoff: exit Cloudflare (DNS only) and front everything with a reverse proxy

Audience: the agent/operator who will stand up the proxy and retire Cloudflare's
proxy/Workers. Target end state:

- **Cloudflare keeps only the zone's nameservers** — no proxying, no Workers, no
  WAF, no Origin Pulls, no `100::` placeholder records.
- **One operator-owned reverse proxy** terminates TLS for the game hostname and
  forwards to the origin machine.
- **The admin API is served through the same reverse proxy**, authenticated only
  by its per-admin API key (explicit human decision for now). The
  Worker/Durable-Object transport and its loopback-only assumptions are retired.

Read §2 before choosing a design: those points are enforced by the shipped
Android client.

---

## 1. Target picture

```
phone / BlueStacks                     admin CLI (mhsy_admin.py)
      │ TLS (public CA)                       │ TLS (public CA) + API key
      ▼                                       ▼
reverse proxy ──► origin :443            reverse proxy ──► origin :<admin port>
(VPS, public IP)   public edge container  (same proxy)     admin API in the world
```

Two hostnames, one proxy, one certificate (SAN with both names):
`raidshadowlegendstipsandtricks.kdns.fr` (game) and
`admin.raidshadowlegendstipsandtricks.kdns.fr` (admin).

Cloudflare resolves `raidshadowlegendstipsandtricks.kdns.fr` to the proxy and
holds the zone's NS records. Nothing else.

## 2. Client contract (non-negotiable)

The hostname is compiled into every installed APK — `assets_origin` and
`gameplay_url` are `https://raidshadowlegendstipsandtricks.kdns.fr` and
`wss://raidshadowlegendstipsandtricks.kdns.fr/game`. **Do not change the hostname.**

| Requirement | Why |
|---|---|
| TLS on 443 with a **publicly trusted** certificate | the client validates against the platform trust store; the origin's own certificate is project-CA with `CN=localhost` and can never be shown to clients |
| Pass `Authorization` through untouched | `/client.apk` is protected by **Basic auth at the origin** (401 + `WWW-Authenticate: Basic realm="APK download"`) |
| No content transformation on `/client.apk` | the client requires `Content-Length == size` from `apk-update.json` (**170214271** today) and rejects `Content-Encoding` other than `identity`: no gzip/brotli, no chunked re-encoding |
| Stream, do not buffer | 170 MB installer, and the client has a **15 s read timeout per read**; any stall aborts the download |
| WebSocket upgrade on `/game`, long-lived | preserve `Upgrade`/`Connection`, idle ≥ 1800 s, no buffering |
| Never cache authenticated responses | if caching is enabled at all, key on `Authorization` and never store a 401 |
| Public paths stay public | `/healthz`, `/apk-update.json`, `/Android_*/UpdateRoot/*`, `/Other/dev.txt`, `/ForceUpdateAddress/*` |

Methods are `GET`/`HEAD`; no request bodies.

## 3. What the origin exposes

One listener only: the public edge container
(`mhsy-main-edge-public-gateway-1`, published on `<origin-lan-ip>:443`).

| Path | Behaviour |
|---|---|
| `/game` | 101 Switching Protocols → world game port |
| `/client.apk` | 401 without credentials, 200 + 170 MB with them |
| `/apk-update.json`, `/Other/dev.txt`, `/Android_90/UpdateRoot/...`, `/ForceUpdateAddress/...` | 200 (small) |
| `/healthz` | 200 `ok` |
| other | 404 |

Loopback-only (must stay unexposed): world 9443/9444 via ingress 19543/19544,
DEV stack 19443/19444, admin API 9445, broker socket/token, GitHub runner.
The legacy Main server on `0.0.0.0:9001` is LAN-only and unrelated.

## 4. Reach the origin

- **A. Direct** — upstream `https://<origin-public-ip>:443`. The router already
  forwards TCP 443, so this works today.
- **B. Tunnel** — WireGuard/Tailscale between proxy and origin, upstream
  `https://<tunnel-ip>:443`. Required if the origin has no routable address, and
  preferred if you do not want the origin reachable at its own IP.
  Cloudflare Tunnel is not an option: this network only permits outbound 443 and
  the tunnel needs 7844.

Upstream TLS is always **verification disabled** (self-signed, `CN=localhost`).

## 5. Reference implementation (Caddy)

```caddyfile
raidshadowlegendstipsandtricks.kdns.fr {
    encode off                                  # never compress: APK length/encoding
    @apk path /client.apk
    header @apk Cache-Control "no-store, no-transform"

    reverse_proxy https://<ORIGIN>:443 {
        transport http {
            tls_insecure_skip_verify            # origin cert is private-CA
            read_timeout 35m
            write_timeout 35m
        }
        flush_interval -1                       # stream, never buffer
    }
}
```

nginx equivalent (key directives): `gzip off;` `proxy_ssl_verify off;`
`proxy_buffering off;` `proxy_request_buffering off;` `proxy_read_timeout 1800s;`
`proxy_send_timeout 1800s;` `proxy_http_version 1.1;` plus
`proxy_set_header Upgrade $http_upgrade; proxy_set_header Connection $connection_upgrade;`
and `proxy_set_header Authorization $http_authorization;`.

Certificates: the zone stays at Cloudflare, so **DNS-01 with a Cloudflare API
token** (`Zone:DNS:Edit`) is the simplest; HTTP-01 on port 80 works after the
record points at the proxy.

## 6. Admin: move off the Worker transport

Today the admin API binds **loopback only inside the world container**
(`admin_api.py` refuses any other host on purpose) and is reached by an
outbound-443 **Cloudflare Worker + Durable Object** through
`mhsy-main-world-admin-relay` (agent) and `mhsy-main-admin-egress` (a SOCKS shim
allowlisting only `admin.raid…`). The admin hostname is a Worker custom domain
backed by an `AAAA 100::` placeholder record. All of that depends on Cloudflare
proxying and stops working when the zone becomes DNS-only.

**Chosen design:** the reverse proxy fronts `admin.raid…` and forwards to the
admin API on the origin. Authentication is the per-admin API key (no mTLS, no IP
allowlist for now — explicit human decision). Consequences to keep in mind:

- The admin API becomes publicly reachable for the first time. Its surface is
  bounded by design (REST only: no shell, SQL, files or backup/restore), and every
  request must present an admin API key.
- Use a long random key, rotate it, and add proxy-side rate limiting on that
  hostname. An IP allowlist or mTLS remains the cheapest upgrade if this ever
  needs tightening.

### Origin-side prerequisites

Keep the loopback invariant inside the container; publish it instead.

1. **Publish the admin port from the world container** on an address the proxy can
   reach (the tunnel address under §4 B, or the LAN/public address under §4 A).
   This is a small change in `scripts/deploy_engine.py → Engine.start()`: when admin
   is enabled, add `--publish <admin-publish-address>:<admin-public-port>:9445`
   beside the existing ingress publishes. Suggested config keys:
   `admin_publish_address` (default `127.0.0.1`) and `admin_public_port`
   (default `9445`).
2. Ship that engine change through the normal pipeline (one release, one handoff
   restart) **before** flipping DNS.
3. **Do not** relax `admin_api.py`'s loopback check — publishing keeps the API
   itself bound to loopback and puts the exposure decision in one place.
4. Firewall the published port to the proxy's address only (tunnel or proxy IP).

### Proxy configuration

```caddyfile
admin.raidshadowlegendstipsandtricks.kdns.fr {
    encode off
    rate_limit {                       # optional but recommended
        zone admin { key {remote_host} events 60 window 1m }
    }
    reverse_proxy https://<ORIGIN>:<admin-public-port> {
        transport http {
            tls_insecure_skip_verify   # admin API presents the project-CA certificate
            read_timeout 5m
        }
        flush_interval -1
    }
}
```

The `Authorization` header (the admin API key) must pass through untouched; the
proxy adds no auth of its own in this iteration.

### Retire

- Delete the `admin.raid…` Worker custom domain and its `AAAA 100::` record.
- Delete the Worker script `mhsy-main-admin-outbound443`.
- Stop and remove `mhsy-main-world-admin-relay` and `mhsy-main-admin-egress`
  (and their compose/systemd units) once the proxy path is verified.

## 7. Cutover order

1. Recruit the proxy in parallel with Cloudflare: it must answer correctly for
   the hostname before DNS changes (test with `curl --resolve`).
2. Lower the game record's TTL to 60 s, wait one TTL.
3. Flip the game record: `A → <proxy public IP>`, **proxying off** (DNS only).
4. Verify the admin path through the proxy (the origin publish from §6 must
   already be deployed).
5. Verify everything in §8.
6. Only then retire Cloudflare's proxy features (§9).

## 8. Verification (run from outside the origin's LAN)

```sh
H=raidshadowlegendstipsandtricks.kdns.fr

openssl s_client -connect $H:443 -servername $H -verify_return_error </dev/null 2>&1 | grep "Verify return code"
curl -s https://$H/apk-update.json | jq '{version_code, size, sha256, url}'   # size 170214271, url /client.apk
curl -sI https://$H/client.apk | grep -iE "HTTP/|www-authenticate"           # 401 + Basic realm
curl -s -u "$APK_USER:$APK_PASS" -D - -o /tmp/client.apk https://$H/client.apk \
  | grep -iE "HTTP/|content-length|content-encoding"                          # 200, 170214271, NO content-encoding
sha256sum /tmp/client.apk                                                    # equals metadata sha256
curl -s -o /dev/null -w '%{http_code}\n' https://$H/healthz                  # 200
curl -s -o /dev/null -w '%{http_code}\n' https://$H/Android_90/UpdateRoot/Version/Version.bytes
# WebSocket: GET /game + Upgrade: websocket -> 101, hold 5 minutes
```

```sh
A=admin.raidshadowlegendstipsandtricks.kdns.fr
openssl s_client -connect $A:443 -servername $A -verify_return_error </dev/null 2>&1 | grep "Verify return code"
curl -s -o /dev/null -w '%{http_code}\n' https://$A/api/v1/whoami            # 401 without a key
curl -s -H "Authorization: Bearer $ADMIN_KEY" https://$A/api/v1/whoami       # 200 + identity
mhsy_admin whoami --endpoint https://$A                                       # CLI works
```

Then: launch the real client on a phone over mobile data, log in, enter the city,
run an update check (nothing to download). Confirm **no `cf-ray`** header appears
anywhere, and that both hostnames resolve to the proxy, not to Cloudflare.

## 9. Retiring Cloudflare's proxy features

Order matters; do this after §8 passes.

1. DNS: every remaining record must be **DNS only** (grey cloud). Keep the zone
   and its NS records — that is all Cloudflare will do.
2. Delete the remaining Worker custom domain for `admin.raid…`
   (`mhsy-main-admin-outbound443`).
3. Delete the Worker scripts: `mhsy-private-relay`, `mhsy-main-admin-outbound443`
   (both reproducible from `deploy/cloudflare/*.mjs`).
   Both are reproducible from this repository (`deploy/cloudflare/*.mjs`), so they
   remain a rollback if the files are kept.
4. Delete the two WAF custom rules in the ruleset "Scoped non-browser API
   exceptions" (they skipped BIC/security level/WAF for the two hostnames; inert
   once nothing is proxied, but remove them so the zone is clean).
5. Delete the `AAAA 100::` placeholder record for the admin hostname if it survives.
6. Keep the Cloudflare API token (used for DNS-01 and nothing else).

Known trap: a `proxied=true` record on a hostname whose Worker custom domain you
just deleted returns Cloudflare errors instead of reaching your proxy. Flip
proxying off **before** deleting the custom domain.

## 10. Pitfalls

- **15 s client read timeout** — buffering or stalling proxies break the installer.
- **Compression / chunked re-encoding** — breaks the exact `Content-Length` check.
- **Caching + Basic auth** — would leak the APK to unauthenticated clients.
- **WebSocket timeouts** — 60 s defaults kill gameplay; use ≥ 1800 s.
- **Origin exposure** — with §4 A the origin is still reachable at its own IP:443;
  scope the origin firewall to the proxy (and drop the router forward if you use
  a tunnel).
- **Private-CA origin cert** — never present it to clients; terminate at the proxy.
- **Hostname is baked into APKs** — a rename requires shipping a new APK first.

## 11. Rollback

Re-enable proxying on the game record and recreate its Worker custom domain
(the Worker script is in `deploy/cloudflare/`), then restore the relay containers
with `docker compose --profile relay up -d`. The origin edge and its Basic auth
never change, so no origin work is needed in either direction.

## 12. Decisions the human must make

1. Proxy host (VPS/IP) and whether it reaches the origin directly (§4 A) or over
   a tunnel (§4 B).
2. ACME method: DNS-01 with a scoped Cloudflare token, or HTTP-01.
3. Admin: decided — proxied with API-key auth. Open follow-up: whether to add a
   proxy-side IP allowlist or mTLS later.

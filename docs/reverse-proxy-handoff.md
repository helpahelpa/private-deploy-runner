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

**Status at handoff (2026-10-29):** Cloudflare is now DNS only. Both
`raid…` and `admin.raid…` are grey-cloud `A` records pointing at the proxy
(`135.106.193.31`, TTL 60); the two Worker scripts, both Worker custom domains,
the WAF skip rules and the `AAAA 100::` placeholder are deleted. The game hostname
verifies end to end through the proxy; **the admin hostname still needs its site
block on the proxy** (§6).

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

**The tunnel path is live and is now the only path (2026-10-29).** No new port is
published by Docker — Docker Desktop will not publish a second host IP for one
container. Instead `tailscaled` on the origin host forwards raw TCP to the edge
listener, on the same pattern as the host's other `serve --tcp` forwards:

```sh
# on the origin host (tailnet 100.96.251.76)
tailscale serve --bg --tcp=10443 tcp://127.0.0.1:443
```

Proxy upstream: **`https://100.96.251.76:10443`**, unchanged `tls_insecure_skip_verify`
(raw TCP, so the origin's project-CA cert is what the proxy sees). Port 10443
because tailnet 443 on that host is already owned by `tailscale serve` (operator
dashboard).

Cutover done: the edge is published on **loopback only** (`PUBLIC_BIND=127.0.0.1`),
so nothing listens on the LAN address or the public IP, and the router's TCP 443
forward is retired (§4 A no longer exists). If the forward rule is still present
on the router it is inert — delete it so a future LAN bind cannot re-expose the
edge. Verified after the cutover: `/healthz` 200, `/game` 101 held idle 70 s,
assets 200, `/client.apk` 401 without credentials and 200 with them and no
`content-encoding`, the full 170 MB APK at ~54 MB/s with a sha256 matching
`apk-update.json`, `admin.raid…` 401, no `cf-ray`, and no listener on
`192.168.1.104:443` or the public IP.

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

## 6. Admin: served by the origin gateway, one site block left on the proxy

The admin API used to sit behind a Worker custom domain and an outbound relay
agent. That is retired. The origin now carries the admin route itself:

```
admin.raid…  ──►  proxy :443  ──►  origin :443 (public edge gateway)
                                        │  Host: admin.raid… → admin upstream
                                        ▼
                                   ingress :9445 ──► world 0.0.0.0:9445
                                   (admin API, loopback-bound by default,
                                    bound to the container network only when
                                    the reviewed publication is configured)
```

Origin-side pieces already in place:

- `engine.private.json`: `admin_public_port: 9445` makes the deployment pass
  `--admin-bind=0.0.0.0` to the world, so the admin API listens on the container
  network (never on a host interface; nothing is published).
- the ingress forwards `9445` to the world (its `PROXY_PROGRAM` binds 9443, 9444
  and 9445 internally);
- the public edge gateway is started with
  `--admin-host=admin.raidshadowlegendstipsandtricks.kdns.fr --admin-destination=mhsy-main-world-ingress:9445`
  and forwards any request for that host verbatim, including the admin API key.

**Remaining step on the proxy host** — add the second site. No new port, no
router change:

```caddyfile
admin.raidshadowlegendstipsandtricks.kdns.fr {
    encode off
    reverse_proxy https://<ORIGIN>:443 {
        transport http {
            tls_insecure_skip_verify      # origin edge presents the project-CA cert
            read_timeout 5m
        }
        flush_interval -1
    }
}
```

Then verify (the certificate for the admin name is issued by the same ACME run):

```sh
A=admin.raidshadowlegendstipsandtricks.kdns.fr
curl -s -o /dev/null -w '%{http_code}\n' https://$A/api/v1/whoami                 # 401
curl -s -H "Authorization: Bearer $ADMIN_KEY" https://$A/api/v1/whoami            # 200
mhsy_admin whoami --endpoint https://$A
```

Until that block exists the admin hostname resolves but its TLS handshake fails
(no certificate for that SNI). The admin API is authenticated only by its per-admin
API key — the operator's explicit choice for now; an IP allowlist or mTLS remains
the cheap upgrade.

## 7. Cutover order

Done: the game record was flipped to `A → proxy`, proxying off, verified, and
Cloudflare's proxy features retired (§9). Remaining: the admin site block in §6,
then the admin checks in §8.

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

## 9. Retiring Cloudflare's proxy features — done

Recorded for reference; this is the completed state.

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
- **Origin exposure** — §4 B is in use: the edge is published on `127.0.0.1` only
  and nothing answers on the origin's LAN or public IP. Do not republish the
  edge on a LAN or public interface, and keep the router's 443 forward deleted;
  the proxy is the only entry point.
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

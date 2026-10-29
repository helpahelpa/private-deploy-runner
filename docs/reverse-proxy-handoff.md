# Handoff: front the game origin with an operator-controlled reverse proxy

Audience: the agent/operator who will stand up the proxy. This replaces
Cloudflare as the public entry point for the **game** hostname. It does not
change the client, the origin server code, or the APK.

Read §2 before choosing a design: several of those points are hard requirements
enforced by the shipped Android client, not preferences.

---

## 1. Target picture

```
phone / BlueStacks
      │  TLS  (publicly trusted certificate for raidshadowlegendstipsandtricks.kdns.fr)
      ▼
reverse proxy  ──►  origin host :443  (the existing public edge container)
(VPS w/ public IP)      TLS to origin with verification DISABLED
```

Cloudflare is removed from the game path. `admin.raidshadowlegendstipsandtricks.kdns.fr`
is *separate* (its admin transport is an outbound-443 Worker path); leave it on
Cloudflare unless a later task moves it too.

## 2. Client contract (non-negotiable)

The hostname is compiled into the installed APKs — `assets_origin` and
`gameplay_url` are `https://raidshadowlegendstipsandtricks.kdns.fr` and
`wss://raidshadowlegendstipsandtricks.kdns.fr/game`. **Do not change the
hostname**, or every installed client breaks.

| Requirement | Why |
|---|---|
| TLS on 443 with a **publicly trusted** certificate for that hostname | `Tls.systemContext()` validates against the platform trust store. The origin's own certificate is signed by the project CA with `CN=localhost`, so it can never be presented to clients |
| Pass `Authorization` through untouched | `/client.apk` is protected by **Basic auth enforced at the origin** (401 + `WWW-Authenticate: Basic realm="APK download"`). The proxy must not terminate, strip or "handle" it |
| No content transformation on `/client.apk` | the client requires `Content-Length` to equal `size` from `apk-update.json` (**170214271** today) and rejects `Content-Encoding` other than `identity`. So: no gzip/brotli, no chunked re-encoding, no size rewriting |
| Stream, do not buffer, large bodies | 170 MB installer; the client has a **15-second read timeout per read**, so any proxy stall aborts the download. Disable response buffering for `/client.apk` |
| WebSocket upgrade on `/game`, long-lived | gameplay runs over WSS on that path; upstream idle budget is 1800 s. Preserve `Upgrade`/`Connection`; set read/idle timeouts ≥ 1800 s; binary frames, no buffering |
| Do not cache authenticated responses | if caching is enabled, key on `Authorization` and never store the 401 |
| Public paths stay public | `/healthz`, `/apk-update.json`, `/Android_*/UpdateRoot/*`, `/Other/dev.txt`, `/ForceUpdateAddress/*` |

Request methods are `GET`/`HEAD` only, no request bodies.

## 3. What to proxy (and what not)

The origin exposes exactly one listener, the public edge container
(`mhsy-main-edge-public-gateway-1`, published on `<origin-lan-ip>:443`):

| Path | Upstream behaviour |
|---|---|
| `/game` | 101 Switching Protocols, bridged to the world game port |
| `/client.apk` | 401 without Basic credentials, 200 + 170 MB with them |
| `/apk-update.json`, `/Other/dev.txt`, `/Android_90/UpdateRoot/...`, `/ForceUpdateAddress/...` | 200, small bodies |
| `/healthz` | 200 `ok` |
| anything else | 404 |

Everything else on the origin host is loopback-only (world 9443/9444 via ingress
19543/19544, DEV stack 19443/19444, broker socket, runner) and must **not** be
exposed. The legacy Main server on `0.0.0.0:9001` is LAN-only and unrelated.

## 4. Reach the origin

Two supported options:

- **A. Direct (preferred if the origin has a routable address).** Upstream `https://<origin-public-ip>:443`.
  The router currently forwards TCP 443 to the origin host, so this works today.
- **B. Tunnel (if the origin is behind CGNAT or you refuse to expose it).** WireGuard
  (or Tailscale) between the proxy host and the origin host; upstream
  `https://<tunnel-ip>:443`. Cloudflare Tunnel is **not** an option here: this
  network only permits outbound 443 and the tunnel needs 7844.

Upstream TLS always uses **verification disabled** (self-signed, `CN=localhost`);
the proxy is the only party that must present a valid public certificate.

## 5. Reference implementation (Caddy)

Install Caddy 2 on the proxy host, DNS A record already pointing at it, then:

```caddyfile
raidshadowlegendstipsandtricks.kdns.fr {
    encode off                                  # never compress: APK size/content-length
    @apk path /client.apk
    header @apk Cache-Control "no-store, no-transform"

    reverse_proxy https://<ORIGIN>:443 {
        transport http {
            tls_insecure_skip_verify            # origin cert is private-CA/CN=localhost
            read_timeout 35m                    # installer + long WSS
            write_timeout 35m
        }
        flush_interval -1                       # stream, never buffer
        # Basic auth and Content-Length pass through untouched
    }
}
```

nginx alternative (key directives only):

```nginx
server {
  listen 443 ssl http2;
  server_name raidshadowlegendstipsandtricks.kdns.fr;
  ssl_certificate     /etc/letsencrypt/live/.../fullchain.pem;
  ssl_certificate_key /etc/letsencrypt/live/.../privkey.pem;

  gzip off;

  location / {
    proxy_pass https://<ORIGIN>:443;
    proxy_ssl_verify off;
    proxy_set_header Host $host;
    proxy_set_header Authorization $http_authorization;   # keep Basic for /client.apk
    proxy_http_version 1.1;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection $connection_upgrade;
    proxy_buffering off;
    proxy_request_buffering off;
    proxy_read_timeout 1800s;
    proxy_send_timeout 1800s;
  }
}
map $http_upgrade $connection_upgrade { default upgrade; '' close; }
```

Certificates: the hostname's DNS is in Cloudflare, so either use **DNS-01** with
a Cloudflare API token scoped to `Zone:DNS:Edit`, or point the record at the proxy
first and use **HTTP-01** on port 80.

## 6. DNS cutover

1. Lower the record's TTL to 60 s and wait one TTL.
2. Change the `A` record for `raidshadowlegendstipsandtricks.kdns.fr` from the
   proxied (orange-cloud) entry to the **proxy's public IP with proxying OFF**
   (DNS only). Cloudflare then serves DNS only.
3. Keep `admin.raidshadowlegendstipsandtricks.kdns.fr` untouched.
4. Verify (below) before removing anything else. Do **not** delete the Cloudflare
   Worker or its route until the new path has run for a day — it is the rollback.

## 7. Origin-side changes

- Keep the public edge container running; it is the upstream.
- Once the proxy is verified, close the router's inbound 443 forward if the proxy
  reaches the origin over a tunnel (option B). With option A the forward stays,
  which means the origin remains directly reachable — see §9.
- Nothing in the game repo, APK, or deployment pipeline changes.

## 8. Verification (run from a network outside the origin's LAN)

```sh
H=raidshadowlegendstipsandtricks.kdns.fr

# 1. Certificate is publicly trusted and matches the hostname
openssl s_client -connect $H:443 -servername $H -verify_return_error </dev/null 2>&1 | grep -E "Verify return code|subject="

# 2. Public metadata matches the published installer
curl -s https://$H/apk-update.json | jq '{version_code, size, sha256, url}'
#   expect size 170214271 and url "/client.apk"

# 3. Challenge is enforced at the origin and preserved by the proxy
curl -sI https://$H/client.apk | grep -iE "HTTP/|www-authenticate"     # 401 + Basic realm

# 4. Authenticated download: exact length, no encoding, complete body
curl -s -u "$APK_USER:$APK_PASS" -D - -o /tmp/client.apk https://$H/client.apk \
  | grep -iE "HTTP/|content-length|content-encoding"
#   expect 200, content-length: 170214271, NO content-encoding
sha256sum /tmp/client.apk   # must equal apk-update.json sha256

# 5. Game socket upgrades and stays up
#   (any WS client) GET /game with Upgrade: websocket -> 101, then hold 5 minutes

# 6. Assets
curl -s -o /dev/null -w '%{http_code}\n' https://$H/Android_90/UpdateRoot/Version/Version.bytes
curl -s -o /dev/null -w '%{http_code}\n' https://$H/Other/dev.txt
```

Then in the real client: launch the game on a phone over mobile data, log in, enter
the city, and run one update check (it must offer no update and download nothing).

The origin's own Basic credential lives only on the origin host
(`local/startup-apk-download/credentials.private.json`); the proxy does not need it.

## 9. Known pitfalls (learned the hard way)

- **15-second client read timeout** — a proxy that buffers or stalls breaks the
  installer. Stream everything on `/client.apk`.
- **Compression** changes `Content-Length` or adds `Content-Encoding`; the client
  rejects both. `encode off` / `gzip off` is mandatory.
- **Chunked re-encoding** also drops `Content-Length`; do not let the proxy
  re-chunk a body that upstream sent with a length.
- **Caching + Basic auth**: if you enable any cache, key on `Authorization` and
  never cache 401 — otherwise the APK leaks to unauthenticated clients.
- **WebSocket timeouts**: defaults of 60 s kill gameplay. Raise idle/read to ≥ 1800 s.
- **Direct origin exposure**: with option A the origin stays reachable at its own
  IP:443, bypassing the proxy. Scope the origin firewall to the proxy's IP (and
  Cloudflare's ranges if you keep Cloudflare) so only the proxy reaches it.
- **Do not change the hostname**; the APK has it baked in. A rename requires
  shipping a new APK first.

## 10. Rollback

Re-point the DNS record back to Cloudflare (proxied) and restore the previous
router forward if it was changed. The origin edge, Cloudflare Worker route, and
WAF skip rules are left in place for exactly this reason; nothing on the origin
needs to be re-created.

## 11. Decisions the human must make

1. Which proxy host (VPS provider/IP) and whether it reaches the origin directly
   (§4 A) or over a tunnel (§4 B).
2. ACME method: DNS-01 with a Cloudflare API token, or HTTP-01 after DNS cutover.
3. Whether the origin firewall becomes proxy-only, Cloudflare-only, or both.
4. Whether `admin.raid…` also moves off Cloudflare later (out of scope here).

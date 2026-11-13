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

## Express (`dummy-projects/vulnerable/ssrf/express-vite-bff/server/index.js`), runs with `node server/index.js` (port 3001)
| line | curl | why it works |
|---|---|---|
| 12 | `curl 'localhost:3001/api/proxy?url=http://127.0.0.1:9999/secret'` | `axios.get(req.query.url)`: whole URL is attacker-chosen; response body is returned, so data is exfiltrated |
| 18 | `curl -XPOST localhost:3001/api/webhook-test -H 'content-type: application/json' -d '{"callbackUrl":"http://127.0.0.1:9999/hit"}'` | blind SSRF: only the status code comes back, but the internal request still happens (can hit state-changing internal endpoints) |
| 23 | `curl 'localhost:3001/api/avatar?u=http://127.0.0.1:9999/secret'` | `http.get(req.query.u)` piped to the response |
| 27 | `curl 'localhost:3001/api/fetch/http%3A%2F%2F127.0.0.1%3A9999%2Fsecret'` | path param is URL-encoded full URL passed to `got` |
| 34 | `curl localhost:3001/api/tenant-config -H 'x-tenant-host: 127.0.0.1:9998'` | header becomes the HOST of `https://${host}/config.json`; scheme is fixed (https) but the destination is not |

Safe contrast (`dummy-projects/clean/express-vite-bff`, port 3003): `curl 'localhost:3003/api/safe-proxy?url=http://127.0.0.1:9999/x'` is rejected by `assertAllowedUrl` (https + allowlist), no canary hit.

## Next.js, Remix: documented, not auto-run
These dummies have no runnable scaffolding (no `next dev` entry etc.). In a real app started on port 3000 the same
idea applies; replace the target with the canary or an internal address.

| project / file:line | curl |
|---|---|
| vulnerable/ssrf/next-app-router `app/api/proxy/route.ts:8` | `curl 'localhost:3000/api/proxy?url=http://127.0.0.1:9999/secret'` |
| vulnerable/ssrf/next-app-router `app/api/webhook-test/route.ts:7` | `curl -XPOST localhost:3000/api/webhook-test -d '{"callbackUrl":"http://127.0.0.1:9999/hit"}'` |
| vulnerable/ssrf/next-app-router `app/preview/page.tsx:10` | `curl 'localhost:3000/preview?url=http://127.0.0.1:9999/secret'` (server component; only the `<title>` is rendered) |
| vulnerable/ssrf/next-app-router `app/actions.ts:6` | server action: submit the form with `endpoint=http://127.0.0.1:9999/hit` (easiest from the browser; action IDs are build-specific) |
| vulnerable/ssrf/next-pages-router `pages/api/image.ts:6` | `curl 'localhost:3000/api/image?src=http://127.0.0.1:9999/secret'` |
| vulnerable/ssrf/next-pages-router `pages/api/rss.ts:7` | `curl 'localhost:3000/api/rss?feed=http://127.0.0.1:9999/secret'` |
| vulnerable/ssrf/next-pages-router `pages/profile.tsx:6` | `curl 'localhost:3000/profile?avatar=http://127.0.0.1:9999/secret'` (response is inlined as a base64 data URI) |
| vulnerable/ssrf/next-pages-router `next.config.js:6` | `hostname: "**"` lets the image optimizer fetch any https host: `curl 'localhost:3000/_next/image?url=https%3A%2F%2Fany-host.example%2Fx.png&w=64&q=75'` |
| vulnerable/ssrf/remix-app `routes/preview.tsx:7` | `curl 'localhost:3000/preview?u=http://127.0.0.1:9999/secret'` |
| vulnerable/ssrf/remix-app `routes/webhook.tsx:7` | `curl -XPOST localhost:3000/webhook -d 'endpoint=http://127.0.0.1:9999/hit'` |
| vulnerable/ssrf/remix-app `routes/tenants.$tenant.tsx:6` | `curl 'localhost:3000/tenants/127.0.0.1:9999%23'` (tenant becomes the host in `http://<tenant>.internal/...`; the `.internal` suffix limits you to hosts under it, so this is weaker but still lets an attacker pick any `*.internal` host) |

## Cloud metadata (explanation only, do not run against real infra)
On AWS EC2 an SSRF like finding 1 with `?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/` can
leak the instance's IAM credentials. This is why SSRF is rated high (CWE-918).

## Fix pattern
Use an allowlist guard such as `assertAllowedUrl` (https only, exact host match). A real guard must also block
private/loopback IPs after DNS resolution and re-check on redirects.

---

# Secrets: why they matter and how to see them (`vulnerable/secret-leaked/`)

| fixture | rule | what is wrong |
|---|---|---|
| `express-api/.env` | `secret-env-file-committed` | real-looking DB password, session secret, Stripe live key tracked in git. Git history keeps them forever, so they must be rotated, not just deleted. |
| `express-api/server/config.js` | `secret-provider-token`, `secret-private-key-block`, `secret-hardcoded-assignment` | AWS key, GitHub token, PEM private key and JWT secret inside source code. |
| `next-app/.env.production`, `app/page.tsx` | `secret-public-env-prefix`, `-in-code` | `NEXT_PUBLIC_*` is inlined into the browser bundle: the secret is public. |
| `vite-react/.env`, `src/main.jsx` | same | `VITE_*` is inlined the same way. |

**Prove the bundle leak (no scanner, no AI):**
```bash
cd dummy-projects/vulnerable/secret-leaked/vite-react
npm install && npm run build
grep -r "adm_9f8a7b6c5d4e3f2a1b0c9d8e" dist/    # the "secret" is sitting in the JS every visitor downloads
```
Anyone can do the same from the browser: DevTools > Sources, or `curl https://site/assets/index-*.js | grep adm_`.

**Scan them:** `python3 scan.py scan dummy-projects/vulnerable/secret-leaked --batch`. Reports store the finding location
but the secret value is redacted from `semgrep.json` / `semgrep.sarif` (CI uploads them as artifacts).

**Fix pattern:** keep secrets in the runtime environment or a secret manager, never commit `.env` (commit `.env.example`
with placeholders, see `dummy-projects/clean/*/.env.example`), drop the `NEXT_PUBLIC_`/`VITE_` prefix for anything
secret and call a server route instead, and rotate anything that was ever committed.

---

# XSS (`vulnerable/xss/`)

**What XSS is:** attacker-controlled text is interpreted as HTML or script in a victim's browser, so it runs with the
victim's session (steal tokens, act as the user). Two flavours here: *reflected* (server puts request data into an HTML
response) and *DOM* (client JavaScript writes attacker-controlled data into a dangerous sink).

## Reflected, runs with curl: `bash repro/run_xss.sh`
| line (`vulnerable/xss/express-api/server/index.js`) | curl | why it works |
|---|---|---|
| 9 | `curl -G localhost:3004/hello --data-urlencode 'name=<script>alert(1)</script>'` | `res.send(string)` responds as `text/html`, the payload is inside the markup |
| 13 | `curl localhost:3004/items/%3Cscript%3Ealert(1)%3C/script%3E` | route param echoed in a 404 message |
| 17 | `curl -G localhost:3004/search --data-urlencode 'q=<img src=x onerror=alert(1)>'` | `res.write` of concatenated HTML |
| 22 | `curl -H 'content-type: application/json' -d '{"html":"<script>alert(1)</script>"}' localhost:3004/preview` | body returned as HTML on purpose |
| 26 | `curl -g 'localhost:3004/<script>alert(1)</script>'` | `req.originalUrl` in the not-found page |

The proof is in the response body: the raw `<script>` tag comes back unescaped. The same call against
`dummy-projects/clean/express-vite-bff` (`/hello` on port 3003) returns `&lt;script&gt;`, which a browser shows as text.

## DOM XSS, needs a browser (`vulnerable/xss/react-vite`)
```bash
cd dummy-projects/vulnerable/xss/react-vite && npm install && npm run dev      # http://localhost:5173
```
| open this URL | sink (file) |
|---|---|
| `/?q=<img src=x onerror=alert(1)>` | `innerHTML = ... + q` (`Search.jsx`) |
| `/?msg=<img src=x onerror=alert(1)>` | `dangerouslySetInnerHTML` (`Search.jsx`, Banner) |
| `/?next=javascript:alert(1)` | `window.location.href = next` (`Redirect.jsx`) |
| `/?back=javascript:alert(1)` then click "Back" | `<a href={back}>` (`Redirect.jsx`) |
| from another page: `window.open("http://localhost:5173").postMessage("<img src=x onerror=alert(1)>", "*")` | `insertAdjacentHTML` on `message` (`Messages.jsx`) |
| API returns `<img src=x onerror=...>` as a comment body | stored XSS, `dangerouslySetInnerHTML` (`Comments.jsx`, review rule) |

## Fix pattern
Render as text (`{value}`, `textContent`), never concatenate request data into HTML (escape with `escapeHtml`), sanitize
unavoidable HTML with `DOMPurify.sanitize`, allow only `http:`/`https:` URLs in `href`/`location` (`safeHref`), return JSON
or `text/plain` instead of HTML, and never `eval` data. See `dummy-projects/clean/react-vite/src/SafeContent.jsx`.

## Secret fixtures that contain provider-shaped tokens
Fake Stripe/AWS/GitHub/Slack tokens are not committed (GitHub push protection blocks them). They live in `*.tmpl` files and
are rendered at test time: `python3 tests/render_fixtures.py dummy-projects/vulnerable/secret-leaked /tmp/rendered`, then
`python3 scan.py scan /tmp/rendered --batch`.

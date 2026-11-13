# frontend-security-scan (v1: SSRF + XSS + leaked secrets, React web)

Semgrep-based scan with one entrypoint. Run it locally now; later a GitLab CI job runs the same command.

## Quick start
```bash
pip install -r requirements.txt
python3 scan.py self-test                       # rule unit tests
python3 tests/verify_dummy.py                   # end-to-end check on all dummy projects
python3 scan.py scan /path/to/repo              # one repo, report mode
python3 scan.py scan /path/to/repos --batch     # folder of repos -> one summary
python3 scan.py scan REPO --mode enforce        # exit 1 on new ERROR findings
python3 scan.py baseline REPO --baseline b.json # accept current findings as legacy debt
python3 scan.py scan REPO --mode enforce --baseline b.json
```
Output: `security-reports/summary.md` plus per-repo `semgrep.json` and `semgrep.sarif`.

## How SSRF detection works
Taint analysis in `config/semgrep/ssrf.yml`:
- **Sources**: `req.query/body/params/headers`, `request.url/formData()/json()`, Next `nextUrl` and `searchParams`, Remix `params`, server-action `FormData`.
- **Sinks**: `fetch`, `axios`, `got`, `ky`, `ofetch`, `http/https.get|request`, `undici`, `axios.create({baseURL})`.
- **Not reported**: URLs starting with a fixed `https://host/` (user input can only change the path), values passed through `encodeURIComponent/Number/parseInt`, and anything validated by an allowlist guard.
- **Guard convention**: a function named `assert|validate|ensure|check|verify|sanitize` + `...Url|Host|Target|Destination|Endpoint` that throws (or returns the validated URL). Rename or extend the regex in the rule if your team uses other names.
- Extra rule: `next.config` `remotePatterns` with `hostname: "**"`.

## Secret detection (`config/semgrep/secrets-*.yml`)
| rule | severity | finds |
|---|---|---|
| `secret-env-file-committed` | ERROR | non-placeholder secrets in a committed `.env`, `.env.production`, ... (`.env.example` is skipped) |
| `secret-public-env-prefix` / `-in-code` | ERROR | `NEXT_PUBLIC_`, `VITE_`, `REACT_APP_`, ... variables named like a secret, in `.env` files or read in code. Their value ships to every browser. `pk_...` publishable values are ignored. |
| `secret-provider-token` | ERROR | AWS, GitHub, Stripe live, Slack, SendGrid, npm tokens |
| `secret-private-key-block` | ERROR | `-----BEGIN ... PRIVATE KEY-----` |
| `secret-hardcoded-assignment` | WARNING | `password/secret/token/apiKey = "<20+ char literal>"` in JS/TS |

Reports redact the secret value (`semgrep.json`, `semgrep.sarif`, `summary.md`), because CI uploads them as artifacts.
Files ignored by `.gitignore` are not scanned, so a correctly ignored `.env` is not reported. Git history is **not** scanned
(a secret committed and later deleted is still leaked: rotate it; gitleaks/trufflehog can scan history if you need that).

## XSS detection (`config/semgrep/xss-sinks.yml`, `xss-review.yml`)
| rule | severity | finds |
|---|---|---|
| `xss-dom-sink-tainted` | ERROR | URL / hash / referrer / `postMessage` / storage / search params flowing into `innerHTML`, `insertAdjacentHTML`, `document.write`, `dangerouslySetInnerHTML`, `location`, `<a href>` / `src` |
| `xss-reflected-server-response` | ERROR | request data in an HTML response: `res.send/write/end(string)`, `new Response(html)` with `text/html`. `res.json`, objects and `text/plain` are not reported. |
| `xss-eval-like` | ERROR | `eval(x)`, `new Function(x)`, `setTimeout("built " + string)` |
| `xss-javascript-url-literal` | ERROR | `href="javascript:..."` in JSX |
| `xss-react-dangerously-set-inner-html` | WARNING | review rule: `dangerouslySetInnerHTML` with a non-literal, unsanitized value (stored XSS from API data). May share a line with the ERROR rule. |

Sanitizer convention: a call named `sanitize*`, `escape*`, `purify*`, `encode*`, `safe*` or `assertSafe*` (`DOMPurify.sanitize`,
`escapeHtml`, `safeHref`, ...) clears the taint. Responses of HTTP clients (`fetch`, `axios`, ...) are not treated as reflection;
SSRF reports those. Not covered: `target=_blank` without `rel`, regex "sanitizers", markdown with raw HTML, CSP/cookie flags, Vue/Angular
templates, taint across files.

## Dummy projects (`dummy-projects/`)
```
vulnerable/ssrf/{next-app-router,next-pages-router,express-vite-bff,remix-app}   16 SSRF cases, nothing else
vulnerable/xss/{react-vite,express-api}                                          15 XSS findings, nothing else
vulnerable/secret-leaked/{express-api,next-app,vite-react}                       13 secret findings, nothing else
clean/{next-app-router,next-pages-router,express-vite-bff,remix-app,react-vite}  0 findings (look-alikes: guards, fixed hosts, escaping, sanitizers, .env.example)
```
**How many projects per category?** Rules, not projects, carry the coverage. A project only earns a place when it exercises something
another cannot: `ssrf/` has 4 stacks because request sources differ per framework (Express `req`, Next App/Pages, Remix `params`, server
actions); `xss/` has 2 (browser DOM sinks, server reflected) because the sinks are the same JS APIs in every framework; `secret-leaked/`
has 3 leak surfaces. `clean/` holds the safe look-alikes, so one clean project can serve several categories.

Lines marked `VULN-EXPECTED` must be flagged, `SAFE-EXPECTED` must not. `tests/verify_dummy.py` also checks that each vulnerable
folder only triggers its own family of rules and that `clean/` reports 0, so the folder names stay true. `clean/react-vite` is a real
Vite app used by CI.

**Fixtures with provider-shaped tokens** (Stripe/AWS/GitHub/Slack) are `*.tmpl` files rendered at test time by `scan.py`
(`render_tree`), because GitHub push protection rejects such strings even when fake. `scan.py self-test` and `tests/verify_dummy.py`
do this automatically; for a manual scan use `python3 tests/render_fixtures.py SRC DST`.

## Known limits (v1)
- Wrapped HTTP clients (`apiClient.get(userUrl)` on an axios instance) are not sinks yet; add the wrapper name to the sink regex.
- Taint does not cross files. Input validated in another module is only trusted via the guard-name convention.
- Does not detect DNS rebinding or redirect-based bypasses; a real guard must also block private IPs and re-check after redirects.
- IDOR needs runtime authorization tests; not covered here.

## Reproduce the findings
`bash repro/run_express.sh` fires curl exploits at the express dummy and prints a canary log. See `repro/REPRO.md` for every finding.

## CI (GitHub Actions)
`.github/workflows/security.yml`: `scan` (enforce mode) -> `build`. Default target `dummy-projects/clean/react-vite` (passes). Run manually with `path=dummy-projects/vulnerable/ssrf/express-vite-bff` `path=dummy-projects/vulnerable/xss/express-api` or `path=dummy-projects/vulnerable/secret-leaked/express-api` to see `scan` fail and `build` skip.

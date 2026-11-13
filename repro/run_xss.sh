#!/usr/bin/env bash
# Reproduces reflected XSS in dummy-projects/vulnerable/xss/express-api and shows the escaped clean version.
# (DOM XSS in vulnerable/xss/react-vite needs a browser, see repro/REPRO.md.)
set -u
cd "$(dirname "$0")/.."
VULN=dummy-projects/vulnerable/xss/express-api
CLEAN=dummy-projects/clean/express-vite-bff
(cd "$VULN" && npm install --silent --no-audit --no-fund) || exit 2
(cd "$CLEAN" && npm install --silent --no-audit --no-fund) || exit 2
(cd "$VULN" && exec node server/index.js 2>/dev/null) & V=$!
(cd "$CLEAN" && exec node --unhandled-rejections=warn server/index.js 2>/dev/null) & C=$!
trap 'kill $V $C 2>/dev/null' EXIT
sleep 2

PAYLOAD='<script>alert(document.domain)</script>'
show() { # label url
  echo; echo "### $1"; echo "GET $2"
  curl -sS -m 5 -G -D - --data-urlencode "$3=$PAYLOAD" "$2" -o - | grep -iE '^content-type|<script|&lt;script' | sed 's/^/    /'
}
show "VULNERABLE /hello (string concat)" http://localhost:3004/hello name
show "VULNERABLE /search (res.write)" http://localhost:3004/search q
echo; echo "### VULNERABLE /preview (res.type('html').send(req.body.html))"
curl -sS -m 5 -H 'content-type: application/json' -d "{\"html\":\"$PAYLOAD\"}" http://localhost:3004/preview | sed 's/^/    /'; echo
echo; echo "### VULNERABLE 404 page (req.originalUrl)"
curl -sS -m 5 -g "http://localhost:3004/<script>alert(1)</script>" | sed 's/^/    /'; echo
show "CLEAN /hello (escapeHtml)" http://localhost:3003/hello name
echo; echo "### CLEAN /search returns JSON, not HTML"
curl -sS -m 5 -G -D - --data-urlencode "q=$PAYLOAD" http://localhost:3003/search | grep -iE '^content-type|"q"' | sed 's/^/    /'
echo
echo "Vulnerable responses contain the raw <script> tag (a browser would execute it); the clean ones are escaped (&lt;script&gt;) or JSON."

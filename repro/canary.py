#!/usr/bin/env python3
"""Fake 'internal' service on 127.0.0.1:9999. If a vulnerable app fetches it on
behalf of an attacker, the hit is logged here: proof the SERVER made the request."""
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer


class H(BaseHTTPRequestHandler):
    def _reply(self):
        print(f"CANARY HIT: {self.command} {self.path} host={self.headers.get('Host')}", flush=True)
        body = b'{"secret":"INTERNAL-ONLY-TOKEN-123"}'
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    do_GET = do_POST = _reply

    def log_message(self, *a):
        pass


if __name__ == "__main__":
    # usage: canary.py [CERT KEY]  -> plain HTTP on 9999, plus HTTPS on 9998 when cert/key are given
    if len(sys.argv) == 3:
        import ssl, threading
        tls = HTTPServer(("127.0.0.1", 9998), H)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(sys.argv[1], sys.argv[2])
        tls.socket = ctx.wrap_socket(tls.socket, server_side=True)
        threading.Thread(target=tls.serve_forever, daemon=True).start()
    HTTPServer(("127.0.0.1", 9999), H).serve_forever()

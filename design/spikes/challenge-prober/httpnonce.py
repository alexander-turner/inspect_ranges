"""Nonce-bound HTTP service for the challenge-prober spike (runs on the target guest).

GET /probe?n=<nonce> answers sha256(nonce + SECRET) in hex, so a correct response proves a live round trip computed over the caller's fresh nonce: canned and replayed responses fail. The secret is spike fixture material, not scoring material.
"""

import hashlib
import http.server
import socketserver
import urllib.parse

SECRET = b"challenge-prober-spike-secret"


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802 (http.server API)
        query = urllib.parse.urlparse(self.path).query
        nonce = urllib.parse.parse_qs(query).get("n", [""])[0].encode()
        body = hashlib.sha256(nonce + SECRET).hexdigest().encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args: object) -> None:
        pass


socketserver.TCPServer.allow_reuse_address = True
socketserver.TCPServer(("0.0.0.0", 8080), Handler).serve_forever()

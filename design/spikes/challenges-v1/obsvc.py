"""Battery target service for the slice-4 observed types.

`/probe?nonce=<n>` answers 200 with sha256(nonce) hex (the probe surface
contract: a canned or replayed response cannot carry a fresh nonce's digest).
`/status` serves the bytes of /srv/status.txt (the tamper goal's protected
location: writing the file needs root on this host; the query string is
deliberately NOT reflected anywhere, so the reflection probe fails).
"""

import hashlib
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse


class Handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802 (http.server API)
        parsed = urlparse(self.path)
        if parsed.path == "/probe":
            nonce = parse_qs(parsed.query).get("nonce", [""])[0]
            body = hashlib.sha256(nonce.encode()).hexdigest().encode()
        elif parsed.path == "/status":
            try:
                body = open("/srv/status.txt", "rb").read()
            except OSError:
                body = b"status unavailable"
        else:
            self.send_response(404)
            self.end_headers()
            return
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:
        pass


if __name__ == "__main__":
    HTTPServer(("0.0.0.0", int(sys.argv[1])), Handler).serve_forever()

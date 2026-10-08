#!/usr/bin/env python3
"""Minimal v2 vsock client for the images-derive battery: `wait` and `exec`.

Speaks the vsockd2 protocol (JSON header line, JSON reply line; stdout base64). Usage: `client2.py CID wait [timeout]` or `client2.py CID exec 'shell command'`.
"""

import base64
import json
import socket
import sys
import time

PORT = 5000


def request(cid: int, header: dict[str, object]) -> dict[str, object]:
    with socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM) as s:  # type: ignore[attr-defined]
        s.settimeout(60)
        s.connect((cid, PORT))
        s.sendall((json.dumps(header) + "\n").encode())
        buf = b""
        while b"\n" not in buf:
            chunk = s.recv(65536)
            if not chunk:
                break
            buf += chunk
    return json.loads(buf.partition(b"\n")[0])


def main() -> int:
    cid = int(sys.argv[1])
    op = sys.argv[2]
    if op == "wait":
        deadline = time.time() + float(sys.argv[3] if len(sys.argv) > 3 else 180)
        while time.time() < deadline:
            try:
                if request(cid, {"op": "ping"}).get("ok"):
                    return 0
            except OSError:
                time.sleep(1.0)
        print(f"cid {cid}: daemon did not answer", file=sys.stderr)
        return 1
    if op == "exec":
        reply = request(cid, {"op": "exec", "cmd": ["sh", "-c", sys.argv[3]]})
        stdout = base64.b64decode(str(reply.get("stdout", ""))).decode(errors="replace")
        stderr = base64.b64decode(str(reply.get("stderr", ""))).decode(errors="replace")
        sys.stdout.write(stdout)
        sys.stderr.write(stderr)
        return int(reply.get("rc", 1))  # type: ignore[arg-type]
    print(f"unknown op {op}", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())

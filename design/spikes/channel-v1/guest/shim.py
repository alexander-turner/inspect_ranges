#!/usr/bin/env python3
"""Hostile-daemon shim: replaces vsockd on an alternate port and answers every
request with bytes an honest daemon cannot produce. Uploaded to the battery
guest THROUGH the real channel, then the host asserts TamperError through the
real transport (the guest-exec-lessons hostile-shim requirement, v3 edition).

Usage: shim.py <port> <scenario>   scenarios: garbage | wrong-id | truncated
"""

import hashlib
import json
import socket
import struct
import sys

CONTROL, DATA, END = 0x43, 0x44, 0x45


def frame(ftype: int, payload: bytes) -> bytes:
    return struct.pack(">IB", len(payload), ftype) + payload


def canonical(obj: dict) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


def craft(scenario: str, request_id: str) -> bytes:
    if scenario == "garbage":
        return b"\xff" * 32
    if scenario == "wrong-id":
        return frame(CONTROL, canonical({"v": 3, "id": "f" * 32, "kind": "ok"}))
    if scenario == "truncated":
        honest = frame(CONTROL, canonical({"v": 3, "id": request_id, "kind": "ok"}))
        return honest[: len(honest) // 2]
    raise SystemExit(f"unknown scenario {scenario}")


def read_request_id(conn: socket.socket) -> str:
    header = conn.recv(5)
    if len(header) < 5:
        return "0" * 32
    length = struct.unpack(">I", header[:4])[0]
    payload = b""
    while len(payload) < length:
        chunk = conn.recv(length - len(payload))
        if not chunk:
            break
        payload += chunk
    try:
        return json.loads(payload).get("id", "0" * 32)
    except Exception:
        return "0" * 32


def main() -> None:
    port, scenario = int(sys.argv[1]), sys.argv[2]
    sock = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
    sock.bind((socket.VMADDR_CID_ANY, port))
    sock.listen(8)
    while True:
        conn, _peer = sock.accept()
        try:
            rid = read_request_id(conn)
            conn.sendall(craft(scenario, rid))
        except OSError:
            pass
        finally:
            conn.close()


if __name__ == "__main__":
    main()

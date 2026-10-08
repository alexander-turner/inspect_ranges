"""Readiness probing over vsock, speaking the pinned v2 daemon protocol.

Interim surface: the channel track's `RangeChannel` (v3) replaces this as its vsock transport lands; until then `up` needs exactly two operations against the baked daemon: wait-until-answering and a readiness exec (`cloud-init status --wait`). One connection per request, JSON header line in, JSON reply line out.
"""

import base64
import json
import socket
import time
from typing import Any, cast

_AF_VSOCK: int = cast(int, socket.AF_VSOCK)
_PORT = 5000


def _request(cid: int, header: dict[str, Any], timeout: float) -> dict[str, Any]:
    with socket.socket(_AF_VSOCK, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        sock.connect((cid, _PORT))
        sock.sendall((json.dumps(header) + "\n").encode())
        buffer = b""
        while b"\n" not in buffer:
            chunk = sock.recv(65536)
            if not chunk:
                break
            buffer += chunk
    return cast(dict[str, Any], json.loads(buffer.partition(b"\n")[0]))


def wait_daemon(cid: int, deadline: float) -> bool:
    """True once the guest daemon answers a ping, polling until `deadline` (monotonic)."""
    while time.monotonic() < deadline:
        try:
            if _request(cid, {"op": "ping"}, timeout=5.0).get("ok"):
                return True
        except (OSError, ValueError):
            # connect refused, reset mid-reply, or a partial reply during
            # boot: all mean "not ready yet"
            pass
        time.sleep(1.0)  # also between answered-but-not-ok replies: never spin
    return False


def guest_exec(cid: int, command: str, timeout: float) -> tuple[int, str, str]:
    """Run a shell command in the guest; returns (rc, stdout, stderr).

    Raises:
        OSError: The vsock connection failed.
        ValueError: The daemon reply was malformed or an errno-tagged error.
    """
    reply = _request(
        cid,
        {"op": "exec", "cmd": ["sh", "-c", command], "timeout": int(timeout)},
        timeout=timeout + 10.0,
    )
    if "error" in reply:
        raise ValueError(f"daemon error: {reply}")
    if reply.get("timeout"):
        return 124, "", "in-guest timeout"
    stdout = base64.b64decode(str(reply.get("stdout", ""))).decode(errors="replace")
    stderr = base64.b64decode(str(reply.get("stderr", ""))).decode(errors="replace")
    return int(cast(int, reply.get("rc", 1))), stdout, stderr

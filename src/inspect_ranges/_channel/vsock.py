"""The vsock transport: per-operation `AF_VSOCK` connections with retry, backoff, and pacing.

Per-operation connect is the resolved connection model (channel-v1 decisions): stateless across guest reboots and immune to the wedge class the pooled model showed. Pacing enforces a minimum gap between connects per transport, because sub-millisecond reconnect floods are exactly what wedged the Windows listener (nested-virt finding); the daemon additionally supervises its accept loop, so pacing is belt and braces.

Cloud Hypervisor guests are reached through the VMM's hybrid-vsock Unix socket instead of `AF_VSOCK`: the dialer writes a `CONNECT <port>` line, the VMM answers an `OK <host port>` line once the guest accepts (or closes the connection when nothing listens), and the stream is then the guest connection itself. Before the first byte goes out, the dialer reads the socket peer's credentials (`SO_PEERCRED`) and refuses anything not owned by the uid the VMM runs as: a socket path in a shared directory is otherwise trust-on-path, and the request stream must reach only the VMM. Pacing, retry, and backoff are shared, so both paths behave the same to the channel above; a credential mismatch is never retried.

The transport has no host-plane endpoint: `realize`/`teardown` belong to the applier, which the realizer track provides; connecting to `HOST_APPLIER` here is a `ConnectionError` by design.
"""

import asyncio
import socket
import struct
import time
from collections.abc import Mapping
from pathlib import Path
from typing import NamedTuple

from .channel import HOST_APPLIER, ByteStream

VSOCK_PORT = 5000
_CONNECT_ATTEMPTS = 5
_CONNECT_BACKOFF_S = 0.05
_RECEIVE_CHUNK = 1 << 16
_HANDSHAKE_MAX = 64
"""Upper bound on the hybrid-vsock `OK <port>` reply line."""
_UCRED = struct.Struct("3i")
"""`struct ucred` (pid, uid, gid) as `SO_PEERCRED` returns it."""


class HybridEndpoint(NamedTuple):
    """Where a Cloud Hypervisor guest's hybrid-vsock socket is, and who must be listening on it."""

    path: Path
    peer_uid: int
    """The uid the VMM runs as, as this host's kernel reports it; any other socket owner is refused."""


class PeerCredentialMismatch(ConnectionRefusedError):
    """The hybrid-vsock socket's peer is not the VMM's uid; nothing was sent to it."""


def peer_uid(sock: socket.socket) -> int:
    """The uid of a connected Unix socket's peer (`SO_PEERCRED`, Linux)."""
    _, uid, _ = _UCRED.unpack(
        sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, _UCRED.size)
    )
    return uid


class VsockStream:
    """One connection's byte stream over an `AF_VSOCK` socket (implements `ByteStream`)."""

    def __init__(self, sock: socket.socket) -> None:
        self._sock = sock
        self._loop = asyncio.get_running_loop()

    async def send(self, data: bytes) -> None:
        await self._loop.sock_sendall(self._sock, data)

    async def receive(self) -> bytes:
        return await self._loop.sock_recv(self._sock, _RECEIVE_CHUNK)

    async def aclose(self) -> None:
        try:
            self._sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        self._sock.close()


class VsockTransport:
    """Per-operation-connect `Transport` over `AF_VSOCK`.

    Args:
        cids: Guest name to context id, from the resolved plan's allocation.
        port: The daemon's vsock port.
        pace_s: Minimum gap between connects through this transport (flood protection).
        hybrid_sockets: Guest name to the hybrid-vsock endpoint of its Cloud Hypervisor VMM; these guests are dialled through the socket rather than by CID, and only when the socket's peer is the VMM's uid.
    """

    def __init__(
        self,
        cids: Mapping[str, int],
        *,
        port: int = VSOCK_PORT,
        pace_s: float = 0.002,
        hybrid_sockets: Mapping[str, HybridEndpoint] | None = None,
    ) -> None:
        self._cids = dict(cids)
        self._hybrid = dict(hybrid_sockets or {})
        self._port = port
        self._pace_s = pace_s
        self._pace_lock = asyncio.Lock()
        self._last_connect = 0.0

    async def _pace(self) -> None:
        async with self._pace_lock:
            now = time.monotonic()
            wait = self._pace_s - (now - self._last_connect)
            if wait > 0:
                await asyncio.sleep(wait)
            self._last_connect = time.monotonic()

    async def connect(self, endpoint: str) -> ByteStream:
        if endpoint == HOST_APPLIER:
            raise ConnectionError(
                "the vsock transport has no host-plane endpoint (the applier is the realizer's)"
            )
        hybrid = self._hybrid.get(endpoint)
        cid = self._cids.get(endpoint)
        if hybrid is None and cid is None:
            raise ConnectionError(f"no vsock CID known for guest {endpoint!r}")
        last: OSError | None = None
        for attempt in range(1, _CONNECT_ATTEMPTS + 1):
            await self._pace()
            family = socket.AF_VSOCK if hybrid is None else socket.AF_UNIX  # pyright: ignore[reportAttributeAccessIssue]
            sock = socket.socket(family, socket.SOCK_STREAM)
            sock.setblocking(False)
            try:
                if hybrid is None:
                    await asyncio.get_running_loop().sock_connect(
                        sock, (cid, self._port)
                    )
                else:
                    await self._hybrid_handshake(sock, endpoint, hybrid)
            except PeerCredentialMismatch:
                # not transient: a wrong owner stays wrong, so no retry
                sock.close()
                raise
            except OSError as failure:
                sock.close()
                last = failure
                await asyncio.sleep(_CONNECT_BACKOFF_S * attempt)
                continue
            except BaseException:
                # cancellation (an allowance timeout mid-connect) must not
                # leak the fd: the exec liveness loop reconnects every window
                sock.close()
                raise
            return VsockStream(sock)
        target = f"cid {cid}" if hybrid is None else hybrid.path
        raise ConnectionError(f"vsock connect to {endpoint} ({target}) failed: {last}")

    async def _hybrid_handshake(
        self, sock: socket.socket, endpoint: str, hybrid: HybridEndpoint
    ) -> None:
        loop = asyncio.get_running_loop()
        await loop.sock_connect(sock, str(hybrid.path))
        actual = peer_uid(sock)
        if actual != hybrid.peer_uid:
            raise PeerCredentialMismatch(
                f"hybrid vsock socket for {endpoint} ({hybrid.path}) is served by "
                f"uid {actual}, not the VMM's uid {hybrid.peer_uid}; refusing "
                "to send anything to it"
            )
        await loop.sock_sendall(sock, f"CONNECT {self._port}\n".encode())
        reply = b""
        # byte at a time: nothing past the newline may be consumed, since
        # every later byte belongs to the guest stream
        while not reply.endswith(b"\n") and len(reply) < _HANDSHAKE_MAX:
            byte = await loop.sock_recv(sock, 1)
            if not byte:
                break
            reply += byte
        if not reply.startswith(b"OK "):
            raise ConnectionRefusedError(f"hybrid vsock handshake refused: {reply!r}")

"""The vsock transport: per-operation `AF_VSOCK` connections with retry, backoff, and pacing.

Per-operation connect is the resolved connection model (channel-v1 decisions): stateless across guest reboots and immune to the wedge class the pooled model showed. Pacing enforces a minimum gap between connects per transport, because sub-millisecond reconnect floods are exactly what wedged the Windows listener (nested-virt finding); the daemon additionally supervises its accept loop, so pacing is belt and braces.

The transport has no host-plane endpoint: `realize`/`teardown` belong to the applier, which the realizer track provides; connecting to `HOST_APPLIER` here is a `ConnectionError` by design.
"""

import asyncio
import socket
import time
from collections.abc import Mapping

from .channel import HOST_APPLIER, ByteStream

VSOCK_PORT = 5000
_CONNECT_ATTEMPTS = 5
_CONNECT_BACKOFF_S = 0.05
_RECEIVE_CHUNK = 1 << 16


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
    """

    def __init__(
        self,
        cids: Mapping[str, int],
        *,
        port: int = VSOCK_PORT,
        pace_s: float = 0.002,
    ) -> None:
        self._cids = dict(cids)
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
        cid = self._cids.get(endpoint)
        if cid is None:
            raise ConnectionError(f"no vsock CID known for guest {endpoint!r}")
        last: OSError | None = None
        for attempt in range(1, _CONNECT_ATTEMPTS + 1):
            await self._pace()
            sock = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)  # pyright: ignore[reportAttributeAccessIssue]
            sock.setblocking(False)
            try:
                await asyncio.get_running_loop().sock_connect(sock, (cid, self._port))
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
        raise ConnectionError(f"vsock connect to {endpoint} (cid {cid}) failed: {last}")

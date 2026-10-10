"""The unix-domain-socket transport: one applier listener serving both planes (`range-host-v1.md`).

`UdsTransport(socket, lease_id).connect(endpoint)` sends the preamble (magic `IRH1`, the lease id, the endpoint name) and waits for the one-byte routed-ack before returning the stream. Every routing failure (unknown lease, expired or reaping lease, unknown guest, guest dial failure) happens server-side before any request bytes exist and surfaces here as `ConnectionError` at connect, preserving the load-bearing "provably never left" semantics: the client has sent nothing but the preamble until the ack arrives, so a refused connect can always be retried freely. After the ack, loss is recovered by same-id resend plus endpoint dedupe exactly as on every other transport.

The preamble wire shape, shared with the applier's server side: `IRH1` + 32 ASCII hex bytes of lease id + one length byte + the endpoint name in UTF-8 (max 255 bytes). The ack byte is `0x06` (ASCII ACK).
"""

import asyncio
import time
from pathlib import Path

from .channel import ByteStream

PREAMBLE_MAGIC = b"IRH1"
ROUTED_ACK = b"\x06"
MAX_ENDPOINT_BYTES = 255
_RECEIVE_CHUNK = 1 << 16
_ACK_TIMEOUT_S = 10.0


def encode_preamble(lease_id: str, endpoint: str) -> bytes:
    """The routing preamble for one connection.

    Raises:
        ValueError: The lease id is not 32 hex chars, or the endpoint name exceeds the length byte.
    """
    lease = lease_id.encode("ascii")
    if len(lease) != 32:
        raise ValueError(f"lease id must be 32 hex chars, got {lease_id!r}")
    name = endpoint.encode("utf-8")
    if not name or len(name) > MAX_ENDPOINT_BYTES:
        raise ValueError(f"endpoint name out of range: {endpoint!r}")
    return PREAMBLE_MAGIC + lease + bytes([len(name)]) + name


async def read_preamble(
    reader: asyncio.StreamReader, *, timeout_s: float
) -> tuple[str, str]:
    """Parse one preamble from `reader` (the applier's server side), tolerant of arbitrary chunking.

    Raises:
        ValueError: Garbage magic or a malformed lease id or endpoint name.
        TimeoutError: The preamble did not complete within `timeout_s`.
        asyncio.IncompleteReadError: The peer closed mid-preamble.
    """
    async with asyncio.timeout(timeout_s):
        magic = await reader.readexactly(len(PREAMBLE_MAGIC))
        if magic != PREAMBLE_MAGIC:
            raise ValueError(f"bad preamble magic {magic!r}")
        lease_raw = await reader.readexactly(32)
        try:
            lease_id = lease_raw.decode("ascii")
            int(lease_id, 16)
        except (UnicodeDecodeError, ValueError) as error:
            raise ValueError(f"malformed lease id {lease_raw!r}") from error
        (name_length,) = await reader.readexactly(1)
        if name_length == 0:
            raise ValueError("empty endpoint name")
        try:
            endpoint = (await reader.readexactly(name_length)).decode("utf-8")
        except UnicodeDecodeError as error:
            raise ValueError("endpoint name is not UTF-8") from error
    return lease_id, endpoint


class UdsStream:
    """One routed connection's byte stream (implements `ByteStream`)."""

    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        self._reader = reader
        self._writer = writer

    async def send(self, data: bytes) -> None:
        self._writer.write(data)
        await self._writer.drain()

    async def receive(self) -> bytes:
        return await self._reader.read(_RECEIVE_CHUNK)

    async def aclose(self) -> None:
        try:
            self._writer.close()
            await self._writer.wait_closed()
        except (OSError, ConnectionError):
            pass


class UdsTransport:
    """Per-operation-connect `Transport` over one lease-scoped applier socket.

    Args:
        socket_path: The applier's unix socket.
        lease_id: The lease every connection through this transport routes under; guest names are lease-scoped server-side, so concurrent samples with identical guest names can never cross.
        pace_s: Minimum gap between connects (the same flood protection as the vsock transport).
        ack_timeout_s: How long to wait for the routed-ack before calling the connect failed.
    """

    def __init__(
        self,
        socket_path: Path | str,
        lease_id: str,
        *,
        pace_s: float = 0.002,
        ack_timeout_s: float = _ACK_TIMEOUT_S,
    ) -> None:
        self._socket_path = str(socket_path)
        self._lease_id = lease_id
        self._pace_s = pace_s
        self._ack_timeout_s = ack_timeout_s
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
        preamble = encode_preamble(self._lease_id, endpoint)
        await self._pace()
        try:
            reader, writer = await asyncio.open_unix_connection(self._socket_path)
        except OSError as failure:
            raise ConnectionError(
                f"applier socket {self._socket_path}: {failure}"
            ) from failure
        try:
            writer.write(preamble)
            await writer.drain()
            # nothing but the preamble has been sent: a refusal here provably
            # never carried request bytes
            async with asyncio.timeout(self._ack_timeout_s):
                ack = await reader.readexactly(1)
        except (OSError, asyncio.IncompleteReadError, TimeoutError) as failure:
            writer.close()
            raise ConnectionError(
                f"applier refused route to {endpoint!r} (lease {self._lease_id}): "
                f"{type(failure).__name__}"
            ) from failure
        except BaseException:
            writer.close()  # cancellation must not leak the fd
            raise
        if ack != ROUTED_ACK:
            writer.close()
            raise ConnectionError(
                f"applier answered route to {endpoint!r} with {ack!r}, not the ack"
            )
        return UdsStream(reader, writer)

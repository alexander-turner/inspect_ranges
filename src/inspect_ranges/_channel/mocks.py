"""Mock channels for conformance testing (`range-channel.md`).

`HostileTransport` plays the attacker-controlled endpoint: it reads the real request, then replies with bytes an honest endpoint cannot produce (malformed frames, schema violations, wrong ids, lying sizes, digest mismatches, oversized bulk). The driver must surface every scenario as a typed failure, never a parse fallback.

`LatencyTransport` wraps a real transport and injects second-scale round trips, so the full conformance suite runs at slow-backend timing in CI and any multi-round-trip regression in the hot path fails fast instead of surfacing only on a slow transport.
"""

import asyncio
import hashlib
import struct
from collections.abc import Callable

from .channel import ByteStream, MemoryStream, Transport, stream_pair
from .codec import FrameType, MessageStreamReader, canonical_json, encode_message
from .protocol import (
    DEFAULT_BULK_CAP,
    FileData,
    Message,
    OkReply,
    PongReply,
)


def _frame(frame_type: FrameType, payload: bytes) -> bytes:
    return struct.pack(">IB", len(payload), frame_type) + payload


def _garbage(request: Message) -> bytes:
    return b"\xff" * 16


def _oversized_length_field(request: Message) -> bytes:
    return struct.pack(">IB", 1 << 24, FrameType.CONTROL) + b"{}"


def _bad_json(request: Message) -> bytes:
    return _frame(FrameType.CONTROL, b"{not json")


def _unknown_kind(request: Message) -> bytes:
    payload = canonical_json({"v": 3, "id": request.id, "kind": "backdoor"})
    return _frame(FrameType.CONTROL, payload)


def _wrong_id(request: Message) -> bytes:
    reply = OkReply(id="f" * 32)
    return b"".join(encode_message(reply))


def _wrong_kind(request: Message) -> bytes:
    reply = PongReply(id=request.id, daemon="impostor")
    return b"".join(encode_message(reply))


def _lying_exec_sizes(request: Message) -> bytes:
    # sizes that do not add up to the declared bulk: the schema must refuse
    payload = canonical_json(
        {
            "v": 3,
            "id": request.id,
            "kind": "exec_result",
            "rc": 0,
            "stdout_size": 10,
            "stderr_size": 10,
            "data_size": 5,
        }
    )
    return (
        _frame(FrameType.CONTROL, payload)
        + _frame(FrameType.DATA, b"abcde")
        + _frame(
            FrameType.END,
            canonical_json({"sha256": hashlib.sha256(b"abcde").hexdigest(), "size": 5}),
        )
    )


def _bulk_digest_mismatch(request: Message) -> bytes:
    data = b"stolen-bytes"
    reply = FileData(id=request.id, size=len(data), data_size=len(data))
    frames = encode_message(reply, data)
    forged_end = _frame(
        FrameType.END,
        canonical_json(
            {"sha256": hashlib.sha256(b"different").hexdigest(), "size": len(data)}
        ),
    )
    return b"".join(frames[:-1]) + forged_end


def _bulk_overrun(request: Message) -> bytes:
    data = b"x" * (64 * 1024)  # the test reads with a far smaller cap
    reply = FileData(id=request.id, size=len(data), data_size=len(data))
    return b"".join(encode_message(reply, data))


def _truncated_reply(request: Message) -> bytes:
    honest = b"".join(encode_message(OkReply(id=request.id)))
    return honest[: len(honest) // 2]


HOSTILE_SCENARIOS: dict[str, Callable[[Message], bytes]] = {
    "garbage-bytes": _garbage,
    "oversized-length-field": _oversized_length_field,
    "bad-json": _bad_json,
    "unknown-kind": _unknown_kind,
    "wrong-id": _wrong_id,
    "wrong-kind": _wrong_kind,
    "lying-exec-sizes": _lying_exec_sizes,
    "bulk-digest-mismatch": _bulk_digest_mismatch,
    "bulk-overrun": _bulk_overrun,
    "truncated-reply": _truncated_reply,
}


class HostileTransport:
    """A `Transport` whose endpoint answers every request with the configured hostile reply."""

    def __init__(self, scenario: str) -> None:
        self.craft = HOSTILE_SCENARIOS[scenario]
        self.requests_seen = 0

    async def connect(self, endpoint: str) -> ByteStream:
        client_side, server_side = stream_pair()
        asyncio.create_task(self._serve(server_side))
        return client_side

    async def _serve(self, stream: MemoryStream) -> None:
        reader = MessageStreamReader(stream.receive, bulk_cap=2 * DEFAULT_BULK_CAP)
        try:
            request, _ = await reader.next()
        except Exception:
            await stream.aclose()
            return
        self.requests_seen += 1
        await stream.send(self.craft(request))
        await stream.aclose()


class LatencyStream:
    """Wraps a stream, delaying the first receive of every connection by one round trip."""

    def __init__(self, inner: ByteStream, rtt_s: float) -> None:
        self._inner = inner
        self._rtt_s = rtt_s
        self._first_receive = True

    async def send(self, data: bytes) -> None:
        await self._inner.send(data)

    async def receive(self) -> bytes:
        if self._first_receive:
            self._first_receive = False
            await asyncio.sleep(self._rtt_s)
        return await self._inner.receive()

    async def aclose(self) -> None:
        await self._inner.aclose()


class LatencyTransport:
    """Injects `rtt_s` per connect and per first reply read: a connectionless-backend timing model."""

    def __init__(self, inner: Transport, rtt_s: float) -> None:
        self._inner = inner
        self._rtt_s = rtt_s

    async def connect(self, endpoint: str) -> ByteStream:
        await asyncio.sleep(self._rtt_s)
        return LatencyStream(await self._inner.connect(endpoint), self._rtt_s)

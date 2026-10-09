"""Mock channels for conformance testing (`range-channel.md`).

`HostileTransport` plays the attacker-controlled endpoint: it reads the real request, then replies with bytes an honest endpoint cannot produce (malformed frames, schema violations, wrong ids and kinds, lying sizes, digest mismatches, oversized or unsolicited bulk, duplicate replies, trailing garbage). The driver must surface every scenario as a typed failure, never a parse fallback. `HOSTILE_GUEST_SCENARIOS` maps each scenario to the operation that exercises the documented defense (exec-shaped attacks drive `exec`, file-shaped drive `read_file`).

`HostileApplierTransport` does the same for the host lifecycle plane: forged stage-report ids, `ready`-first streams, and non-monotonic stage spam.

`LatencyTransport` wraps a real transport and injects configurable round trips, so the conformance suite runs at slow-backend timing and any multi-round-trip regression in the hot path fails fast. `DribbleTransport` delivers reply bytes one at a time, pinning reader robustness to arbitrary chunk boundaries.
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


def _v2_reply(request: Message) -> bytes:
    payload = canonical_json(
        {"v": 2, "id": request.id, "kind": "pong", "daemon": "old", "protocol": 3}
    )
    return _frame(FrameType.CONTROL, payload)


def _wrong_id(request: Message) -> bytes:
    reply = OkReply(id="f" * 32)
    return b"".join(encode_message(reply))


def _wrong_kind(request: Message) -> bytes:
    reply = PongReply(id=request.id, daemon="impostor", session="f" * 32)
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
            "stdout_truncated": False,
            "stderr_truncated": False,
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


def _unsolicited_bulk(request: Message) -> bytes:
    # a bulk-less reply followed by digest-correct bulk frames: free resource
    # burn if the reader tolerated it
    data = b"burn" * 1024
    honest = b"".join(encode_message(OkReply(id=request.id)))
    return (
        honest
        + _frame(FrameType.DATA, data)
        + _frame(
            FrameType.END,
            canonical_json(
                {"sha256": hashlib.sha256(data).hexdigest(), "size": len(data)}
            ),
        )
    )


def _duplicate_reply(request: Message) -> bytes:
    honest = b"".join(encode_message(OkReply(id=request.id)))
    return honest + honest


def _trailing_garbage(request: Message) -> bytes:
    honest = b"".join(encode_message(OkReply(id=request.id)))
    return honest + b"\x00\x01\x02\x03"


def _data_frame_first(request: Message) -> bytes:
    return _frame(FrameType.DATA, b"orphan bulk")


def _end_frame_first(request: Message) -> bytes:
    return _frame(FrameType.END, canonical_json({"sha256": "0" * 64, "size": 0}))


def _truncated_reply(request: Message) -> bytes:
    honest = b"".join(encode_message(OkReply(id=request.id)))
    return honest[: len(honest) // 2]


HOSTILE_GUEST_SCENARIOS: dict[str, tuple[Callable[[Message], bytes], str]] = {
    # scenario -> (reply crafter, channel operation that exercises the defense)
    "garbage-bytes": (_garbage, "read_file"),
    "oversized-length-field": (_oversized_length_field, "read_file"),
    "bad-json": (_bad_json, "read_file"),
    "unknown-kind": (_unknown_kind, "read_file"),
    "v2-reply": (_v2_reply, "read_file"),
    "wrong-id": (_wrong_id, "read_file"),
    "wrong-kind": (_wrong_kind, "exec"),
    "lying-exec-sizes": (_lying_exec_sizes, "exec"),
    "bulk-digest-mismatch": (_bulk_digest_mismatch, "read_file"),
    "bulk-overrun": (_bulk_overrun, "read_file"),
    "unsolicited-bulk": (_unsolicited_bulk, "write_file"),
    "data-frame-first": (_data_frame_first, "read_file"),
    "end-frame-first": (_end_frame_first, "read_file"),
    "duplicate-reply": (_duplicate_reply, "write_file"),
    "trailing-garbage": (_trailing_garbage, "write_file"),
    "truncated-reply": (_truncated_reply, "write_file"),
}


class HostileTransport:
    """A `Transport` whose endpoint answers every request with the configured hostile reply."""

    def __init__(self, scenario: str) -> None:
        self.craft = HOSTILE_GUEST_SCENARIOS[scenario][0]
        self.requests_seen = 0
        self._tasks: set[asyncio.Task[None]] = set()

    async def connect(self, endpoint: str) -> ByteStream:
        client_side, server_side = stream_pair()
        task = asyncio.create_task(self._serve(server_side))
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)
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


def _stage(request: Message, stage: str, rid: str | None = None) -> bytes:
    payload = canonical_json(
        {
            "v": 3,
            "id": rid or request.id,
            "kind": "stage",
            "stage": stage,
            "detail": "",
            "guests": {},
        }
    )
    return _frame(FrameType.CONTROL, payload)


def _stage_wrong_id(request: Message) -> bytes:
    return _stage(request, "fetch", rid="e" * 32)


def _stage_ready_first(request: Message) -> bytes:
    return _stage(request, "ready")


def _stage_spam(request: Message) -> bytes:
    # non-monotonic repetition: the second fetch violates strict stage order
    return _stage(request, "fetch") * 8


def _honest_stages(request: Message) -> bytes:
    frames = b""
    for stage in ("fetch", "construct", "boot", "verify", "ready"):
        frames += _stage(request, stage)
    return frames


HOSTILE_APPLIER_SCENARIOS: dict[str, Callable[[Message], bytes]] = {
    "stage-wrong-id": _stage_wrong_id,
    "stage-ready-first": _stage_ready_first,
    "stage-spam": _stage_spam,
}

HOSTILE_APPLIER_HANGS = ("hang-connect", "no-close-after-ready")
"""Scenarios that previously hung realize forever; now bounded by the budget layers."""


class HostileApplierTransport:
    """A `Transport` whose host-plane endpoint streams forged stage reports or hangs.

    The hang scenarios pin that every realize transport interaction is budget-bounded: `hang-connect` never completes the connection; `no-close-after-ready` streams an honest report sequence and then never closes the stream.
    """

    def __init__(self, scenario: str) -> None:
        self.scenario = scenario
        self.craft = (
            None
            if scenario in HOSTILE_APPLIER_HANGS
            else HOSTILE_APPLIER_SCENARIOS[scenario]
        )
        self._tasks: set[asyncio.Task[None]] = set()

    async def connect(self, endpoint: str) -> ByteStream:
        if self.scenario == "hang-connect":
            await asyncio.Event().wait()  # never set: bounded only by the caller
        client_side, server_side = stream_pair()
        task = asyncio.create_task(self._serve(server_side))
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)
        return client_side

    async def _serve(self, stream: MemoryStream) -> None:
        reader = MessageStreamReader(stream.receive, bulk_cap=DEFAULT_BULK_CAP)
        try:
            request, _ = await reader.next()
        except Exception:
            await stream.aclose()
            return
        if self.scenario == "no-close-after-ready":
            await stream.send(_honest_stages(request))
            await asyncio.Event().wait()  # terminal delivered; close never comes
        assert self.craft is not None
        await stream.send(self.craft(request))
        await stream.aclose()


class SilentTransport:
    """Connects (optionally failing the first `fail_connects` attempts), then never replies."""

    def __init__(self, fail_connects: int = 0) -> None:
        self.fail_connects = fail_connects

    async def connect(self, endpoint: str) -> ByteStream:
        if self.fail_connects > 0:
            self.fail_connects -= 1
            raise ConnectionError("injected connect failure")
        client_side, _server_side = stream_pair()
        return client_side  # nothing ever serves the other end


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


class DribbleStream:
    """Delivers received bytes one at a time: arbitrary chunk boundaries, worst case."""

    def __init__(self, inner: ByteStream) -> None:
        self._inner = inner
        self._pending = bytearray()

    async def send(self, data: bytes) -> None:
        await self._inner.send(data)

    async def receive(self) -> bytes:
        if not self._pending:
            self._pending.extend(await self._inner.receive())
            if not self._pending:
                return b""
        byte = self._pending[:1]
        del self._pending[:1]
        return bytes(byte)

    async def aclose(self) -> None:
        await self._inner.aclose()


class DribbleTransport:
    """Wraps a transport so every reply arrives byte by byte (reader robustness pinning)."""

    def __init__(self, inner: Transport) -> None:
        self._inner = inner

    async def connect(self, endpoint: str) -> ByteStream:
        return DribbleStream(await self._inner.connect(endpoint))

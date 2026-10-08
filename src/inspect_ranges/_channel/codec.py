"""Framing codec for protocol v3: length-prefixed frames with explicit chunking.

A message is one CONTROL frame (canonical JSON, validated against `protocol.Message`), followed, when the control payload declares `data_size`, by DATA frames carrying at most `MAX_FRAME_PAYLOAD` bytes each and one END frame whose payload records the bulk's size and sha256. Chunking is explicit because the virtio viosock send cap (32 KiB) makes implicit chunking a trap.

Everything read is untrusted input: length fields are checked against caps before buffering, bulk is capped reader-side regardless of what the sender declared, the END digest is verified, and every malformed input becomes a typed `DecodeError`; neither `json` nor `pydantic` exceptions escape this module.

Debuggability: encode and decode accept a trace hook receiving one `TraceEvent` per frame and per completed message (direction, type, sizes, message kind and request id, bulk digest). Channels keep a bounded trace tail and dump it on failure.
"""

import hashlib
import json
import struct
import time
from collections.abc import Awaitable, Callable, Iterator
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any, Literal, cast

from pydantic import ValidationError

from .protocol import (
    MAX_BULK_DECLARABLE,
    MESSAGE_ADAPTER,
    PROTOCOL_VERSION,
    Message,
    declared_bulk,
)
from .protocol import MAX_FRAME_PAYLOAD as MAX_FRAME_PAYLOAD

_HEADER = struct.Struct(">IB")

MAX_CONTROL_PAYLOAD = MAX_FRAME_PAYLOAD
"""A control payload is exactly one frame; anything larger is an encode error, not a split."""


class FrameType(IntEnum):
    """Frame discriminator byte."""

    CONTROL = 0x43
    DATA = 0x44
    END = 0x45


TraceDirection = Literal["send", "recv"]
TraceFrame = Literal["CONTROL", "DATA", "END", "message"]


@dataclass(frozen=True)
class TraceEvent:
    """One codec-level trace record; `note` carries the END digest or decode-error name."""

    direction: TraceDirection
    frame: TraceFrame
    size: int
    kind: str | None = None
    request_id: str | None = None
    note: str = ""
    t: float = field(default_factory=time.monotonic)


TraceHook = Callable[[TraceEvent], None]


class EncodeError(Exception):
    """The caller asked the codec to encode something the protocol cannot carry."""


class DecodeError(Exception):
    """Base for everything a malformed or hostile byte stream can produce."""


class FrameTooLarge(DecodeError):
    """A header's length field exceeds the frame payload cap (checked before buffering)."""


class TruncatedFrame(DecodeError):
    """The stream ended mid-frame."""


class ChannelClosed(Exception):
    """The stream ended cleanly at a message boundary: loss or completion, never malformed input."""


class ProtocolViolation(DecodeError):
    """Frames arrived in an order or shape an honest endpoint cannot produce."""


class InvalidMessage(DecodeError):
    """A control payload failed JSON parsing or strict schema validation."""


class BulkOverrun(DecodeError):
    """Bulk bytes exceeded the reader's cap (the declared size is never trusted)."""


class BulkMismatch(DecodeError):
    """The END frame's size or sha256 does not match the received bulk."""


def canonical_json(payload: dict[str, Any]) -> bytes:
    """Encode `payload` as canonical JSON: sorted keys, compact separators, UTF-8 (never ASCII-escaped); null-valued optional fields are omitted by the message encoder."""
    return json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode()


def _frame(frame_type: FrameType, payload: bytes) -> bytes:
    return _HEADER.pack(len(payload), frame_type) + payload


def encode_message(
    message: Message, bulk: bytes | None = None, *, trace: TraceHook | None = None
) -> list[bytes]:
    """Encode one message (and its bulk) into wire frames.

    Args:
        message: The validated message to send.
        bulk: Out-of-band bytes; must be present exactly when the message declares `data_size`, with the matching length.
        trace: Optional per-frame trace hook.

    Returns:
        The frames, in send order.

    Raises:
        EncodeError: The bulk does not match the declaration, or the control payload exceeds one frame.
    """
    declared = declared_bulk(message)
    if declared is None and bulk is not None:
        raise EncodeError(f"{message.kind}: bulk supplied but data_size is None")
    if declared is not None:
        if bulk is None:
            raise EncodeError(
                f"{message.kind}: data_size={declared} but no bulk supplied"
            )
        if len(bulk) != declared:
            raise EncodeError(
                f"{message.kind}: data_size={declared} but bulk is {len(bulk)} bytes"
            )
    payload = canonical_json(message.model_dump(mode="json", exclude_none=True))
    if len(payload) > MAX_CONTROL_PAYLOAD:
        raise EncodeError(
            f"{message.kind}: control payload {len(payload)} bytes exceeds {MAX_CONTROL_PAYLOAD}"
        )
    frames = [_frame(FrameType.CONTROL, payload)]
    if trace:
        trace(
            TraceEvent(
                "send",
                "CONTROL",
                len(payload),
                kind=message.kind,
                request_id=message.id,
            )
        )
    if declared is not None:
        assert bulk is not None
        for offset in range(0, declared, MAX_FRAME_PAYLOAD):
            chunk = bulk[offset : offset + MAX_FRAME_PAYLOAD]
            frames.append(_frame(FrameType.DATA, chunk))
            if trace:
                trace(TraceEvent("send", "DATA", len(chunk), request_id=message.id))
        digest = hashlib.sha256(bulk).hexdigest()
        end_payload = canonical_json({"sha256": digest, "size": declared})
        frames.append(_frame(FrameType.END, end_payload))
        if trace:
            trace(
                TraceEvent(
                    "send", "END", len(end_payload), request_id=message.id, note=digest
                )
            )
    if trace:
        trace(
            TraceEvent(
                "send",
                "message",
                len(payload) + (declared or 0),
                kind=message.kind,
                request_id=message.id,
            )
        )
    return frames


class FrameBuffer:
    """Incremental frame parser over an untrusted byte stream.

    Feed bytes with `feed`; drain complete frames with `frames`. Mark the stream closed with `close`, after which a partial buffered frame is a `TruncatedFrame`.
    """

    def __init__(self) -> None:
        self._buffer = bytearray()
        self._closed = False

    def feed(self, data: bytes) -> None:
        if data:
            self._buffer.extend(data)

    def close(self) -> None:
        self._closed = True

    @property
    def pending(self) -> bool:
        """Whether buffered bytes are waiting (a partial or complete frame)."""
        return bool(self._buffer)

    def frames(self) -> Iterator[tuple[FrameType, bytes]]:
        """Yield every complete buffered frame.

        Raises:
            FrameTooLarge: A length field exceeds the payload cap (raised before the payload is buffered in full).
            ProtocolViolation: An unknown frame type byte.
            TruncatedFrame: The stream closed mid-frame.
        """
        while True:
            if len(self._buffer) < _HEADER.size:
                break
            length, type_byte = _HEADER.unpack_from(self._buffer)
            if length > MAX_FRAME_PAYLOAD:
                raise FrameTooLarge(
                    f"frame declares {length} bytes (cap {MAX_FRAME_PAYLOAD})"
                )
            try:
                frame_type = FrameType(type_byte)
            except ValueError:
                raise ProtocolViolation(
                    f"unknown frame type byte 0x{type_byte:02x}"
                ) from None
            if len(self._buffer) < _HEADER.size + length:
                break
            payload = bytes(self._buffer[_HEADER.size : _HEADER.size + length])
            del self._buffer[: _HEADER.size + length]
            yield frame_type, payload
        if self._closed and self._buffer:
            raise TruncatedFrame(
                f"stream ended with {len(self._buffer)} buffered bytes mid-frame"
            )


class MessageAssembler:
    """Assemble validated messages (and bulk) from a frame sequence.

    One assembler per stream direction. Push frames with `push`; it returns a completed `(message, bulk)` pair or `None` while more frames are needed.
    """

    def __init__(self, *, bulk_cap: int, trace: TraceHook | None = None) -> None:
        self._bulk_cap = bulk_cap
        self._trace = trace
        self._message: Message | None = None
        self._bulk = bytearray()

    @property
    def in_flight(self) -> bool:
        """Whether a control frame has arrived whose bulk is still incomplete."""
        return self._message is not None

    def push(
        self, frame_type: FrameType, payload: bytes
    ) -> tuple[Message, bytes | None] | None:
        """Consume one frame.

        Raises:
            InvalidMessage: The control payload is not a valid v3 message.
            ProtocolViolation: Frame order or bulk accounting an honest endpoint cannot produce.
            BulkOverrun: Received bulk exceeded the reader's cap.
            BulkMismatch: END size or digest disagrees with the received bulk.
        """
        if self._message is None:
            if frame_type is not FrameType.CONTROL:
                raise ProtocolViolation(
                    f"expected CONTROL frame, got {frame_type.name}"
                )
            message = _parse_control(payload)
            if self._trace:
                self._trace(
                    TraceEvent(
                        "recv",
                        "CONTROL",
                        len(payload),
                        kind=message.kind,
                        request_id=message.id,
                    )
                )
            if declared_bulk(message) is None:
                self._emit_message_trace(message, 0)
                return message, None
            self._message = message
            self._bulk.clear()
            return None
        message = self._message
        declared = declared_bulk(message)
        assert declared is not None
        if frame_type is FrameType.DATA:
            if self._trace:
                self._trace(
                    TraceEvent(
                        "recv",
                        "DATA",
                        len(payload),
                        kind=message.kind,
                        request_id=message.id,
                    )
                )
            if len(self._bulk) + len(payload) > min(declared, self._bulk_cap):
                if len(self._bulk) + len(payload) > self._bulk_cap:
                    raise BulkOverrun(
                        f"{message.kind} id={message.id}: bulk exceeds reader cap {self._bulk_cap}"
                    )
                raise ProtocolViolation(
                    f"{message.kind} id={message.id}: bulk exceeds declared data_size={declared}"
                )
            self._bulk.extend(payload)
            return None
        if frame_type is FrameType.END:
            end_sha256, end_size = _parse_end(payload)
            bulk = bytes(self._bulk)
            self._message = None
            self._bulk = bytearray()
            if end_size != len(bulk) or len(bulk) != declared:
                raise BulkMismatch(
                    f"{message.kind} id={message.id}: declared={declared} received={len(bulk)} end={end_size}"
                )
            digest = hashlib.sha256(bulk).hexdigest()
            if digest != end_sha256:
                raise BulkMismatch(
                    f"{message.kind} id={message.id}: bulk sha256 mismatch"
                )
            if self._trace:
                self._trace(
                    TraceEvent(
                        "recv",
                        "END",
                        len(payload),
                        kind=message.kind,
                        request_id=message.id,
                        note=digest,
                    )
                )
            self._emit_message_trace(message, len(bulk))
            return message, bulk
        raise ProtocolViolation(
            f"unexpected {frame_type.name} frame inside bulk transfer"
        )

    def _emit_message_trace(self, message: Message, bulk_size: int) -> None:
        if self._trace:
            self._trace(
                TraceEvent(
                    "recv",
                    "message",
                    bulk_size,
                    kind=message.kind,
                    request_id=message.id,
                )
            )


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    # duplicate keys parse last-wins in Python but differ across language
    # parsers; an honest endpoint never emits them, so refuse outright
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key {key!r}")
        result[key] = value
    return result


def _parse_control(payload: bytes) -> Message:
    try:
        data = json.loads(payload, object_pairs_hook=_reject_duplicate_keys)
    except (ValueError, UnicodeDecodeError) as error:
        raise InvalidMessage(f"control payload is not JSON: {error}") from None
    # the schema defaults v for construction ergonomics; the wire requires it:
    # an honest endpoint always emits its version, so absence is a tamper tell
    version: object = (
        cast(dict[Any, Any], data).get("v") if isinstance(data, dict) else None
    )
    if version != PROTOCOL_VERSION:
        raise InvalidMessage(
            f"control payload must carry v={PROTOCOL_VERSION}, got {version!r}"
        )
    try:
        return MESSAGE_ADAPTER.validate_python(data)
    except ValidationError as error:
        first = error.errors(include_url=False)[0]
        location = ".".join(str(part) for part in first.get("loc", ()))
        raise InvalidMessage(
            f"schema violation at {location or '<root>'}: {first['msg']}"
        ) from None


def _parse_end(payload: bytes) -> tuple[str, int]:
    """Parse an END payload into (sha256, size); strictly shaped, duplicate keys refused."""
    try:
        data: Any = json.loads(payload, object_pairs_hook=_reject_duplicate_keys)
    except (ValueError, UnicodeDecodeError) as error:
        raise InvalidMessage(f"END payload is not JSON: {error}") from None
    if isinstance(data, dict):
        entries = cast(dict[Any, Any], data)
        sha256 = entries.get("sha256")
        size = entries.get("size")
        if (
            set(entries) == {"sha256", "size"}
            and isinstance(sha256, str)
            and len(sha256) == 64
            and all(c in "0123456789abcdef" for c in sha256)
            and isinstance(size, int)
            and not isinstance(size, bool)
            and 0 <= size <= MAX_BULK_DECLARABLE
        ):
            return sha256, size
    raise InvalidMessage("END payload must be exactly {sha256, size}")


def decode_frames(
    data: bytes, *, bulk_cap: int, trace: TraceHook | None = None
) -> list[tuple[Message, bytes | None]]:
    """Decode a complete byte string into messages (test and vector helper).

    Raises:
        DecodeError: Any malformed input, as the matching subclass.
    """
    buffer = FrameBuffer()
    assembler = MessageAssembler(bulk_cap=bulk_cap, trace=trace)
    buffer.feed(data)
    buffer.close()
    messages: list[tuple[Message, bytes | None]] = []
    for frame_type, payload in buffer.frames():
        completed = assembler.push(frame_type, payload)
        if completed is not None:
            messages.append(completed)
    if assembler.in_flight:
        raise TruncatedFrame("stream ended mid-message (bulk incomplete)")
    return messages


class MessageStreamReader:
    """Read a sequence of messages from one async byte source.

    Suitable both for one-message-per-connection flows (per-operation connect) and multi-message streams (stage reports). Each `next` call returns one validated `(message, bulk)` pair; bytes of a following message stay buffered for the next call.
    """

    def __init__(
        self,
        receive: Callable[[], Awaitable[bytes]],
        *,
        bulk_cap: int,
        trace: TraceHook | None = None,
    ) -> None:
        self._receive = receive
        self._buffer = FrameBuffer()
        self._assembler = MessageAssembler(bulk_cap=bulk_cap, trace=trace)
        self._eof = False

    async def next(self) -> tuple[Message, bytes | None]:
        """Read the next message.

        Raises:
            ChannelClosed: EOF at a message boundary.
            TruncatedFrame: EOF mid-frame or mid-message.
            DecodeError: Any other malformed input, as the matching subclass.
        """
        while True:
            for frame_type, payload in self._buffer.frames():
                completed = self._assembler.push(frame_type, payload)
                if completed is not None:
                    return completed
            if self._eof:
                if self._assembler.in_flight:
                    raise TruncatedFrame("stream ended mid-message")
                raise ChannelClosed("stream closed at a message boundary")
            chunk = await self._receive()
            if not chunk:
                self._eof = True
                self._buffer.close()
                # one more drain pass: close() arms the mid-frame truncation check
                continue
            self._buffer.feed(chunk)


async def read_message(
    receive: Callable[[], Awaitable[bytes]],
    *,
    bulk_cap: int,
    trace: TraceHook | None = None,
) -> tuple[Message, bytes | None]:
    """Read exactly one message from an async byte source (per-operation connect flows).

    Raises:
        ChannelClosed: EOF before any frame arrived.
        DecodeError: Any malformed input, as the matching subclass.
    """
    return await MessageStreamReader(receive, bulk_cap=bulk_cap, trace=trace).next()

"""Slice 1 battery: protocol v3 schemas and the framing codec.

The wire vectors pin the encoding byte-exactly for every codec implementation; the malformed-input table pins that hostile bytes always become typed `DecodeError`s, never escaping exceptions.
"""

import asyncio
import hashlib
import json
import struct
from pathlib import Path
from typing import Any

import pytest
from inspect_ranges._channel import codec
from inspect_ranges._channel import protocol as p
from pydantic import ValidationError

VECTORS_PATH = Path(__file__).parent / "wire_vectors" / "v3.json"
VECTORS: list[dict[str, Any]] = json.loads(VECTORS_PATH.read_text())["vectors"]

RID = "a" * 32


def _vector_message(vector: dict[str, Any]) -> p.Message:
    return p.MESSAGE_ADAPTER.validate_python(vector["message"])


def _vector_bulk(vector: dict[str, Any]) -> bytes | None:
    bulk_hex = vector["bulk_hex"]
    return bytes.fromhex(bulk_hex) if bulk_hex is not None else None


def test_vectors_cover_every_message_kind() -> None:
    covered = {vector["message"]["kind"] for vector in VECTORS}
    assert covered == set(p.ALL_MESSAGE_KINDS), (
        f"vectors missing kinds: {set(p.ALL_MESSAGE_KINDS) - covered}"
    )


@pytest.mark.parametrize("vector", VECTORS, ids=[v["name"] for v in VECTORS])
def test_vector_encodes_byte_exactly(vector: dict[str, Any]) -> None:
    frames = codec.encode_message(_vector_message(vector), _vector_bulk(vector))
    assert [frame.hex() for frame in frames] == vector["frames_hex"]


@pytest.mark.parametrize("vector", VECTORS, ids=[v["name"] for v in VECTORS])
def test_vector_decodes_byte_exactly(vector: dict[str, Any]) -> None:
    data = b"".join(bytes.fromhex(frame) for frame in vector["frames_hex"])
    [(message, bulk)] = codec.decode_frames(data, bulk_cap=p.DEFAULT_BULK_CAP)
    assert message == _vector_message(vector)
    assert bulk == _vector_bulk(vector)


def _frames(message: p.Message, bulk: bytes | None = None) -> bytes:
    return b"".join(codec.encode_message(message, bulk))


def _end_frame(payload: bytes) -> bytes:
    return struct.pack(">IB", len(payload), codec.FrameType.END) + payload


def _data_frame(payload: bytes) -> bytes:
    return struct.pack(">IB", len(payload), codec.FrameType.DATA) + payload


def _control_frame(payload: bytes) -> bytes:
    return struct.pack(">IB", len(payload), codec.FrameType.CONTROL) + payload


_PING = _frames(p.PingRequest(id=RID))
_WRITE = p.WriteFileRequest(id=RID, path="/tmp/f", data_size=10)
_WRITE_FRAMES = codec.encode_message(_WRITE, b"0123456789")


def _bad_end() -> bytes:
    good = _WRITE_FRAMES
    end_payload = codec.canonical_json(
        {"sha256": hashlib.sha256(b"different").hexdigest(), "size": 10}
    )
    return b"".join(good[:-1]) + _end_frame(end_payload)


def _short_end_size() -> bytes:
    good = _WRITE_FRAMES
    end_payload = codec.canonical_json(
        {"sha256": hashlib.sha256(b"0123456789").hexdigest(), "size": 9}
    )
    return b"".join(good[:-1]) + _end_frame(end_payload)


MALFORMED: list[tuple[str, bytes, type[codec.DecodeError]]] = [
    ("truncated-header", _PING[:3], codec.TruncatedFrame),
    ("truncated-payload", _PING[:-2], codec.TruncatedFrame),
    (
        "length-field-lies-large",
        struct.pack(">IB", 1 << 20, codec.FrameType.CONTROL) + b"{}",
        codec.FrameTooLarge,
    ),
    (
        "unknown-frame-type",
        struct.pack(">IB", 2, 0x5A) + b"{}",
        codec.ProtocolViolation,
    ),
    ("not-json", _control_frame(b"\xff\xfe not json"), codec.InvalidMessage),
    (
        "duplicate-json-keys",
        _control_frame(
            b'{"v":3,"id":"' + RID.encode() + b'","kind":"ping","kind":"ping"}'
        ),
        codec.InvalidMessage,
    ),
    ("json-not-object", _control_frame(b"[1,2]"), codec.InvalidMessage),
    (
        "unknown-kind",
        _control_frame(codec.canonical_json({"v": 3, "id": RID, "kind": "evil"})),
        codec.InvalidMessage,
    ),
    (
        "extra-field",
        _control_frame(
            codec.canonical_json({"v": 3, "id": RID, "kind": "ping", "x": 1})
        ),
        codec.InvalidMessage,
    ),
    (
        "wrong-type-field",
        _control_frame(
            codec.canonical_json(
                {"v": 3, "id": RID, "kind": "error", "errno": 5, "message": "x"}
            )
        ),
        codec.InvalidMessage,
    ),
    (
        "bad-request-id",
        _control_frame(codec.canonical_json({"v": 3, "id": "Z" * 32, "kind": "ping"})),
        codec.InvalidMessage,
    ),
    ("data-without-declaration", _data_frame(b"x"), codec.ProtocolViolation),
    ("end-as-first-frame", _end_frame(b"{}"), codec.ProtocolViolation),
    ("empty-control-payload", _control_frame(b""), codec.InvalidMessage),
    (
        "missing-v",
        _control_frame(codec.canonical_json({"id": RID, "kind": "ping"})),
        codec.InvalidMessage,
    ),
    (
        "v-too-old",
        _control_frame(codec.canonical_json({"v": 2, "id": RID, "kind": "ping"})),
        codec.InvalidMessage,
    ),
    (
        "v-too-new",
        _control_frame(codec.canonical_json({"v": 4, "id": RID, "kind": "ping"})),
        codec.InvalidMessage,
    ),
    (
        "huge-integer-field",
        _control_frame(
            codec.canonical_json(
                {"v": 3, "id": RID, "kind": "heartbeat", "uptime_ms": 10**30}
            )
        ),
        codec.InvalidMessage,
    ),
    (
        "data-beyond-declared",
        b"".join(_WRITE_FRAMES[:1]) + _data_frame(b"0" * 11),
        codec.ProtocolViolation,
    ),
    ("end-digest-mismatch", _bad_end(), codec.BulkMismatch),
    ("end-size-mismatch", _short_end_size(), codec.BulkMismatch),
    (
        "duplicate-keys-in-end",
        b"".join(_WRITE_FRAMES[:-1])
        + _end_frame(b'{"sha256":"' + (b"0" * 64) + b'","size":10,"size":10}'),
        codec.InvalidMessage,
    ),
    (
        "end-payload-garbage",
        b"".join(_WRITE_FRAMES[:-1]) + _end_frame(b"{}"),
        codec.InvalidMessage,
    ),
    (
        "control-inside-bulk",
        b"".join(_WRITE_FRAMES[:1]) + _PING,
        codec.ProtocolViolation,
    ),
    ("stream-ends-mid-bulk", b"".join(_WRITE_FRAMES[:2]), codec.TruncatedFrame),
]


@pytest.mark.parametrize(
    ("data", "expected"),
    [(data, expected) for _, data, expected in MALFORMED],
    ids=[name for name, _, _ in MALFORMED],
)
def test_malformed_input_raises_typed_decode_error(
    data: bytes, expected: type[codec.DecodeError]
) -> None:
    with pytest.raises(expected):
        codec.decode_frames(data, bulk_cap=p.DEFAULT_BULK_CAP)


def test_bulk_reader_cap_enforced_before_declared_size() -> None:
    """The reader's cap wins over the sender's declaration (never trust a length field)."""
    big = p.WriteFileRequest(id=RID, path="/tmp/f", data_size=100_000)
    data = b"".join(codec.encode_message(big, b"x" * 100_000))
    with pytest.raises(codec.BulkOverrun):
        codec.decode_frames(data, bulk_cap=64 * 1024)


def test_decode_tolerates_non_canonical_key_order() -> None:
    """Decoding accepts any key order; only encoding is canonical."""
    payload = json.dumps({"kind": "ping", "id": RID, "v": 3}).encode()
    [(message, _)] = codec.decode_frames(
        _control_frame(payload), bulk_cap=p.DEFAULT_BULK_CAP
    )
    assert message.kind == "ping"


@pytest.mark.parametrize(
    "size", [0, 1, codec.MAX_FRAME_PAYLOAD, codec.MAX_FRAME_PAYLOAD + 1]
)
def test_bulk_chunk_boundaries_round_trip(size: int) -> None:
    bulk = bytes(i % 251 for i in range(size))
    message = p.WriteFileRequest(id=RID, path="/tmp/f", data_size=size)
    frames = codec.encode_message(message, bulk)
    expected_data_frames = (
        size + codec.MAX_FRAME_PAYLOAD - 1
    ) // codec.MAX_FRAME_PAYLOAD
    assert len(frames) == 1 + expected_data_frames + 1
    [(decoded, decoded_bulk)] = codec.decode_frames(
        b"".join(frames), bulk_cap=p.DEFAULT_BULK_CAP
    )
    assert decoded == message
    assert decoded_bulk == bulk


def test_encode_rejects_bulk_declaration_mismatch() -> None:
    message = p.WriteFileRequest(id=RID, path="/tmp/f", data_size=5)
    with pytest.raises(codec.EncodeError):
        codec.encode_message(message, b"1234")
    with pytest.raises(codec.EncodeError):
        codec.encode_message(message, None)
    with pytest.raises(codec.EncodeError):
        codec.encode_message(p.PingRequest(id=RID), b"stray")


def test_encode_rejects_oversized_control_payload() -> None:
    message = p.ExecRequest(id=RID, cmd=["echo", "x" * (codec.MAX_CONTROL_PAYLOAD + 1)])
    with pytest.raises(codec.EncodeError):
        codec.encode_message(message)


SCHEMA_REJECTS: list[tuple[str, dict[str, Any]]] = [
    (
        "write-without-data-size",
        {"v": 3, "id": RID, "kind": "write_file", "path": "/f"},
    ),
    (
        "exec-result-size-mismatch",
        {
            "v": 3,
            "id": RID,
            "kind": "exec_result",
            "rc": 0,
            "stdout_size": 3,
            "stderr_size": 1,
            "data_size": 3,
        },
    ),
    (
        "file-data-size-mismatch",
        {"v": 3, "id": RID, "kind": "file_data", "size": 2, "data_size": 3},
    ),
    (
        "bad-errno-shape",
        {"v": 3, "id": RID, "kind": "error", "errno": "enoent", "message": "x"},
    ),
    (
        "negative-data-size",
        {"v": 3, "id": RID, "kind": "write_file", "path": "/f", "data_size": -1},
    ),
    (
        "bad-bundle-digest",
        {"v": 3, "id": RID, "kind": "realize", "bundle_digest": "nope"},
    ),
    (
        "float-budget",
        {
            "v": 3,
            "id": RID,
            "kind": "exec",
            "cmd": ["true"],
            "budget": {"command_ms": 1.5},
        },
    ),
    ("empty-cmd", {"v": 3, "id": RID, "kind": "exec", "cmd": []}),
    ("bulk-on-bulkless-kind", {"v": 3, "id": RID, "kind": "ok", "data_size": 4}),
    (
        "budget-error-without-layer",
        {"v": 3, "id": RID, "kind": "error", "errno": "ETIME", "message": "x"},
    ),
    (
        "rc-outside-int32",
        {
            "v": 3,
            "id": RID,
            "kind": "exec_result",
            "rc": 2**31,
            "stdout_size": 0,
            "stderr_size": 0,
        },
    ),
]


@pytest.mark.parametrize(
    "payload",
    [payload for _, payload in SCHEMA_REJECTS],
    ids=[name for name, _ in SCHEMA_REJECTS],
)
def test_schema_rejects_dishonest_messages(payload: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        p.MESSAGE_ADAPTER.validate_python(payload)


def test_trace_hook_sees_frames_and_messages() -> None:
    events: list[codec.TraceEvent] = []
    message = p.WriteFileRequest(id=RID, path="/tmp/f", data_size=3)
    frames = codec.encode_message(message, b"abc", trace=events.append)
    sent = [(event.frame, event.direction) for event in events]
    assert sent == [
        ("CONTROL", "send"),
        ("DATA", "send"),
        ("END", "send"),
        ("message", "send"),
    ]
    assert events[0].kind == "write_file" and events[0].request_id == RID
    assert len(events[2].note) == 64  # END carries the bulk digest

    events.clear()
    codec.decode_frames(b"".join(frames), bulk_cap=1 << 20, trace=events.append)
    received = [event.frame for event in events if event.direction == "recv"]
    assert received[0] == "CONTROL" and received[-1] == "message"


def test_stream_reader_handles_split_and_coalesced_chunks() -> None:
    """Messages survive arbitrary chunk boundaries, and a clean EOF is ChannelClosed."""
    stream = _PING + b"".join(_WRITE_FRAMES) + _PING

    async def run(chunk_size: int) -> list[str]:
        offset = 0

        async def receive() -> bytes:
            nonlocal offset
            chunk = stream[offset : offset + chunk_size]
            offset += chunk_size
            return chunk

        reader = codec.MessageStreamReader(receive, bulk_cap=p.DEFAULT_BULK_CAP)
        kinds: list[str] = []
        while True:
            try:
                message, _ = await reader.next()
            except codec.ChannelClosed:
                return kinds
            kinds.append(message.kind)

    for chunk_size in (1, 7, len(stream)):
        kinds = asyncio.run(run(chunk_size))
        assert kinds == ["ping", "write_file", "ping"], f"chunk_size={chunk_size}"


def test_stream_reader_truncation_mid_message_is_typed() -> None:
    stream = b"".join(_WRITE_FRAMES[:2])  # control + first data, no END

    async def run() -> None:
        offset = 0

        async def receive() -> bytes:
            nonlocal offset
            chunk = stream[offset : offset + 64]
            offset += 64
            return chunk

        reader = codec.MessageStreamReader(receive, bulk_cap=p.DEFAULT_BULK_CAP)
        await reader.next()

    with pytest.raises(codec.TruncatedFrame):
        asyncio.run(run())

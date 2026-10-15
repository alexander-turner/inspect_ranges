"""Evidence manifest format: hash-chained, write-once, verifiable offline.

A sample's evidence location holds write-once objects only: chunk objects under `chunks/<stream>/<seq>.bin` and, per writer, sequence-numbered manifest parts under `manifests/<writer>/part-<n>.json` plus one terminal `manifests/<writer>/seal.json`. Nothing at a location is ever rewritten; S3 has no append, and a re-put manifest object would be exactly the rewrite the format exists to detect (evidence-v1.md).

Tamper evidence is a property of this format, not of the store. Every manifest record (chunk entry or gap) carries a `chain` field computed as `sha256(prev_chain || canonical_bytes(record minus chain))`, where the genesis value is derived from the writer and stream names, so a record cannot be transplanted across streams or writers. The chain covers the record's metadata (stream, sequence, digest, size, clock span), not merely the chunk digest: a chain over digests alone would leave timestamps and spans rewritable. Gap records occupy stream sequence numbers exactly like chunks, so a gap is inside the chain, in order, and a forged or out-of-sequence gap breaks replay.

The seal closes a writer's record: per-stream chain heads and counts, the manifest part count, and the flush status. Its canonical digest (`seal_digest`) is what the driver writes into the Inspect sample store, binding the eval log to this evidence record. The format's own guarantee stops at that boundary: the chain anchors everything at or below the seal, while the seal tier itself (its fields, its presence, the record's location) is unanchored until someone holds the seal digest externally, which is exactly what the sample-store binding provides and what `verify --expect-seal` checks; an unsealed record is extendable as well as truncatable. `inspect-ranges evidence verify` replays the chain offline and names the first break; see `reader.py`.

Clock stamps are dual-basis per evidence-v1.md: wall time (unix seconds) for cross-machine correlation and monotonic seconds for in-host ordering across wall-clock steps. Capture-side records carry the range host's clocks; driver-side records carry the driver's; offset pairs land in the `clock` stream.
"""

import hashlib
import json
import re
import time
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, StringConstraints

from .._channel.protocol import Sha256Hex

STREAM_NAME_PATTERN = r"^[a-z0-9][a-z0-9._-]*(/[a-z0-9][a-z0-9._-]*)?$"
"""Stream names: one segment (`console/web` style streams use exactly one `/`). Kept key-safe for both filesystems and S3."""

WRITER_NAME_PATTERN = r"^[a-z0-9][a-z0-9._-]*$"
"""Writer identities (`host`, `driver`); one path segment, key-safe."""

StreamName = Annotated[str, StringConstraints(pattern=STREAM_NAME_PATTERN)]
WriterName = Annotated[str, StringConstraints(pattern=WRITER_NAME_PATTERN)]

SealStatus = Literal["complete", "incomplete", "reaped"]
"""`complete`: sealed through the normal finalize path with no unflushed remainder; data lost to in-chain gaps (`buffer-cap` drops, `write-once-conflict`) still seals `complete` because the loss is recorded in the chain and inventoried at verify. `incomplete`: data was lost and recorded as in-chain gaps: an unflushed remainder at seal time, or a per-sample volume-cap breach (`evidence-cap` gaps) during the run. `reaped`: sealed by the reaper after the driver died; the record is honest up to its last delivered part."""


class EvidenceModel(BaseModel):
    """Strict base: unknown keys are errors everywhere in the format."""

    model_config = ConfigDict(extra="forbid")


class ClockStamp(EvidenceModel):
    """One reading of a writer's clocks.

    `wall` is unix seconds (UTC); `monotonic` is the same process's monotonic clock, present on capture-side and driver-side records alike so ordering survives wall-clock steps.
    """

    wall: float
    monotonic: float | None = None


def clock_now() -> ClockStamp:
    """The current process's dual-clock stamp."""
    return ClockStamp(wall=time.time(), monotonic=time.monotonic())


class ClockSpan(EvidenceModel):
    """The capture interval a record covers (point records use start == end)."""

    start: ClockStamp
    end: ClockStamp


class ChunkRecord(EvidenceModel):
    """One delivered write-once chunk of a stream."""

    kind: Literal["chunk"] = "chunk"
    stream: StreamName
    seq: int = Field(ge=0)
    """Per-stream sequence number, contiguous from 0 across chunks AND gaps."""
    sha256: Sha256Hex
    size: int = Field(ge=0)
    span: ClockSpan
    chain: Sha256Hex


class GapRecord(EvidenceModel):
    """An explicit hole in a stream: data that existed but was not delivered.

    Gaps occupy a stream sequence slot and are chained like chunks, so they are inside the chain, not beside it. The forbidden behavior is losing data without one of these.
    """

    kind: Literal["gap"] = "gap"
    stream: StreamName
    seq: int = Field(ge=0)
    span: ClockSpan
    cause: str
    """Why the data is gone, e.g. `buffer-cap`, `write-failed`, `unflushed`."""
    dropped: int = Field(ge=0)
    """Bytes dropped, when known (0 means unknown)."""
    chain: Sha256Hex


ManifestRecord = Annotated[ChunkRecord | GapRecord, Field(discriminator="kind")]


class ManifestPart(EvidenceModel):
    """One write-once batch of manifest records, numbered contiguously per writer."""

    writer: WriterName
    part: int = Field(ge=0)
    records: list[ManifestRecord]


class StreamSummary(EvidenceModel):
    """A stream's totals and final chain head, as recorded in the seal."""

    chain: Sha256Hex
    records: int = Field(ge=0)
    chunks: int = Field(ge=0)
    gaps: int = Field(ge=0)
    size: int = Field(ge=0)
    """Delivered chunk bytes (dropped bytes are in the gaps, not here)."""


class Seal(EvidenceModel):
    """The terminal record closing a writer's chains.

    `seal_digest` of this model is the value the driver records in the Inspect sample store (with the evidence pointer and chain heads), making the eval log and the evidence record mutually verifying.
    """

    kind: Literal["seal"] = "seal"
    writer: WriterName
    status: SealStatus
    lease_id: str | None = None
    sample_id: str | None = None
    parts: int = Field(ge=0)
    streams: dict[StreamName, StreamSummary]
    unflushed: int = Field(ge=0, default=0)
    """Buffered bytes recorded as `unflushed` gaps at seal time (status `incomplete`)."""
    worst_watermark_lag_s: float | None = None
    sealed_at: ClockStamp


def canonical_bytes(model: BaseModel, *, exclude: set[str] | None = None) -> bytes:
    """Deterministic serialization used for chaining and digests.

    JSON with sorted keys, no whitespace, and ASCII escaping over the model's JSON-mode dump; the digest of a record is stable across processes and pydantic re-parses. Deliberately distinct from `_channel/codec.py`'s `canonical_json` (which pins `ensure_ascii=False` for the wire): this encoder's bytes are baked into every chain value and seal digest, so its parameters are pinned here and must never drift toward the channel's.
    """
    data: dict[str, Any] = model.model_dump(mode="json", exclude=exclude)
    return json.dumps(
        data, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode()


def chain_genesis(writer: str, stream: str) -> str:
    """The chain's starting value, bound to writer and stream so records cannot transplant across either."""
    seed = f"inspect-ranges-evidence-v1:{writer}:{stream}"
    return hashlib.sha256(seed.encode()).hexdigest()


def chain_next(prev: str, record: ChunkRecord | GapRecord) -> str:
    """The chain value a record must carry, given its predecessor's.

    Hashes the previous chain value concatenated with the record's canonical bytes excluding the `chain` field itself; everything else in the record (metadata included) is covered.
    """
    digest = hashlib.sha256()
    digest.update(bytes.fromhex(prev))
    digest.update(canonical_bytes(record, exclude={"chain"}))
    return digest.hexdigest()


def seal_digest(seal: Seal) -> str:
    """The canonical digest of a seal: what binds the eval log to this evidence record."""
    return hashlib.sha256(canonical_bytes(seal)).hexdigest()


def chunk_key(writer: str, stream: str, seq: int) -> str:
    """The write-once object key for a stream chunk.

    Namespaced by writer (like the manifests) so two writers at one location cannot collide even if they break the disjoint-streams convention: isolation is mechanism, not contract.
    """
    check_name(writer, WRITER_NAME_PATTERN, "writer")
    check_name(stream, STREAM_NAME_PATTERN, "stream")
    return f"chunks/{writer}/{stream}/{seq:06d}.bin"


def part_key(writer: str, part: int) -> str:
    """The write-once object key for a manifest part."""
    check_name(writer, WRITER_NAME_PATTERN, "writer")
    return f"manifests/{writer}/part-{part:06d}.json"


def seal_key(writer: str) -> str:
    """The write-once object key for a writer's seal."""
    check_name(writer, WRITER_NAME_PATTERN, "writer")
    return f"manifests/{writer}/seal.json"


def check_name(value: str, pattern: str, label: str) -> None:
    if re.match(pattern, value) is None:
        raise ValueError(f"invalid {label} name {value!r} (must match {pattern})")

"""Verified reading of an evidence location: the offline chain replay.

The reader is the only component that reads evidence; the writer never does (put-only credentials). `verify_location` replays every writer's manifest from genesis, recomputing the chain record by record and checking every referenced chunk, and reports the FIRST break with its neighborhood: the output is designed for incident use, so a sample's evidence trouble is diagnosable from the manifest alone, without host access.

What a break means: any rewrite, reorder, truncation of a sealed record, deletion, or forged record is a chain, sequence, digest, or seal mismatch here. What is honestly out of reach: an UNSEALED record's tail can be truncated without detection (there is no seal binding the part count yet) — verify reports such locations as unsealed rather than pretending; the lifecycle makes unsealed-at-rest an anomaly (finalize and the reaper both seal).
"""

import hashlib
from pathlib import Path
from typing import Literal, Protocol

from pydantic import BaseModel, ConfigDict, ValidationError

from .manifest import (
    ChunkRecord,
    GapRecord,
    ManifestPart,
    Seal,
    chain_genesis,
    chain_next,
    chunk_key,
    part_key,
    seal_digest,
    seal_key,
)


class EvidenceStore(Protocol):
    """Read-side access to an evidence location (separate from the write-only sink)."""

    async def get(self, key: str) -> bytes:
        """Return the object at `key`; raise `FileNotFoundError` if absent."""
        ...

    async def list(self, prefix: str) -> list[str]:
        """All keys under `prefix`, sorted by key (never by backend list order)."""
        ...


class LocalDirStore:
    """Read-side counterpart of `LocalDirSink`."""

    def __init__(self, root: Path) -> None:
        self.root = root

    async def get(self, key: str) -> bytes:
        path = self.root / key
        if not path.is_file():
            raise FileNotFoundError(key)
        return path.read_bytes()

    async def list(self, prefix: str) -> list[str]:
        base = self.root / prefix
        if not base.is_dir():
            return []
        keys = [
            str(path.relative_to(self.root))
            for path in base.rglob("*")
            if path.is_file() and not path.name.startswith(".tmp-")
        ]
        return sorted(keys)


class Break(BaseModel):
    """The first point where replay diverges from the stored record."""

    model_config = ConfigDict(extra="forbid")

    kind: Literal[
        "manifest-unparseable",
        "part-sequence",
        "record-sequence",
        "chain",
        "chunk-missing",
        "chunk-digest",
        "chunk-size",
        "seal-unparseable",
        "seal-parts",
        "seal-chain-head",
        "seal-counts",
    ]
    key: str
    """The object key where the break was observed."""
    detail: str
    stream: str | None = None
    seq: int | None = None
    neighborhood: str | None = None
    """The last-good record before the break, for incident orientation."""


class StreamCoverage(BaseModel):
    """A stream's replayed totals and clock coverage."""

    model_config = ConfigDict(extra="forbid")

    records: int = 0
    chunks: int = 0
    gaps: int = 0
    size: int = 0
    wall_start: float | None = None
    wall_end: float | None = None


class GapInfo(BaseModel):
    """One gap, inventoried for the report."""

    model_config = ConfigDict(extra="forbid")

    stream: str
    seq: int
    cause: str
    dropped: int
    wall_start: float
    wall_end: float


class WriterReport(BaseModel):
    """One writer's replay outcome."""

    model_config = ConfigDict(extra="forbid")

    writer: str
    parts: int = 0
    sealed: bool = False
    seal_status: str | None = None
    seal_digest: str | None = None
    first_break: Break | None = None
    streams: dict[str, StreamCoverage] = {}
    gaps: list[GapInfo] = []

    @property
    def ok(self) -> bool:
        """True when replay completed with no break (sealed or not; see `sealed`)."""
        return self.first_break is None


class VerifyReport(BaseModel):
    """The whole location's verification outcome."""

    model_config = ConfigDict(extra="forbid")

    location: str
    writers: dict[str, WriterReport] = {}
    unreferenced: list[str] = []
    """Chunk keys no manifest references: crash residue or pollution, reported but never a break (the chain cannot cover what it never claimed)."""

    @property
    def ok(self) -> bool:
        """True when at least one writer exists and every writer replayed cleanly."""
        return bool(self.writers) and all(w.ok for w in self.writers.values())


async def verify_location(
    store: EvidenceStore, *, location: str = "", deep: bool = True
) -> VerifyReport:
    """Replay every writer's chain at a location and report the first break per writer.

    With `deep` (the default) every referenced chunk is fetched and its digest and size checked; without it only manifests, chains, and seals are replayed.
    """
    report = VerifyReport(location=location)
    referenced: set[str] = set()
    manifest_keys = await store.list("manifests")
    writers = sorted(
        {key.split("/")[1] for key in manifest_keys if len(key.split("/")) >= 3}
    )
    for writer in writers:
        report.writers[writer] = await _verify_writer(
            store, writer, deep=deep, referenced=referenced
        )
    chunk_keys = await store.list("chunks")
    report.unreferenced = [key for key in chunk_keys if key not in referenced]
    return report


async def _verify_writer(
    store: EvidenceStore, writer: str, *, deep: bool, referenced: set[str]
) -> WriterReport:
    result = WriterReport(writer=writer)
    keys = await store.list(f"manifests/{writer}")
    part_keys = [key for key in keys if key.split("/")[-1].startswith("part-")]
    chains: dict[str, str] = {}
    next_seq: dict[str, int] = {}
    coverage: dict[str, StreamCoverage] = result.streams
    last_good: str | None = None

    for index, key in enumerate(part_keys):
        expected = part_key(writer, index)
        if key != expected:
            result.first_break = Break(
                kind="part-sequence",
                key=key,
                detail=f"expected {expected}: manifest parts must be contiguous from 0",
                neighborhood=last_good,
            )
            return result
        try:
            part = ManifestPart.model_validate_json(await store.get(key))
        except (ValidationError, ValueError) as error:
            result.first_break = Break(
                kind="manifest-unparseable",
                key=key,
                detail=str(error),
                neighborhood=last_good,
            )
            return result
        if part.writer != writer or part.part != index:
            result.first_break = Break(
                kind="part-sequence",
                key=key,
                detail=f"part claims writer={part.writer!r} part={part.part}, stored as {key}",
                neighborhood=last_good,
            )
            return result
        for record in part.records:
            broke = await _verify_record(
                store,
                writer,
                key,
                record,
                chains,
                next_seq,
                coverage,
                deep,
                referenced,
                last_good,
            )
            if broke is not None:
                result.first_break = broke
                return result
            if isinstance(record, GapRecord):
                result.gaps.append(
                    GapInfo(
                        stream=record.stream,
                        seq=record.seq,
                        cause=record.cause,
                        dropped=record.dropped,
                        wall_start=record.span.start.wall,
                        wall_end=record.span.end.wall,
                    )
                )
            last_good = f"{record.stream}#{record.seq} ({record.kind}) in {key}"
        result.parts = index + 1

    try:
        seal_bytes = await store.get(seal_key(writer))
    except FileNotFoundError:
        return result
    try:
        seal = Seal.model_validate_json(seal_bytes)
    except (ValidationError, ValueError) as error:
        result.first_break = Break(
            kind="seal-unparseable",
            key=seal_key(writer),
            detail=str(error),
            neighborhood=last_good,
        )
        return result
    result.sealed = True
    result.seal_status = seal.status
    result.seal_digest = seal_digest(seal)
    if seal.parts != result.parts:
        result.first_break = Break(
            kind="seal-parts",
            key=seal_key(writer),
            detail=f"seal claims {seal.parts} part(s), store holds {result.parts}",
            neighborhood=last_good,
        )
        return result
    sealed_streams = set(seal.streams)
    replayed_streams = set(chains)
    if sealed_streams != replayed_streams:
        result.first_break = Break(
            kind="seal-counts",
            key=seal_key(writer),
            detail=(
                f"seal streams {sorted(sealed_streams)} != replayed {sorted(replayed_streams)}"
            ),
            neighborhood=last_good,
        )
        return result
    for stream, summary in seal.streams.items():
        if summary.chain != chains[stream]:
            result.first_break = Break(
                kind="seal-chain-head",
                key=seal_key(writer),
                detail=f"stream {stream!r}: seal head {summary.chain} != replayed {chains[stream]}",
                stream=stream,
                neighborhood=last_good,
            )
            return result
        observed = coverage[stream]
        if (
            summary.records != observed.records
            or summary.chunks != observed.chunks
            or summary.gaps != observed.gaps
            or summary.size != observed.size
        ):
            result.first_break = Break(
                kind="seal-counts",
                key=seal_key(writer),
                detail=(
                    f"stream {stream!r}: seal says records={summary.records} chunks={summary.chunks} "
                    f"gaps={summary.gaps} size={summary.size}, replay saw records={observed.records} "
                    f"chunks={observed.chunks} gaps={observed.gaps} size={observed.size}"
                ),
                stream=stream,
                neighborhood=last_good,
            )
            return result
    return result


async def _verify_record(
    store: EvidenceStore,
    writer: str,
    part_key_name: str,
    record: ChunkRecord | GapRecord,
    chains: dict[str, str],
    next_seq: dict[str, int],
    coverage: dict[str, StreamCoverage],
    deep: bool,
    referenced: set[str],
    last_good: str | None,
) -> Break | None:
    stream = record.stream
    expected_seq = next_seq.get(stream, 0)
    if record.seq != expected_seq:
        return Break(
            kind="record-sequence",
            key=part_key_name,
            detail=f"stream {stream!r} expected seq {expected_seq}, found {record.seq}",
            stream=stream,
            seq=record.seq,
            neighborhood=last_good,
        )
    prev = chains.get(stream, chain_genesis(writer, stream))
    expected_chain = chain_next(prev, record)
    if record.chain != expected_chain:
        return Break(
            kind="chain",
            key=part_key_name,
            detail=f"stream {stream!r} seq {record.seq}: stored chain does not extend its predecessor (record was altered or does not belong here)",
            stream=stream,
            seq=record.seq,
            neighborhood=last_good,
        )
    chains[stream] = record.chain
    next_seq[stream] = expected_seq + 1
    cov = coverage.setdefault(stream, StreamCoverage())
    cov.records += 1
    start, end = record.span.start.wall, record.span.end.wall
    cov.wall_start = start if cov.wall_start is None else min(cov.wall_start, start)
    cov.wall_end = end if cov.wall_end is None else max(cov.wall_end, end)
    if isinstance(record, GapRecord):
        cov.gaps += 1
        return None
    cov.chunks += 1
    cov.size += record.size
    key = chunk_key(stream, record.seq)
    referenced.add(key)
    if not deep:
        return None
    try:
        data = await store.get(key)
    except FileNotFoundError:
        return Break(
            kind="chunk-missing",
            key=key,
            detail=f"manifest references {key} but the store has no such object",
            stream=stream,
            seq=record.seq,
            neighborhood=last_good,
        )
    if len(data) != record.size:
        return Break(
            kind="chunk-size",
            key=key,
            detail=f"manifest says {record.size} bytes, object holds {len(data)}",
            stream=stream,
            seq=record.seq,
            neighborhood=last_good,
        )
    actual = hashlib.sha256(data).hexdigest()
    if actual != record.sha256:
        return Break(
            kind="chunk-digest",
            key=key,
            detail=f"manifest digest {record.sha256}, object digest {actual}",
            stream=stream,
            seq=record.seq,
            neighborhood=last_good,
        )
    return None

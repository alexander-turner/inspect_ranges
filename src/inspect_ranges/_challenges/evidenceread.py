"""Window-aware evidence reads for goal checks: JSON-line records with their chunk spans.

Detection, availability, and degrade decide verdicts from the sealed evidence record alone. Window scoping rides the manifest's per-chunk `ClockSpan`s (the dual-clock stamping from evidence-v1), so a record's wall placement is as fine as its chunk: with the 15 s meta/probe batching, window edges are decided at batch granularity, stated in the goal types' docstrings. Reads are unverified conveniences over `manifest_records`/`stream_chunks` (the integrity check is `evidence verify` with the store binding; scoring consumes the same bytes it would attest).
"""

import json
from typing import TYPE_CHECKING, cast

from .._evidence.manifest import ChunkRecord, GapRecord
from .._evidence.reader import manifest_records, stream_chunks

if TYPE_CHECKING:
    from .._evidence.reader import EvidenceStore

__all__ = ["SpannedRecord", "stream_chunks_with_spans", "stream_json_records"]


class SpannedRecord:
    """One JSON-line record with its enclosing chunk's wall-clock span."""

    __slots__ = ("record", "wall_start", "wall_end")

    def __init__(
        self, record: dict[str, object], wall_start: float, wall_end: float
    ) -> None:
        self.record = record
        self.wall_start = wall_start
        self.wall_end = wall_end

    def wall(self) -> float:
        """The record's own wall stamp when it carries one, else the chunk span start."""
        wall = self.record.get("wall")
        return wall if isinstance(wall, (int, float)) else self.wall_start


async def stream_chunks_with_spans(
    store: "EvidenceStore",
    writer: str,
    stream: str,
    *,
    manifest: "list[ChunkRecord | GapRecord] | None" = None,
) -> tuple[list[tuple[bytes, float | None, float | None]], bool]:
    """A stream's chunks with their wall-clock spans, plus whether the stream carries gaps.

    A delivered chunk beyond the committed manifest parts (the writer batches parts on an interval, so the newest chunks routinely have no committed span yet) carries `None` spans. Consumers must treat a span-less chunk as the newest data, not as pre-window: excluding it from a trailing window hands a free quiet pass over alerts the record demonstrably contains (quality review A4).

    `manifest` lets callers reuse one `manifest_records` fetch across streams.
    """
    spans: dict[int, tuple[float, float]] = {}
    gapped = False
    for entry in (
        manifest if manifest is not None else await manifest_records(store, writer)
    ):
        if entry.stream != stream:
            continue
        if isinstance(entry, ChunkRecord):
            spans[entry.seq] = (entry.span.start.wall, entry.span.end.wall)
        else:
            gapped = True
    chunks = await stream_chunks(store, writer, stream)
    ordered_seqs = sorted(spans)
    spanned: list[tuple[bytes, float | None, float | None]] = []
    for position, chunk in enumerate(chunks):
        if position < len(ordered_seqs):
            start, end = spans[ordered_seqs[position]]
            spanned.append((chunk, start, end))
        else:
            spanned.append((chunk, None, None))
    return spanned, gapped


async def stream_json_records(
    store: "EvidenceStore",
    writer: str,
    stream: str,
    *,
    manifest: "list[ChunkRecord | GapRecord] | None" = None,
) -> tuple[list[SpannedRecord], bool]:
    """Every JSON-line record of a stream, with spans, plus whether the stream carries gaps.

    Returns:
        The records in sequence order and a flag that is True when any in-chain gap record exists for the stream (an observation hole: the consumer decides what incompleteness means for its verdict).
    """
    spans: dict[int, tuple[float, float]] = {}
    gapped = False
    for entry in (
        manifest if manifest is not None else await manifest_records(store, writer)
    ):
        if entry.stream != stream:
            continue
        if isinstance(entry, ChunkRecord):
            spans[entry.seq] = (entry.span.start.wall, entry.span.end.wall)
        else:
            gapped = True
    chunks = await stream_chunks(store, writer, stream)
    records: list[SpannedRecord] = []
    ordered_seqs = sorted(spans)
    for position, chunk in enumerate(chunks):
        # A delivered-beyond-committed chunk has no span yet; records keep the
        # (0.0, 0.0) placeholder because every JSON-record stream (meta, probe)
        # stamps its own `wall`, which `SpannedRecord.wall()` prefers.
        wall_start, wall_end = (
            spans[ordered_seqs[position]]
            if position < len(ordered_seqs)
            else (0.0, 0.0)
        )
        for line in chunk.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                parsed: object = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(parsed, dict):
                typed = cast(dict[str, object], parsed)
                records.append(SpannedRecord(typed, wall_start, wall_end))
    return records, gapped

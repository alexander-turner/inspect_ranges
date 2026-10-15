"""Window-aware evidence reads for goal checks: JSON-line records with their chunk spans.

Detection, availability, and degrade decide verdicts from the sealed evidence record alone. Window scoping rides the manifest's per-chunk `ClockSpan`s (the dual-clock stamping from evidence-v1), so a record's wall placement is as fine as its chunk: with the 15 s meta/probe batching, window edges are decided at batch granularity, stated in the goal types' docstrings. Reads are unverified conveniences over `manifest_records`/`stream_chunks` (the integrity check is `evidence verify` with the store binding; scoring consumes the same bytes it would attest).
"""

import json
from typing import TYPE_CHECKING

from .._evidence.manifest import ChunkRecord
from .._evidence.reader import manifest_records, stream_chunks

if TYPE_CHECKING:
    from .._evidence.reader import EvidenceStore

__all__ = ["SpannedRecord", "stream_json_records"]


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


async def stream_json_records(
    store: "EvidenceStore", writer: str, stream: str
) -> tuple[list[SpannedRecord], bool]:
    """Every JSON-line record of a stream, with spans, plus whether the stream carries gaps.

    Returns:
        The records in sequence order and a flag that is True when any in-chain gap record exists for the stream (an observation hole: the consumer decides what incompleteness means for its verdict).
    """
    spans: dict[int, tuple[float, float]] = {}
    gapped = False
    for entry in await manifest_records(store, writer):
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
                parsed = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(parsed, dict):
                records.append(SpannedRecord(parsed, wall_start, wall_end))
    return records, gapped

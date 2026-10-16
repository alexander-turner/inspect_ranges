"""Window-aware evidence reads against PRODUCTION-written records (quality review A4).

The A4 class of bug hid because every compare-level test hand-built `data_spans`; these fixtures are written by a real `EvidenceWriter` over a real `LocalDirSink` and read back through `store_for_location`, so the delivered-but-uncommitted state is exactly what the production part-batching produces.
"""

import asyncio
import json
from pathlib import Path

from inspect_ranges._challenges.engine import Observations
from inspect_ranges._challenges.evidenceread import (
    stream_chunks_with_spans,
    stream_json_records,
)
from inspect_ranges._challenges.observedtypes import DetectionType, EvadeType
from inspect_ranges._challenges.plants import PlantStore
from inspect_ranges._challenges.schema import DetectionGoal, EvadeGoal, SeverityFilter
from inspect_ranges._evidence.manifest import ClockSpan, ClockStamp
from inspect_ranges._evidence.s3 import store_for_location
from inspect_ranges._evidence.sink import EvidenceWriter, LocalDirSink

T0 = 1000.0
NOW = 1100.0

QUIET = b'{"PRIORITY":"6","MESSAGE":"routine"}\n'
LOUD = (
    b'{"PRIORITY":"2","MESSAGE":"alert intrusion"}\n'
    b'{"PRIORITY":"1","MESSAGE":"alert exfil"}\n'
    b'{"PRIORITY":"0","MESSAGE":"alert panic"}\n'
)


def _span(start: float, end: float) -> ClockSpan:
    return ClockSpan(
        start=ClockStamp(wall=start, monotonic=start),
        end=ClockStamp(wall=end, monotonic=end),
    )


async def _write_tail_state(root: Path) -> None:
    """Chunk 0 + meta committed in a part; chunk 1 (the alerts) delivered, part NOT cut."""
    writer = EvidenceWriter(
        LocalDirSink(root), writer="driver", part_interval_s=3600.0
    )
    meta = (
        json.dumps(
            {"wall": T0 + 50, "outcome": "ok", "advanced": True, "bytes": len(QUIET)}
        )
        + "\n"
        + json.dumps(
            {"wall": NOW - 2, "outcome": "ok", "advanced": True, "bytes": len(LOUD)}
        )
        + "\n"
    ).encode()
    await writer.append("telemetry/siem", QUIET, span=_span(T0, T0 + 50))
    await writer.append("telemetry-meta/siem", meta, span=_span(T0, NOW - 2))
    await writer.checkpoint()  # commits the part: both chunks gain spans
    await writer.append("telemetry/siem", LOUD, span=_span(NOW - 10, NOW - 2))
    await writer.flush()  # delivers the chunk OBJECT; the part is not due


async def _observations(root: Path) -> Observations:
    """Exactly `RangeOracle._telemetry_export_fetch` + `_telemetry_observations`."""
    store = store_for_location(str(root))
    meta, meta_gapped = await stream_json_records(store, "driver", "telemetry-meta/siem")
    data, data_gapped = await stream_chunks_with_spans(store, "driver", "telemetry/siem")
    return Observations(
        source="evidence",
        reads={
            "meta": json.dumps(
                [entry.record | {"_wall": entry.wall()} for entry in meta]
            ).encode(),
            "gapped": b"1" if (meta_gapped or data_gapped) else b"0",
            "data_spans": json.dumps(
                [
                    None if start is None or end is None else [start, end]
                    for _, start, end in data
                ]
            ).encode(),
        },
        chunk_reads={"data": [chunk for chunk, _, _ in data]},
    )


def _severity() -> SeverityFilter:
    return SeverityFilter(
        pattern=r'"PRIORITY":"(\d)"', floor=4, lower_is_more_severe=True
    )


class TestUncommittedTailSpans:
    def test_tail_chunk_has_no_span_and_committed_chunks_align(
        self, tmp_path: Path
    ) -> None:
        async def scenario() -> None:
            await _write_tail_state(tmp_path)
            store = store_for_location(str(tmp_path))
            data, gapped = await stream_chunks_with_spans(
                store, "driver", "telemetry/siem"
            )
            assert not gapped
            assert [chunk for chunk, _, _ in data] == [QUIET, LOUD]
            # positional alignment: the committed chunk carries its real span
            assert data[0][1:] == (T0, T0 + 50)
            # the delivered-beyond-committed tail carries None, never (0.0, 0.0)
            assert data[1][1:] == (None, None)

        asyncio.run(scenario())

    def test_windowed_evade_counts_the_uncommitted_alerts(
        self, tmp_path: Path
    ) -> None:
        """The A4 defect: a windowed evade goal read achieved=True over 3 delivered alerts."""

        async def scenario() -> None:
            await _write_tail_state(tmp_path)
            obs = await _observations(tmp_path)
            windowed = EvadeGoal(
                id="quiet",
                collector="siem",
                severity=_severity(),
                threshold=0,
                window_s=90.0,
            )
            whole_run = EvadeGoal(
                id="quiet", collector="siem", severity=_severity(), threshold=0
            )
            store = PlantStore(None)
            for goal in (windowed, whole_run):
                result = EvadeType().compare(goal, obs, store)
                assert not result.achieved and not result.indeterminate, (
                    goal.window_s,
                    result,
                )
                assert "3 qualifying alerts" in (result.reason or "")

        asyncio.run(scenario())

    def test_windowed_detection_finds_the_uncommitted_signal(
        self, tmp_path: Path
    ) -> None:
        async def scenario() -> None:
            await _write_tail_state(tmp_path)
            obs = await _observations(tmp_path)
            goal = DetectionGoal(
                id="alert", collector="siem", signal="alert exfil", window_s=90.0
            )
            result = DetectionType().compare(goal, obs, PlantStore(None))
            assert result.achieved

        asyncio.run(scenario())

    def test_committed_pre_window_chunk_stays_excluded(self, tmp_path: Path) -> None:
        """The chunk-B rule survives A4: a COMMITTED pre-window signal still never decides the window."""

        async def scenario() -> None:
            writer = EvidenceWriter(
                LocalDirSink(tmp_path), writer="driver", part_interval_s=3600.0
            )
            old_alert = b'{"PRIORITY":"1","MESSAGE":"alert ancient"}\n'
            meta = (
                json.dumps(
                    {
                        "wall": NOW - 2,
                        "outcome": "ok",
                        "advanced": True,
                        "bytes": len(QUIET),
                    }
                )
                + "\n"
            ).encode()
            await writer.append("telemetry/siem", old_alert, span=_span(T0, T0 + 1))
            await writer.append("telemetry-meta/siem", meta, span=_span(T0, NOW - 2))
            await writer.checkpoint()
            obs = await _observations(tmp_path)
            goal = EvadeGoal(
                id="quiet",
                collector="siem",
                severity=_severity(),
                threshold=0,
                window_s=30.0,
            )
            result = EvadeType().compare(goal, obs, PlantStore(None))
            assert result.achieved, result
            assert "0 qualifying alerts" in (result.reason or "")

        asyncio.run(scenario())

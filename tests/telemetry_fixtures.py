"""Shared exported-telemetry observation fixtures for the `detection` and `evade` verdict tests.

The observation shape is assembled by the production `telemetry_observations_from`, never hand-copied: a hand-built transcript of that function is exactly how the A4 class would hide again (quality review R2-24 consolidated the two byte-identical copies into this module).
"""

from typing import Any

from inspect_ranges._challenges.engine import Observations
from inspect_ranges._challenges.evidenceread import SpannedRecord
from inspect_ranges._challenges.observedtypes import telemetry_observations_from

__all__ = ["meta_record", "telemetry_obs"]


def meta_record(wall: float, outcome: str = "ok", **extra: Any) -> dict[str, Any]:
    """One `telemetry-meta` poll record in the shape the poller writes."""
    defaults: dict[str, Any] = {
        "advanced": outcome == "ok",
        "bytes": 10 if outcome == "ok" else 0,
    }
    return {"_wall": wall, "outcome": outcome, **defaults, **extra}


def telemetry_obs(
    meta: list[dict[str, Any]],
    data: list[bytes],
    gapped: bool = False,
    data_spans: list[list[float]] | None = None,
) -> Observations:
    """Exported-telemetry observations for `compare`, assembled through the production function."""
    spans = data_spans if data_spans is not None else [[0.0, 10.0]] * len(data)
    records = [
        SpannedRecord(
            {key: value for key, value in record.items() if key != "_wall"},
            record["_wall"],
            record["_wall"],
        )
        for record in meta
    ]
    return telemetry_observations_from(
        records,
        [(chunk, span[0], span[1]) for chunk, span in zip(data, spans, strict=True)],
        gapped,
    )

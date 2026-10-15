"""Measure-first timing instrumentation: per-goal and per-stage wall-clock in the eval log.

Surface decision (`challenges-v1.md` slice 5): timings ride the Inspect sample store under `inspect_ranges:timings`, because store state is serialized into the eval log's sample record verbatim, structured and queryable, where INFO log lines do not reliably land in sample events (the slice-3 finding). Transcript info events were the alternative; the store wins because the battery's measurement tables and post-hoc analysis read the same shape the log carries.

Shape: `{scope: {stage: {"s": total_seconds, "n": observations}}}` where scope is `"sample"` or `"goal:<goal id>"`. Stages accumulate (a poller that compares a goal five times contributes five observations), so both totals and rates are recoverable. Values are seconds; nothing here ever carries plant material.
"""

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from inspect_ai.util import Store

TIMINGS_STORE_KEY = "inspect_ranges:timings"
"""Sample-store key the timing records travel under (lands in the eval log)."""

__all__ = ["TIMINGS_STORE_KEY", "add_timing", "render_timing_table", "timings_snapshot"]


def add_timing(store: "Store", scope: str, stage: str, seconds: float) -> None:
    """Accumulate one timing observation under `scope`/`stage`.

    Args:
        store: The sample store.
        scope: `"sample"` for sample-level stages, `"goal:<goal id>"` for per-goal ones.
        stage: The stage name (`setup`, `check-compare`, `corroborate`, `poller-tick`, ...).
        seconds: Elapsed wall-clock for this observation.
    """
    raw: dict[str, dict[str, dict[str, float]]] = dict(store.get(TIMINGS_STORE_KEY, {}))
    scope_entry = dict(raw.get(scope, {}))
    stage_entry = dict(scope_entry.get(stage, {"s": 0.0, "n": 0}))
    stage_entry["s"] = float(stage_entry.get("s", 0.0)) + seconds
    stage_entry["n"] = int(stage_entry.get("n", 0)) + 1
    scope_entry[stage] = stage_entry
    raw[scope] = scope_entry
    store.set(TIMINGS_STORE_KEY, raw)


def timings_snapshot(store: "Store") -> dict[str, dict[str, dict[str, float]]]:
    """The accumulated timings, as stored (and as the eval log will carry them)."""
    return dict(store.get(TIMINGS_STORE_KEY, {}))


def render_timing_table(snapshot: dict[str, dict[str, dict[str, float]]]) -> str:
    """The measurement table (`challenges-v1.md`): one row per scope and stage, fixed width.

    Columns: scope, stage, total seconds, observations, mean seconds. Rows sort by scope then stage so tables diff cleanly across battery runs.
    """
    lines = [f"{'scope':<28} {'stage':<16} {'total_s':>9} {'n':>5} {'mean_s':>9}"]
    for scope in sorted(snapshot):
        for stage in sorted(snapshot[scope]):
            entry = snapshot[scope][stage]
            total = float(entry.get("s", 0.0))
            count = int(entry.get("n", 0))
            mean = total / count if count else 0.0
            lines.append(
                f"{scope:<28} {stage:<16} {total:>9.3f} {count:>5d} {mean:>9.3f}"
            )
    return "\n".join(lines)

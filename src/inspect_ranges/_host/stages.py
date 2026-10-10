"""Translation from `up`'s stage-log vocabulary to the seam's stage reports (`range-host-v1.md`).

The applier runs `up` with an `on_stage` callback and feeds every `(stage, status, fields)` event through a `StageTranslator`; the translator decides which events become seam `StageReport`s. The mapping (settled in the record): `verify-images` is `fetch`; `prepare`, `range-image`, and `range-container` coalesce into one `construct` report whose detail carries the triggering up stage (the client enforces strictly increasing stage order, so repeats would be tamper against our own channel); `guest-boot` is `boot`; `readiness` is `verify`; `ready` is `ready`. Any `fail` status becomes `failed` with the detail prefixed by the up stage name, which keeps the reverse mapping (seam report back to `UpError` stage) lossless for the provider's respin classification. `verify-bundle` and `teardown` emit nothing on success.

`ready` and `failed` are terminal: the client rejects any data after a terminal report as tamper, so once the translator emits one it answers `None` for everything that follows (one `up` failure logs several `fail` events: the per-guest cause, the summary, sometimes a `teardown` fail during cleanup).

Failures raised before `up` creates its stage log (`verify-bundle`, an early `prepare` refusal) never reach `on_stage`; the applier translates the raised `UpError` itself by feeding a synthetic `(error.stage, "fail", {"error": str(error)})` event, which the fail rule maps to `failed` with the same lossless prefix.

Pure and deterministic: no I/O, one instance per realize.
"""

from typing import Literal, NamedTuple

SeamStage = Literal["fetch", "construct", "boot", "verify", "ready", "failed"]

SEAM_STAGES: tuple[SeamStage, ...] = (
    "fetch",
    "construct",
    "boot",
    "verify",
    "ready",
    "failed",
)

_GROUP: dict[str, SeamStage | None] = {
    "verify-bundle": None,
    "verify-images": "fetch",
    "prepare": "construct",
    "range-image": "construct",
    "range-container": "construct",
    "guest-boot": "boot",
    "readiness": "verify",
    "ready": "ready",
    "teardown": None,
}


class TranslatedStage(NamedTuple):
    """One seam report the applier should emit for a stage-log event."""

    stage: SeamStage
    detail: str


class StageTranslator:
    """Stateful per-realize translator: one report per seam stage, in order.

    `translate` returns the report to emit for an event, or `None` when the event adds nothing (a repeat within a coalesced group, a per-guest readiness event after the first, an unknown or unmapped stage, anything after a terminal report). The first event with `fail` status emits `failed` with the up stage name prefixed to the detail (the diagnostic comes from the event's `error` or `cause` field, with the guest named when present); `ready` and `failed` both latch the translator closed.

    Raises:
        ValueError: `ready` would be the very first emission; an honest `up` run always logs earlier stages first, so this is an applier bug surfacing loudly rather than a tamper verdict against our own stream.
    """

    def __init__(self) -> None:
        self._emitted: set[SeamStage] = set()
        self._done = False

    def translate(
        self, stage: str, status: str, fields: dict[str, object] | None = None
    ) -> TranslatedStage | None:
        if self._done:
            return None
        if status == "fail":
            self._done = True
            raw = fields or {}
            cause = raw.get("error") or raw.get("cause")
            parts = [str(part) for part in (raw.get("guest"), cause) if part]
            detail = f"{stage}: {': '.join(parts)}" if parts else stage
            return TranslatedStage("failed", detail)
        group = _GROUP.get(stage)
        if group is None or group in self._emitted:
            return None
        if group == "ready" and not self._emitted:
            raise ValueError("ready cannot be the first seam stage")
        if group == "ready":
            self._done = True
        self._emitted.add(group)
        detail = stage if group == "construct" else ""
        return TranslatedStage(group, detail)

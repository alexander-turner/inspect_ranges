"""Translation from `up`'s stage-log vocabulary to the seam's stage reports (`range-host-v1.md`).

The applier runs `up` with an `on_stage` callback and feeds every `(stage, status, fields)` event through a `StageTranslator`; the translator decides which events become seam `StageReport`s. The mapping (settled in the record): `verify-images` is `fetch`; `prepare`, `range-image`, and `range-container` coalesce into one `construct` report whose detail carries the triggering up stage (the client enforces strictly increasing stage order, so repeats would be tamper against our own channel); `guest-boot` is `boot`; `readiness` is `verify`; `ready` is `ready`. Any `fail` status becomes `failed` with the detail prefixed by the up stage name, which keeps the reverse mapping (seam report back to `UpError` stage) lossless for the provider's respin classification. `verify-bundle` and `teardown` emit nothing (a verify-bundle failure still surfaces as `failed` through the fail rule).

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

    `translate` returns the report to emit for an event, or `None` when the event adds nothing (a repeat within a coalesced group, a per-guest readiness event after the first, an unknown or unmapped stage). `failed` is always emitted, from any event with `fail` status, with the up stage name prefixed to the detail.

    Raises:
        ValueError: `ready` would be the very first emission; an honest `up` run always logs earlier stages first, so this is an applier bug surfacing loudly rather than a tamper verdict against our own stream.
    """

    def __init__(self) -> None:
        self._emitted: set[SeamStage] = set()

    def translate(
        self, stage: str, status: str, fields: dict[str, object] | None = None
    ) -> TranslatedStage | None:
        if status == "fail":
            error = str((fields or {}).get("error", ""))
            return TranslatedStage("failed", f"{stage}: {error}".rstrip())
        group = _GROUP.get(stage)
        if group is None or group in self._emitted:
            return None
        if group == "ready" and not self._emitted:
            raise ValueError("ready cannot be the first seam stage")
        self._emitted.add(group)
        detail = stage if group == "construct" else ""
        return TranslatedStage(group, detail)

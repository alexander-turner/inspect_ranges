"""The `RangeHost`/`HostProvider` seam (`host-provider.md`, implemented per `range-host-v1.md`).

A `HostProvider` acquires range hosts as leases (identity plus expiry; release is destruction) and a `RangeHost` carries the channel, the isolation claim, and the host's declared capabilities and facts. The seam types here are the first concrete definitions anywhere and deliberately minimal; the lease store, reaper, and backends arrive in the later slices of the phase.
"""

from .host import (
    HostCapabilities,
    HostFacts,
    HostProvider,
    RangeHost,
    SampleSpec,
)
from .stages import SEAM_STAGES, SeamStage, StageTranslator, TranslatedStage

__all__ = [
    "HostCapabilities",
    "HostFacts",
    "HostProvider",
    "RangeHost",
    "SEAM_STAGES",
    "SampleSpec",
    "SeamStage",
    "StageTranslator",
    "TranslatedStage",
]

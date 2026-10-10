"""The `RangeHost`/`HostProvider` seam (`host-provider.md`, implemented per `range-host-v1.md`).

A `HostProvider` acquires range hosts as leases (identity plus expiry; release is destruction) and a `RangeHost` carries the channel, the isolation claim, and the host's declared capabilities and facts. The lease store (`leases.py`), the independent reaper (`reaper.py`), and the local backend (`local.py`) implement the seam for one co-resident host; the separated backend arrives in slice 3 of the phase.
"""

from .host import (
    HostCapabilities,
    HostFacts,
    HostProvider,
    LeasePlacement,
    RangeHost,
    SampleSpec,
)
from .leases import HostLease, LeaseLostError, LeaseStore, lease_ttl_s
from .local import HostNotReadyError, LocalHostProvider, LocalRangeHost
from .stages import SEAM_STAGES, SeamStage, StageTranslator, TranslatedStage

__all__ = [
    "HostCapabilities",
    "HostFacts",
    "HostLease",
    "HostNotReadyError",
    "HostProvider",
    "LeaseLostError",
    "LeasePlacement",
    "LeaseStore",
    "LocalHostProvider",
    "LocalRangeHost",
    "RangeHost",
    "SEAM_STAGES",
    "SampleSpec",
    "SeamStage",
    "StageTranslator",
    "TranslatedStage",
    "lease_ttl_s",
]

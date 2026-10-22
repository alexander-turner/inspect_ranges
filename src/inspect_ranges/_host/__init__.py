"""The `RangeHost`/`HostProvider` seam (`host-provider.md`, implemented per `range-host-v1.md`).

A `HostProvider` acquires range hosts as leases (identity plus expiry; release is destruction) and a `RangeHost` carries the channel, the isolation claim, and the host's declared capabilities and facts. The lease store (`leases.py`), the independent reaper (`reaper.py`), and the local backend (`local.py`) implement the seam for one co-resident host; the separated backend arrives in slice 3 of the phase.
"""

from .backend import (
    DoctorProbe,
    HostBackend,
    HostBackendContext,
    HostBackendFactory,
    ReclaimFn,
    parse_host_backend,
    resolve_host_backend,
)
from .host import (
    HostCapabilities,
    HostFacts,
    HostProvider,
    IsolationLevel,
    LeasePlacement,
    RangeHost,
    SampleSpec,
)
from .leases import HostLease, LeaseLostError, LeaseStore, lease_ttl_s
from .local import (
    HostNotReadyError,
    LocalHostProvider,
    LocalRangeHost,
    local_host_facts,
)
from .remote import RemoteHostProvider, RemoteRangeHost
from .seams import ChannelForLease, derive_channel_seams
from .stages import SEAM_STAGES, SeamStage, StageTranslator, TranslatedStage

__all__ = [
    "ChannelForLease",
    "DoctorProbe",
    "HostBackend",
    "HostBackendContext",
    "HostBackendFactory",
    "HostCapabilities",
    "HostFacts",
    "HostLease",
    "HostNotReadyError",
    "HostProvider",
    "IsolationLevel",
    "LeaseLostError",
    "LeasePlacement",
    "LeaseStore",
    "LocalHostProvider",
    "LocalRangeHost",
    "RangeHost",
    "ReclaimFn",
    "RemoteHostProvider",
    "RemoteRangeHost",
    "SEAM_STAGES",
    "SampleSpec",
    "SeamStage",
    "StageTranslator",
    "TranslatedStage",
    "derive_channel_seams",
    "lease_ttl_s",
    "local_host_facts",
    "parse_host_backend",
    "resolve_host_backend",
]

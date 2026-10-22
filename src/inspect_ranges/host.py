"""The range-host extension point: implement and register a custom backend for `INSPECT_RANGES_HOST`.

A backend is registered by the environment variable itself: `INSPECT_RANGES_HOST=<module>.<factory>[:<config>]` names a `HostBackendFactory` that is imported and called at resolution, and the same value is persisted verbatim as each lease's `origin`, so a fresh process (the reaper foremost) re-resolves teardown from disk alone wherever the backend's package is installed. The factory returns a `HostBackend` bundle: a `HostProvider` (acquire, release, abandon), plus for a separated deployment the one `channel_for_lease` hook from which the runtime derives its boot, teardown, and channel seams, an optional reaper `reclaim` connector, and an optional doctor probe.

The lease machinery is reusable as-is: stamp the context's `origin` through `LeaseStore.acquire`, or subclass `LocalRangeHost` (as the built-in `uds:` backend's host does) to inherit renewal, `check_lease`, and the typed `LeaseLostError`. The channel tier is public for the same reason: a realistic backend implements one `Transport` (per-endpoint `connect`, where the endpoint is a guest name or `HOST_APPLIER`) and wraps it in `MessageChannel`, inheriting the whole wire discipline of request ids, idempotent retries, budgets, and strict reply validation. See the Range Host documentation page for the grammar and the contracts an implementation is held to.
"""

from ._channel.channel import (
    HOST_APPLIER,
    ByteStream,
    ExecOutcome,
    MessageChannel,
    RangeChannel,
    Transport,
)
from ._channel.protocol import (
    DEFAULT_BULK_CAP,
    DiagReply,
    ExecRequest,
    ForwardReply,
    Heartbeat,
    PongReply,
    Sha256Hex,
    StageReport,
)
from ._host import (
    ChannelForLease,
    DoctorProbe,
    HostBackend,
    HostBackendContext,
    HostBackendFactory,
    HostCapabilities,
    HostFacts,
    HostLease,
    HostProvider,
    IsolationLevel,
    LeaseLostError,
    LeasePlacement,
    LeaseStore,
    LocalRangeHost,
    RangeHost,
    ReclaimFn,
    SampleSpec,
    lease_ttl_s,
    local_host_facts,
)

__all__ = [
    "ByteStream",
    "ChannelForLease",
    "DEFAULT_BULK_CAP",
    "DiagReply",
    "DoctorProbe",
    "ExecOutcome",
    "ExecRequest",
    "ForwardReply",
    "HOST_APPLIER",
    "Heartbeat",
    "HostBackend",
    "HostBackendContext",
    "HostBackendFactory",
    "HostCapabilities",
    "HostFacts",
    "HostLease",
    "HostProvider",
    "IsolationLevel",
    "LeaseLostError",
    "LeasePlacement",
    "LeaseStore",
    "LocalRangeHost",
    "MessageChannel",
    "PongReply",
    "RangeChannel",
    "RangeHost",
    "ReclaimFn",
    "SampleSpec",
    "Sha256Hex",
    "StageReport",
    "Transport",
    "lease_ttl_s",
    "local_host_facts",
]

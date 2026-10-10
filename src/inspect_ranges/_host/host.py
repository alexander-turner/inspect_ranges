"""Seam types for the `RangeHost`/`HostProvider` contract (`host-provider.md:83-91`).

These are the first concrete definitions of `SampleSpec`, `HostCapabilities`, and `HostFacts` anywhere in the project, and they are deliberately minimal: each is extensible, and growth happens against evidence (`range-host-v1.md`). Both v1 backends honestly claim `isolation="shared"` (one host is reused across samples); `"instance"` arrives only with a real fleet provider.
"""

from typing import Literal, Protocol

from pydantic import BaseModel, ConfigDict

from .._channel.channel import RangeChannel
from .._channel.protocol import Sha256Hex
from .._compiler.plan import Totals

IsolationLevel = Literal["instance", "shared"]
"""The per-sample isolation claim, logged so the eval-log claim stays truthful (`host-provider.md:27`)."""


class SampleSpec(BaseModel):
    """What a `HostProvider.acquire` needs to know about the sample it hosts."""

    model_config = ConfigDict(extra="forbid")

    sample_id: str
    task_name: str
    spec_sha256: Sha256Hex
    bundle_digest: Sha256Hex
    """The canonical bundle digest: sha256 of the rendered bundle's `manifest.json` bytes."""
    totals: Totals


class HostCapabilities(BaseModel):
    """What the deployment declares it can do; absence refuses at planning, never degrades silently.

    v1 pins every capability to its only supported value: image delivery is pre-seeded (the cache already holds the verified chain), and neither `forward` upstream reach nor egress grants exist yet.
    """

    model_config = ConfigDict(extra="forbid")

    image_delivery: Literal["pre-seeded"] = "pre-seeded"
    forward_upstream: Literal[False] = False
    egress_grant: Literal[False] = False


class HostFacts(BaseModel):
    """Host-class identity: render inputs are host-class declarations, never per-instance probes."""

    model_config = ConfigDict(extra="forbid")

    arch: str
    hostname: str
    host_class: str


class LeasePlacement(BaseModel):
    """Driver-side placement facts the lease record needs so the reaper can act from disk alone.

    `SampleSpec` deliberately carries none of these (they are placement, not sample identity), yet the recorded lease shape requires them; `acquire` takes them as a second argument. Recorded in the `range-host-v1.md` ledger as a seam-signature extension over the `host-provider.md:83-91` sketch.
    """

    model_config = ConfigDict(extra="forbid")

    project: str
    bundle_path: str
    staging: str


class RangeHost(Protocol):
    """One acquired range host: the channel to it, and what the deployment claims about it.

    `channel` is `None` between acquire and boot in the co-resident backend (the local path builds its channel from booted guest CIDs, after `up`); the separated backend attaches it at acquire. Consumers that need the channel assert its presence at their boundary.
    """

    channel: RangeChannel | None
    isolation: IsolationLevel
    capabilities: HostCapabilities
    facts: HostFacts

    def check_lease(self) -> None:
        """Raise `LeaseLostError` when this host's lease has been lost (reaped, or expired and reclaimed); ops call this first, so lease loss fails the sample loudly at its next operation instead of silently running on a reclaimed host."""
        ...


class HostProvider(Protocol):
    """Acquires and releases range hosts.

    `acquire` returns a lease (identity plus expiry; a sample that outlives its lease is reclaimed by the independent reaper), gates on doctor readiness, logs the isolation claim, and starts renewal. `release` is destruction and must only follow a successful teardown: a used host is never returned to a pool, and a failed teardown frees nothing. `abandon` is the deliberate keep-it-running path (`cleanup=False`): renewal stops but the lease stays, so the reaper reclaims after expiry.
    """

    async def acquire(
        self, sample: SampleSpec, placement: LeasePlacement
    ) -> RangeHost: ...
    async def release(self, host: RangeHost) -> None: ...
    async def abandon(self, host: RangeHost) -> None: ...

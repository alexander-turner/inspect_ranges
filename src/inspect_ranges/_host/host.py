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


class RangeHost(Protocol):
    """One acquired range host: the channel to it, and what the deployment claims about it."""

    channel: RangeChannel
    isolation: IsolationLevel
    capabilities: HostCapabilities
    facts: HostFacts


class HostProvider(Protocol):
    """Acquires and releases range hosts.

    `acquire` returns a lease (identity plus expiry; a sample that outlives its lease is reclaimed by the independent reaper) and gates on doctor readiness. `release` is destruction: a used host is never returned to a pool.
    """

    async def acquire(self, sample: SampleSpec) -> RangeHost: ...
    async def release(self, host: RangeHost) -> None: ...

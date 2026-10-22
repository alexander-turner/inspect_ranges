"""The separated `uds:` backend: `RemoteRangeHost` over the applier's unix socket.

`RemoteHostProvider.acquire` writes the lease (origin `uds:<socket>`), starts renewal, and attaches the channel at acquire (a `MessageChannel` over `UdsTransport` scoped to the lease): the other half of the `RangeHost.channel` nullability deviation, where the local backend attaches post-boot. Readiness is gated host-side: the applier refuses to serve unhealthy at startup, so the driver carries no second doctor gate.

Everything else the backend used to carry here, the derived provider seams and the reaper's teardown connector, is now the generic channel machinery (`seams.py`), reached through the backend bundle `resolve_host_backend` assembles for `uds:` values (`backend.py`). What remains UDS-specific is one function: `uds_channel_for_lease`, the `channel_for_lease` hook built on `UdsTransport`.
"""

import asyncio
import logging
from pathlib import Path

from .._channel.channel import MessageChannel, RangeChannel
from .._channel.uds import UdsTransport
from .host import LeasePlacement, RangeHost, SampleSpec
from .leases import HostLease, LeaseStore, lease_ttl_s
from .local import LocalRangeHost, local_host_facts
from .seams import ChannelForLease

logger = logging.getLogger("inspect_ranges.host")


class RemoteRangeHost(LocalRangeHost):
    """One leased host behind the applier socket; identical lease/renewal behavior to the co-resident host, with the channel attached at acquire."""

    def __init__(
        self,
        lease: HostLease,
        store: LeaseStore,
        ttl_s: float,
        channel: RangeChannel,
    ) -> None:
        super().__init__(lease, store, ttl_s)
        self.channel: RangeChannel | None = channel


class RemoteHostProvider:
    """Grants leases served by the applier at `socket_path` (one host, shared state dir)."""

    def __init__(
        self,
        socket_path: Path | str,
        state_dir: Path,
        *,
        store: LeaseStore | None = None,
        ttl_s: float | None = None,
    ) -> None:
        self._socket_path = Path(socket_path)
        self._store = store if store is not None else LeaseStore(state_dir)
        self._ttl_s = ttl_s if ttl_s is not None else lease_ttl_s()

    async def acquire(
        self, sample: SampleSpec, placement: LeasePlacement
    ) -> RemoteRangeHost:
        lease = await asyncio.to_thread(
            lambda: self._store.acquire(
                project=placement.project,
                task_name=sample.task_name,
                sample_id=sample.sample_id,
                isolation="shared",
                origin=f"uds:{self._socket_path}",
                bundle_path=placement.bundle_path,
                bundle_digest=sample.bundle_digest,
                staging=placement.staging,
                host_facts=local_host_facts(),
                ttl_s=self._ttl_s,
                evidence_location=placement.evidence_location,
            )
        )
        channel = MessageChannel(
            UdsTransport(self._socket_path, lease.lease_id), label=placement.project
        )
        host = RemoteRangeHost(lease, self._store, self._ttl_s, channel)
        logger.info(
            "acquired host: backend=uds isolation=%s lease=%s project=%s socket=%s",
            host.isolation,
            lease.lease_id,
            lease.project,
            self._socket_path,
        )
        host.start_renewal()
        return host

    async def release(self, host: RangeHost) -> None:
        """Stop renewal and remove the lease; only ever after a successful teardown."""
        assert isinstance(host, LocalRangeHost)
        await host.stop_renewal()
        await asyncio.to_thread(self._store.release, host.lease.lease_id)

    async def abandon(self, host: RangeHost) -> None:
        """Stop renewal but LEAVE the lease (`cleanup=False`); the reaper reclaims after expiry."""
        assert isinstance(host, LocalRangeHost)
        await host.stop_renewal()


def _lease_channel(socket_path: Path, lease: HostLease, label: str) -> MessageChannel:
    """THE way a driver-side helper reaches one lease's plane (one construction site for transport, label, and budgets)."""
    return MessageChannel(UdsTransport(socket_path, lease.lease_id), label=label)


def uds_channel_for_lease(socket_path: Path) -> ChannelForLease:
    """The `uds:` backend's `channel_for_lease` hook: every derived seam and the reaper's reclaim reach the applier through it."""

    def channel_for_lease(lease: HostLease) -> MessageChannel:
        return _lease_channel(socket_path, lease, lease.project)

    return channel_for_lease

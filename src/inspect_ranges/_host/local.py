"""The local (co-resident) backend: today's exact provider path, plus the lease.

`LocalRangeHost` adds only what the record allows over the pre-seam behavior: the host lease, its renewal task at TTL/3, the cached-per-task doctor-readiness gate, and the isolation log line; everything else (render, `up`, the vsock channel, teardown) stays exactly the provider's existing path, proven behavior-identical by the lifecycle battery rather than asserted. The backend honestly claims `isolation="shared"`: one host is reused across samples.
"""

import asyncio
import logging
import os
import platform
import socket
from collections.abc import Callable
from pathlib import Path

from .._channel.channel import RangeChannel
from .._doctor.checks import readiness_failures
from .host import (
    HostCapabilities,
    HostFacts,
    IsolationLevel,
    LeasePlacement,
    RangeHost,
    SampleSpec,
)
from .leases import HostLease, LeaseLostError, LeaseStore, lease_ttl_s

logger = logging.getLogger("inspect_ranges.host")

GateFn = Callable[[], list[str]]


class HostNotReadyError(RuntimeError):
    """The host fails the doctor-readiness gate; the sample fails fast with the report (`host-provider.md:94`)."""


def local_host_facts() -> HostFacts:
    """This machine's host-class identity; `INSPECT_RANGES_HOST_CLASS` names the class (declarations, never per-instance probes)."""
    return HostFacts(
        arch=platform.machine(),
        hostname=socket.gethostname(),
        host_class=os.environ.get("INSPECT_RANGES_HOST_CLASS", "unspecified"),
    )


class LocalRangeHost:
    """One leased co-resident host. The channel is attached by the provider after boot (today's path builds it from booted guest CIDs), so it is `None` until then."""

    def __init__(self, lease: HostLease, store: LeaseStore, ttl_s: float) -> None:
        self.channel: RangeChannel | None = None
        self.isolation: IsolationLevel = "shared"
        self.capabilities = HostCapabilities()
        self.facts = lease.host_facts
        self.lease = lease
        self._store = store
        self._ttl_s = ttl_s
        self._lost: LeaseLostError | None = None
        self._renewal: asyncio.Task[None] | None = None

    def check_lease(self) -> None:
        """Raise the `LeaseLostError` a renewal step recorded, so lease loss fails the sample loudly at its next operation.

        Raises:
            LeaseLostError: Renewal found the lease gone or reaping.
        """
        if self._lost is not None:
            raise self._lost

    async def renew_now(self) -> None:
        """One renewal step, exactly what the background task runs at TTL/3; the renewal-versus-reap tests drive it directly.

        Raises:
            LeaseLostError: The CAS lost; also recorded so every later `check_lease` raises it.
        """
        try:
            self.lease = await asyncio.to_thread(
                self._store.renew, self.lease.lease_id, self._ttl_s
            )
        except LeaseLostError as error:
            self._lost = error
            logger.error(
                "lease lost: lease=%s project=%s: %s",
                self.lease.lease_id,
                self.lease.project,
                error,
            )
            raise

    def start_renewal(self) -> None:
        self._renewal = asyncio.create_task(
            self._renew_forever(), name=f"lease-renewal-{self.lease.lease_id}"
        )

    async def stop_renewal(self) -> None:
        if self._renewal is not None:
            self._renewal.cancel()
            try:
                await self._renewal
            except asyncio.CancelledError:
                pass
            self._renewal = None

    async def _renew_forever(self) -> None:
        while True:
            await asyncio.sleep(self._ttl_s / 3)
            try:
                await self.renew_now()
            except LeaseLostError:
                return  # recorded; check_lease surfaces it at the next op


class LocalHostProvider:
    """Grants leases on this machine; otherwise the provider's path is untouched.

    The doctor-readiness gate runs once per provider instance (one per `ProviderRuntime`, so once per task) and is injectable for tests; the real subset is `readiness_failures`.
    """

    def __init__(
        self,
        state_dir: Path,
        *,
        gate: GateFn | None = None,
        store: LeaseStore | None = None,
        ttl_s: float | None = None,
    ) -> None:
        self._store = store if store is not None else LeaseStore(state_dir)
        self._gate = gate if gate is not None else readiness_failures
        self._gate_failures: list[str] | None = None
        self._ttl_s = ttl_s if ttl_s is not None else lease_ttl_s()

    async def acquire(
        self, sample: SampleSpec, placement: LeasePlacement
    ) -> LocalRangeHost:
        """Gate on readiness, write the lease, log the isolation claim, start renewal.

        Raises:
            HostNotReadyError: The cached doctor-readiness subset reports failures.
        """
        if self._gate_failures is None:
            self._gate_failures = await asyncio.to_thread(self._gate)
        if self._gate_failures:
            raise HostNotReadyError(
                "the local host fails doctor readiness: "
                + "; ".join(self._gate_failures)
                + " (run: inspect-ranges doctor)"
            )
        lease = await asyncio.to_thread(
            lambda: self._store.acquire(
                project=placement.project,
                task_name=sample.task_name,
                sample_id=sample.sample_id,
                isolation="shared",
                origin="local",
                bundle_path=placement.bundle_path,
                bundle_digest=sample.bundle_digest,
                staging=placement.staging,
                host_facts=local_host_facts(),
                ttl_s=self._ttl_s,
            )
        )
        host = LocalRangeHost(lease, self._store, self._ttl_s)
        logger.info(
            "acquired host: backend=local isolation=%s lease=%s project=%s",
            host.isolation,
            lease.lease_id,
            lease.project,
        )
        host.start_renewal()
        return host

    async def release(self, host: RangeHost) -> None:
        """Stop renewal and remove the lease. Release is destruction: only call after a successful teardown."""
        assert isinstance(host, LocalRangeHost)
        await host.stop_renewal()
        await asyncio.to_thread(self._store.release, host.lease.lease_id)

    async def abandon(self, host: RangeHost) -> None:
        """Stop renewal but LEAVE the lease (the `cleanup=False` path): the reaper reclaims after expiry."""
        assert isinstance(host, LocalRangeHost)
        await host.stop_renewal()

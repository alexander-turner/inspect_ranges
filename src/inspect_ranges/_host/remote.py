"""The separated backend: `RemoteRangeHost` over the applier's unix socket.

`RemoteHostProvider.acquire` writes the lease (origin `uds:<socket>`), starts renewal, and attaches the channel at acquire (a `MessageChannel` over `UdsTransport` scoped to the lease): the other half of the `RangeHost.channel` nullability deviation, where the local backend attaches post-boot. Readiness is gated host-side: the applier refuses to serve unhealthy at startup, so the driver carries no second doctor gate.

The provider seams derive from the channel per the record: `remote_seams` yields an `up_fn` that drives `channel.realize` and folds the stage stream back into `UpResult` or `UpError` (the failed detail's leading up-stage name makes the reverse mapping lossless; an `EAGAIN` refusal folds to `UpError("admission", ...)` so the provider's transient respin classifies it, while `ENOSPC`/`EINVAL`/`ENOTSUP` refusals stay typed `HostRefused`, permanent), a `down_fn` that drives `channel.teardown` (falling back to direct `down` when no lease exists for the project, the fresh-process cleanup case), and a `channel_factory` building on `UdsTransport`. The seams are sync (they run in the provider's worker threads) and own a private event loop per call.

The reaper's applier connector lives here too: `applier_teardown` tears a `uds:` lease down through its own socket, releasing the applier's admission charge and relay map.
"""

import asyncio
import logging
import time
from collections.abc import Callable
from pathlib import Path

from .._channel.channel import HostRefused, MessageChannel, RangeChannel
from .._channel.uds import UdsTransport
from .._channel.vsock import HybridEndpoint
from .._compiler.plan import ResolvedPlan
from .._runtime.down import DownResult
from .._runtime.down import down as run_down
from .._runtime.up import (
    IMAGE_BUILD_TIMEOUT_S,
    GuestState,
    OnStage,
    UpError,
    UpOptions,
    UpResult,
    bundle_digest,
)
from .host import LeasePlacement, RangeHost, SampleSpec
from .leases import HostLease, LeaseStore, lease_ttl_s
from .local import LocalRangeHost, local_host_facts

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


# -- the derived provider seams ---------------------------------------------------


def _lease_for_project(store: LeaseStore, project: str) -> HostLease | None:
    for lease in store.leases():
        if lease.project == project:
            return lease
    return None


def _lease_channel(socket_path: Path, lease: HostLease, label: str) -> MessageChannel:
    """THE way a driver-side helper reaches one lease's plane (one construction site for transport, label, and budgets)."""
    return MessageChannel(UdsTransport(socket_path, lease.lease_id), label=label)


def realize_gap_allowances(
    plan: ResolvedPlan, options: UpOptions
) -> dict[str | None, float]:
    """Per-gap report allowances for `channel.realize`, keyed by the stage each gap follows (`None` keys the gap before the first report).

    Each gap's allowance is the plan-derived bound of its legitimate occupant, which emits no intermediate report while it runs (quality-review A10, extended to the sibling gaps by R2-3): before the first report sits everything up to `up`'s stage-log creation, worst the first-use range-image build (`IMAGE_BUILD_TIMEOUT_S`); after `construct` sits `compose up --wait` (readiness timeout plus 60 s); after `boot` sits the guest-boot exec (readiness timeout); after `verify` sits the applier's whole sequential readiness pass (the readiness deadline plus every guest's minimum probe window). Gaps with no legitimate occupant (`fetch` to `construct`) are deliberately absent, so the flat channel allowance still catches a truly silent applier there.

    The APPLIER runs `up` with its own `UpOptions` (`RealizeRequest` carries no readiness fields), so the readiness-derived envelopes are floored at the defaults the applier actually probes with: a driver configured with a SHORTER readiness timeout must not starve a legitimately slower applier pass (carrying readiness fields on the wire is the recorded growth path).
    """
    default_timeout = float(UpOptions.model_fields["readiness_timeout"].default)
    default_window = float(UpOptions.model_fields["readiness_min_window"].default)
    readiness_timeout = max(options.readiness_timeout, default_timeout)
    probe_window = max(options.readiness_min_window, default_window)
    return {
        None: IMAGE_BUILD_TIMEOUT_S + 30.0,
        "construct": readiness_timeout + 60.0 + 30.0,
        "boot": readiness_timeout + 30.0,
        "verify": readiness_timeout + len(plan.guests) * probe_window + 30.0,
    }


async def _drive_realize(
    socket_path: Path,
    lease: HostLease,
    bundle: Path,
    project: str,
    on_stage: OnStage | None,
    options: UpOptions,
) -> UpResult:
    """`channel.realize` folded back into the `up` contract (`UpResult` or `UpError`).

    `on_stage` observes each folded report with the DRIVER's clocks at receive time (the seam-stage vocabulary, status `report`): the receive-side half of the clock-offset pairs whose emit side the applier's recorder writes host-side (`evidence-v1.md`).
    """
    plan = ResolvedPlan.model_validate_json((bundle / "plan.json").read_text())
    digest = bundle_digest(bundle)  # UpError-typed on an unreadable manifest
    channel = _lease_channel(socket_path, lease, project)
    started = time.monotonic()
    try:
        async for report in channel.realize(
            digest, [], gap_allowances=realize_gap_allowances(plan, options)
        ):
            if on_stage is not None:
                # never let an observer failure alter the realize outcome
                try:
                    on_stage(report.stage, "report", {"detail": report.detail})
                except Exception:
                    logger.exception("realize on_stage observer failed (ignored)")
            if report.stage == "failed":
                # the failed detail begins with the up stage name: the lossless
                # reverse mapping the provider's respin classification needs
                stage, _, message = report.detail.partition(": ")
                raise UpError(stage or "guest-boot", message or report.detail)
    except HostRefused as refusal:
        if refusal.errno == "EAGAIN":
            # full-now is transient: fold to the admission stage so the
            # provider's layer-3 respin classifies it
            raise UpError("admission", str(refusal)) from refusal
        raise  # ENOSPC/EINVAL/ENOTSUP are permanent and stay typed
    guests = [
        GuestState(name=guest.name, cid=guest.cid, ready=True) for guest in plan.guests
    ]
    return UpResult(
        project=project,
        range_name=plan.range.name,
        guests=guests,
        seconds=time.monotonic() - started,
    )


RemoteSeams = tuple[
    Callable[[Path, UpOptions, OnStage | None], UpResult],
    Callable[[str, Path], DownResult],
    Callable[[dict[str, int], str, dict[str, HybridEndpoint]], MessageChannel],
]


def remote_seams(socket_path: Path, state_dir: Path) -> RemoteSeams:
    """The provider seams the `uds:` backend derives: (`up_fn`, `down_fn`, `channel_factory`).

    Each seam looks its lease up by project from the shared store (the seams are runtime-global but leases are per-sample) and runs the channel on a private event loop (the seams execute in the provider's worker threads).
    """
    store = LeaseStore(state_dir)

    def up_fn(bundle: Path, options: UpOptions, on_stage: OnStage | None) -> UpResult:
        project = options.project or ""
        lease = _lease_for_project(store, project)
        if lease is None:
            raise UpError(
                "verify-bundle", f"no host lease found for project {project!r}"
            )
        return asyncio.run(
            _drive_realize(socket_path, lease, bundle, project, on_stage, options)
        )

    def down_fn(project: str, state_dir_arg: Path) -> DownResult:
        lease = _lease_for_project(store, project)
        if lease is None:
            # fresh-process cleanup of a project whose lease is already gone:
            # same host, so direct down is both available and correct
            return run_down(project, state_dir=state_dir_arg)
        _teardown_lease(socket_path, lease)
        # the applier's OkReply carries no removal counts, so zeros here mean
        # "not counted remotely", not "no-op" (a counted teardown reply is a
        # wire-growth candidate, not something to fabricate)
        return DownResult(project=project, containers=0, volumes=0, networks=0)

    def channel_factory(
        cids: dict[str, int], label: str, hybrid_sockets: dict[str, HybridEndpoint]
    ) -> MessageChannel:
        # hybrid_sockets is unused: the applier dials Cloud Hypervisor guests
        # itself (its guest connector), so the client relays by name as usual
        lease = _lease_for_project(store, label)
        if lease is None:
            raise RuntimeError(f"no host lease found for project {label!r}")
        return _lease_channel(socket_path, lease, label)

    return up_fn, down_fn, channel_factory


def _teardown_lease(socket_path: Path, lease: HostLease) -> None:
    """One lease's teardown through its applier, from sync (worker-thread or fresh-process) callers."""

    async def teardown() -> None:
        await _lease_channel(socket_path, lease, lease.project).teardown()

    asyncio.run(teardown())


def applier_teardown(lease: HostLease) -> None:
    """The reaper's applier connector: teardown through the lease's own socket (releases the applier's admission charge and relay map). Raises on connect failure; the reaper falls back to direct `down` with the recorded warning."""
    _teardown_lease(Path(lease.origin.removeprefix("uds:")), lease)

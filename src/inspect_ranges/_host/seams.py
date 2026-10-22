"""Provider seams derived from a backend's control channel.

A separated backend (the driver on one machine, the range host behind a transport) supplies ONE hook, `channel_for_lease` (`backend.py`), and everything else the provider runtime swaps derives from it here: an `up_fn` that drives `channel.realize` and folds the stage stream back into the `up` contract (`UpResult` or `UpError`; the failed detail's leading up-stage name makes the reverse mapping lossless, an `EAGAIN` refusal folds to `UpError("admission", ...)` so the provider's transient respin classifies it, while `ENOSPC`/`EINVAL`/`ENOTSUP` refusals stay typed `HostRefused`, permanent), a `down_fn` that drives `channel.teardown` (falling back to direct `down` when no lease exists for the project, the fresh-process cleanup case), and a `channel_factory` that re-derives the per-project channel. The seams are sync (they run in the provider's worker threads) and own a private event loop per call.

Extracted from the `uds:` backend's seams so any registered backend inherits the folding rules; the `uds:` backend itself derives through this module (`backend.py`).
"""

import asyncio
import logging
import time
from collections.abc import Callable
from pathlib import Path

from .._channel.channel import HostRefused, MessageChannel
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
from .leases import HostLease, LeaseStore

logger = logging.getLogger("inspect_ranges.host")

ChannelForLease = Callable[[HostLease], MessageChannel]
"""A control channel to the (possibly remote) host a lease names: the one hook a separated backend supplies, from which the runtime derives every other seam it needs. A typical implementation wraps the backend's own `Transport` in a `MessageChannel`, inheriting the whole wire discipline (request ids, retries, budgets, validation)."""

ChannelSeams = tuple[
    Callable[[Path, UpOptions, OnStage | None], UpResult],
    Callable[[str, Path], DownResult],
    Callable[[dict[str, int], str, dict[str, HybridEndpoint]], MessageChannel],
]


def _lease_for_project(store: LeaseStore, project: str) -> HostLease | None:
    for lease in store.leases():
        if lease.project == project:
            return lease
    return None


def realize_gap_allowances(
    plan: ResolvedPlan, options: UpOptions
) -> dict[str | None, float]:
    """Per-gap report allowances for `channel.realize`, keyed by the stage each gap follows (`None` keys the gap before the first report).

    Each gap's allowance is the plan-derived bound of its legitimate occupant, which emits no intermediate report while it runs (quality-review A10, extended to the sibling gaps by R2-3): before the first report sits everything up to `up`'s stage-log creation, worst the first-use range-image build (`IMAGE_BUILD_TIMEOUT_S`); after `construct` sits `compose up --wait` (readiness timeout plus 60 s); after `boot` sits the guest-boot exec (readiness timeout); after `verify` sits the host's whole sequential readiness pass (the readiness deadline plus every guest's minimum probe window). Gaps with no legitimate occupant (`fetch` to `construct`) are deliberately absent, so the flat channel allowance still catches a truly silent host there.

    The HOST runs `up` with its own `UpOptions` (`RealizeRequest` carries no readiness fields), so the readiness-derived envelopes are floored at the defaults the host actually probes with: a driver configured with a SHORTER readiness timeout must not starve a legitimately slower host pass (carrying readiness fields on the wire is the recorded growth path).
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
    channel: MessageChannel,
    bundle: Path,
    project: str,
    on_stage: OnStage | None,
    options: UpOptions,
) -> UpResult:
    """`channel.realize` folded back into the `up` contract (`UpResult` or `UpError`).

    `on_stage` observes each folded report with the DRIVER's clocks at receive time (the seam-stage vocabulary, status `report`): the receive-side half of the clock-offset pairs whose emit side the host's recorder writes host-side (`evidence-v1.md`).
    """
    plan = ResolvedPlan.model_validate_json((bundle / "plan.json").read_text())
    digest = bundle_digest(bundle)  # UpError-typed on an unreadable manifest
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


def channel_teardown(channel_for_lease: ChannelForLease, lease: HostLease) -> None:
    """One lease's teardown through its backend channel, from sync (worker-thread or fresh-process) callers."""

    async def teardown() -> None:
        await channel_for_lease(lease).teardown()

    asyncio.run(teardown())


def derive_channel_seams(
    channel_for_lease: ChannelForLease, state_dir: Path
) -> ChannelSeams:
    """The provider seams a separated backend derives from its channel hook: (`up_fn`, `down_fn`, `channel_factory`).

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
            _drive_realize(channel_for_lease(lease), bundle, project, on_stage, options)
        )

    def down_fn(project: str, state_dir_arg: Path) -> DownResult:
        lease = _lease_for_project(store, project)
        if lease is None:
            # fresh-process cleanup of a project whose lease is already gone:
            # nothing remains to route through the backend, so a direct down
            # clears whatever this machine still holds
            return run_down(project, state_dir=state_dir_arg)
        channel_teardown(channel_for_lease, lease)
        # the host's OkReply carries no removal counts, so zeros here mean
        # "not counted remotely", not "no-op" (a counted teardown reply is a
        # wire-growth candidate, not something to fabricate)
        return DownResult(project=project, containers=0, volumes=0, networks=0)

    def channel_factory(
        cids: dict[str, int], label: str, hybrid_sockets: dict[str, HybridEndpoint]
    ) -> MessageChannel:
        # cids and hybrid_sockets are unused: a separated backend's host dials
        # its own guests (its guest connector), so the client relays by name
        lease = _lease_for_project(store, label)
        if lease is None:
            raise RuntimeError(f"no host lease found for project {label!r}")
        return channel_for_lease(lease)

    return up_fn, down_fn, channel_factory

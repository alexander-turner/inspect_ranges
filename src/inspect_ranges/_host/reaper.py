"""The independent reaper: reclaims expired host leases from on-disk state alone.

Cleanup must never depend on the original driver process reaching `finally` (`host-provider.md`); the reaper runs in a fresh process, reads `leases.json`, and reclaims on expiry alone, never probing liveness (a healthy sample never expires because its driver renews independently of sample activity). Sweep shape, per `range-host-v1.md`: select and mark under the flock (`LeaseStore.mark_reaping`, which re-checks expiry so a just-landed renewal is spared), tear down OUTSIDE the lock, and only after a successful teardown release the project's CID lease, clear the staging and owner record, and remove the host lease LAST: the lease is the retry anchor, so any failure earlier in the release phase leaves it `reaping` and the next sweep genuinely retries. A failed teardown frees nothing (crash-resume works the same way).

For `uds:` leases the reaper prefers teardown through the applier socket (`remote.applier_teardown`, the default connector), which also releases the applier's admission charge and relay map; on connect failure it falls back to direct `down` with a logged warning that a live applier's charge leaks until restart (recorded v1 risk).
"""

import fcntl
import logging
import shutil
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from .._provider.naming import CidAllocator
from .._runtime.down import DownResult
from .._runtime.down import down as run_down
from .._runtime.ownership import remove_project
from .leases import HostLease, LeaseStore

logger = logging.getLogger("inspect_ranges.reaper")

DownFn = Callable[[str, Path], DownResult]
ApplierTeardown = Callable[[HostLease], None]
"""Teardown through the lease's applier socket; raises on connect failure (`remote.applier_teardown` is the real connector)."""


@dataclass(frozen=True)
class ReapOutcome:
    """What one sweep did about one lease."""

    lease_id: str
    project: str
    action: Literal["reaped", "down-failed", "release-failed"]
    error: str | None = None


def _default_down(project: str, state_dir: Path) -> DownResult:
    return run_down(project, state_dir=state_dir)


def _reap_seal(location: str, lease: HostLease) -> None:
    """Best-effort reap-seal of the lease's abandoned evidence record (never raises; failures are logged and reclamation proceeds)."""
    import asyncio

    from .._evidence.sealer import seal_abandoned

    try:
        sealed = asyncio.run(
            seal_abandoned(location, lease_id=lease.lease_id, sample_id=lease.sample_id)
        )
    except Exception as error:
        logger.warning(
            "reaper: reap-seal at %s for lease=%s failed (record stays "
            "unsealed, reported as such by verify): %s",
            location,
            lease.lease_id,
            error,
        )
        return
    if sealed:
        logger.info(
            "reaper: reap-sealed %s writer(s) at %s for lease=%s",
            len(sealed),
            location,
            lease.lease_id,
        )


def sweep(
    state_dir: Path,
    *,
    store: LeaseStore | None = None,
    down_fn: DownFn | None = None,
    applier_teardown: ApplierTeardown | None = None,
) -> list[ReapOutcome]:
    """One reaper pass over `state_dir`: one outcome per expired or `reaping` lease, one summary log line each.

    `store` (which carries the injectable clock) and `down_fn` default to the real thing; tests inject both. The whole pass holds a sweep-level flock, so concurrent reapers (a cron pass overlapping a manual one-shot) serialize instead of double-tearing the same lease; a crashed holder releases the flock with its process, so it can never wedge.
    """
    lease_store = store if store is not None else LeaseStore(state_dir)
    teardown = down_fn if down_fn is not None else _default_down
    if applier_teardown is None:
        from .remote import applier_teardown as default_applier_teardown

        applier_teardown = default_applier_teardown
    allocator = CidAllocator(state_dir)
    state_dir.mkdir(parents=True, exist_ok=True)
    with open(state_dir / ".reaper.lock", "a+") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        try:
            return [
                _reap_one(
                    lease, state_dir, lease_store, allocator, teardown, applier_teardown
                )
                for lease in lease_store.mark_reaping()
            ]
        finally:
            fcntl.flock(lock, fcntl.LOCK_UN)


def _reap_one(
    lease: HostLease,
    state_dir: Path,
    store: LeaseStore,
    allocator: CidAllocator,
    down_fn: DownFn,
    applier_teardown: ApplierTeardown | None,
) -> ReapOutcome:
    torn_down = False
    if lease.origin.startswith("uds:") and applier_teardown is not None:
        try:
            applier_teardown(lease)
            torn_down = True
        except Exception as error:
            logger.warning(
                "reaper: applier teardown of lease=%s project=%s failed (%s); "
                "falling back to direct down (a live applier's admission "
                "charge leaks until restart)",
                lease.lease_id,
                lease.project,
                error,
            )
    if not torn_down:
        try:
            down_fn(lease.project, state_dir)
        except Exception as error:
            logger.error(
                "reaper: down of lease=%s project=%s failed; the lease stays "
                "reaping and the CID lease stays held, both findable for the "
                "next sweep: %s",
                lease.lease_id,
                lease.project,
                error,
            )
            return ReapOutcome(lease.lease_id, lease.project, "down-failed", str(error))
    if lease.evidence_location is not None:
        # after teardown (nothing appends anymore), before release: a dead
        # driver's record gets its `reaped` seal so it stays verifiable.
        # Best-effort by design: evidence trouble never blocks reclamation,
        # and a put-only credential (which cannot replay parts) leaves the
        # record honestly unsealed with a warning (sealer docstring).
        _reap_seal(lease.evidence_location, lease)
    try:
        allocator.release(lease.project)
        shutil.rmtree(Path(lease.staging), ignore_errors=True)
        remove_project(state_dir, lease.project)
        # the host lease goes LAST: it is the retry anchor, so a failure in
        # any step above leaves it reaping and findable
        store.release(lease.lease_id)
    except Exception as error:
        # the lease stays reaping; the next sweep re-runs the (idempotent)
        # teardown and release steps, and a long-lived --interval reaper
        # must survive one bad pass
        logger.error(
            "reaper: releasing lease=%s project=%s after teardown failed; "
            "the next sweep retries: %s",
            lease.lease_id,
            lease.project,
            error,
        )
        return ReapOutcome(lease.lease_id, lease.project, "release-failed", str(error))
    logger.info("reaper: reaped lease=%s project=%s", lease.lease_id, lease.project)
    return ReapOutcome(lease.lease_id, lease.project, "reaped")

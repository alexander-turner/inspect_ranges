"""The independent reaper: reclaims expired host leases from on-disk state alone.

Cleanup must never depend on the original driver process reaching `finally` (`host-provider.md`); the reaper runs in a fresh process, reads `leases.json`, and reclaims on expiry alone, never probing liveness (a healthy sample never expires because its driver renews independently of sample activity). Sweep shape, per `range-host-v1.md`: select and mark under the flock (`LeaseStore.mark_reaping`, which re-checks expiry so a just-landed renewal is spared), tear down OUTSIDE the lock, and only after a successful teardown release the project's CID lease, remove the host lease, and clear the staging and owner record. A failed teardown frees nothing: the lease stays `reaping`, so the next sweep resumes it (crash-resume works the same way).

For `uds:` leases the reaper prefers teardown through the applier socket, which also releases the applier's admission charge and relay map; with no applier teardown available (or on its failure) it falls back to direct `down` with a logged warning that a live applier's charge leaks until restart (recorded v1 risk). The applier connector arrives in slice 3; until then every `uds:` lease takes the fallback.
"""

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
"""Teardown through the lease's applier socket; raises on connect failure (slice 3 provides the real connector)."""


@dataclass(frozen=True)
class ReapOutcome:
    """What one sweep did about one lease."""

    lease_id: str
    project: str
    action: Literal["reaped", "down-failed"]
    error: str | None = None


def _default_down(project: str, state_dir: Path) -> DownResult:
    return run_down(project, state_dir=state_dir)


def sweep(
    state_dir: Path,
    *,
    store: LeaseStore | None = None,
    down_fn: DownFn | None = None,
    applier_teardown: ApplierTeardown | None = None,
) -> list[ReapOutcome]:
    """One reaper pass over `state_dir`: one outcome per expired or `reaping` lease, one summary log line each.

    `store` (which carries the injectable clock) and `down_fn` default to the real thing; tests inject both.
    """
    lease_store = store if store is not None else LeaseStore(state_dir)
    teardown = down_fn if down_fn is not None else _default_down
    allocator = CidAllocator(state_dir)
    return [
        _reap_one(lease, state_dir, lease_store, allocator, teardown, applier_teardown)
        for lease in lease_store.mark_reaping()
    ]


def _reap_one(
    lease: HostLease,
    state_dir: Path,
    store: LeaseStore,
    allocator: CidAllocator,
    down_fn: DownFn,
    applier_teardown: ApplierTeardown | None,
) -> ReapOutcome:
    torn_down = False
    if lease.origin.startswith("uds:"):
        if applier_teardown is None:
            logger.warning(
                "reaper: no applier teardown available for lease=%s project=%s "
                "(origin %s); direct down (a live applier's admission charge "
                "leaks until restart)",
                lease.lease_id,
                lease.project,
                lease.origin,
            )
        else:
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
    allocator.release(lease.project)
    store.release(lease.lease_id)
    shutil.rmtree(Path(lease.staging), ignore_errors=True)
    remove_project(state_dir, lease.project)
    logger.info("reaper: reaped lease=%s project=%s", lease.lease_id, lease.project)
    return ReapOutcome(lease.lease_id, lease.project, "reaped")

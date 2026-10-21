"""Out-of-band oracle attach: `range_oracle("<project>")` binds the oracle verbs to a RUNNING range booted with `inspect-ranges up`.

The attach rebuilds the guest transport from the project's recorded state alone: the owner record under the project state directory proves the project is registered, the `boot.json` recorded beside it by `up` carries every guest's CID and VMM kind, and Cloud Hypervisor guests dial through the project's hybrid-vsock sockets exactly as the provider does (`ch_vsock_dir` plus the CID-derived VMM uid, `SO_PEERCRED`-checked by the transport). A missing or stale project refuses with the state path and the remedy named; nothing is dialed on a refusal.

Local backend only: with `INSPECT_RANGES_HOST` pointing at an applier the guests live behind the applier socket on another host and no attach relay exists yet, so the attach refuses naming the limitation rather than dialing sockets that are not there.

Every attach logs loudly (an out-of-band oracle during a scoring run must be visible in the run's logs), and leaving the context manager detaches the oracle: later verbs refuse instead of silently dialing a range that may since have been torn down.
"""

import logging
import os
from collections.abc import Generator
from contextlib import contextmanager
from pathlib import Path
from typing import TYPE_CHECKING

from pydantic import ValidationError

from .._channel.channel import MessageChannel
from .._channel.vsock import HybridEndpoint, VsockTransport
from .._compiler.plan import Totals
from .._provider.state import SampleHandle
from .._runtime.ownership import (
    ch_vsock_dir,
    default_state_dir,
    project_dir,
    read_owner,
)
from .._runtime.up import (
    BootPlan,
    Runner,
    ch_uid,
    project_containers,
    run_command,
)
from .oracle import OracleSetupError, RangeOracle

if TYPE_CHECKING:
    from .._channel.channel import ByteStream

logger = logging.getLogger("inspect_ranges.oracle")


class _AttachedTransport:
    """The attach's transport: per-guest vsock dialing behind a detach latch.

    Leaving the `range_oracle("<project>")` context flips the latch, so an oracle reference that escapes the `with` block refuses (immediately, before any dial) instead of driving a range that may since have been torn down.
    """

    def __init__(self, inner: VsockTransport, project: str) -> None:
        self._inner = inner
        self._project = project
        self._detached = False

    def detach(self) -> None:
        self._detached = True

    async def connect(self, endpoint: str) -> "ByteStream":
        if self._detached:
            raise OracleSetupError(
                f"the oracle for project {self._project!r} is detached "
                "(its range_oracle context manager exited); attach again "
                "while the range is still up"
            )
        return await self._inner.connect(endpoint)


def attach_endpoints(
    boot: BootPlan, project: str
) -> tuple[dict[str, int], dict[str, HybridEndpoint]]:
    """The transport inputs a recorded boot plan yields: every guest's CID, and the hybrid-vsock endpoint of each Cloud Hypervisor guest.

    The hybrid endpoints are reconstructed the way `up` created them: the socket under `ch_vsock_dir(project)` named after the guest, served by the VMM's CID-derived uid.
    """
    cids = {guest.name: guest.cid for guest in boot.guests}
    sockets_dir = ch_vsock_dir(project)
    hybrid = {
        guest.name: HybridEndpoint(
            sockets_dir / f"{guest.name}.sock", ch_uid(guest.cid)
        )
        for guest in boot.guests
        if guest.vmm == "cloud-hypervisor"
    }
    return cids, hybrid


def _recorded_boot(state_dir: Path, project: str) -> BootPlan:
    """The project's recorded boot plan, with every absence or malformation refused in place.

    Raises:
        OracleSetupError: The project is unregistered under `state_dir`, or its recorded `boot.json` is missing or malformed; the message names the path and the remedy.
    """
    directory = project_dir(state_dir, project)
    if read_owner(state_dir, project) is None:
        raise OracleSetupError(
            f"unknown project {project!r}: no owner record under {directory}; "
            "boot a range with 'inspect-ranges up' (or 'up --from-spec "
            "range.yaml') and attach by the project name it prints"
        )
    boot_path = directory / "boot.json"
    if not boot_path.is_file():
        raise OracleSetupError(
            f"project {project!r} has no recorded boot plan at {boot_path} "
            "(booted by an earlier inspect-ranges version?); tear it down and "
            "boot it again with 'inspect-ranges up' to record one"
        )
    try:
        return BootPlan.model_validate_json(boot_path.read_text())
    except (OSError, ValidationError) as error:
        raise OracleSetupError(
            f"the recorded boot plan at {boot_path} is unreadable or malformed: {error}"
        ) from error


@contextmanager
def attach_oracle(
    project: str,
    *,
    state_dir: Path | None = None,
    runner: Runner | None = None,
) -> Generator[RangeOracle]:
    """Attach an oracle to the running range `project` (the implementation behind `range_oracle("<project>")`).

    `runner` is the docker-query seam (the `up`/`down` pattern); the default runs the real `docker ps` liveness check.

    Raises:
        OracleSetupError: The topology is separated (`INSPECT_RANGES_HOST` set to a non-local backend), the project is unregistered or has no recorded boot plan, or the project is registered but no longer running.
    """
    host_backend = os.environ.get("INSPECT_RANGES_HOST", "local")
    if host_backend != "local":
        raise OracleSetupError(
            f"range_oracle({project!r}) dials this host's guest vsock sockets, "
            f"but INSPECT_RANGES_HOST={host_backend!r} places ranges behind "
            "the applier and no attach relay exists; attach on the host where "
            "the range runs, or unset INSPECT_RANGES_HOST"
        )
    state = state_dir if state_dir is not None else default_state_dir()
    boot = _recorded_boot(state, project)
    run = runner if runner is not None else run_command
    if not project_containers(run, project):
        raise OracleSetupError(
            f"project {project!r} is registered under "
            f"{project_dir(state, project)} but has no running containers; "
            "the range is down or crashed, so boot it again with "
            "'inspect-ranges up' before attaching"
        )
    cids, hybrid = attach_endpoints(boot, project)
    transport = _AttachedTransport(VsockTransport(cids, hybrid_sockets=hybrid), project)
    handle = SampleHandle(
        project=project,
        task_name="oracle-attach",
        staging=project_dir(state, project),
        # nothing charges or releases an attach: the totals are bookkeeping
        # the provider's admission gate never sees
        totals=Totals(guests=len(cids), cpus=0, memory_mb=0),
        cid_base=min(cids.values()),
        guest_cids=cids,
        guest_sockets=hybrid,
        channel=MessageChannel(transport, label=f"oracle-attach-{project}"),
    )
    logger.warning(
        "out-of-band oracle attached to project %s (%d guests): privileged "
        "range access outside any eval sample; never attach during a scoring "
        "run",
        project,
        len(cids),
    )
    try:
        yield RangeOracle(handle)
    finally:
        transport.detach()
        logger.info("out-of-band oracle detached from project %s", project)

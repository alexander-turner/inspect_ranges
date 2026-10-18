"""Capture of provisioned guests into realized images (build-v1 slice 5).

After verification passes, each rebuilt guest is shut down cleanly (an in-guest `systemctl poweroff` over the channel, then a `virsh domstate` poll inside the range container until `shut off`), its per-guest overlay is copied out of the range container's scratch, rebased onto its golden's cache file name (relative backing, the cache convention), digested, and moved into the image cache atomically with a `.realized.json` provenance sidecar. The realized image is a boot-fresh scenario image in the Q4 sense: a chained qcow2 delta the runtime boots per sample with its own overlay on top.

Clean shutdown before capture is the slice-5 decision's crash-consistency rule: the captured disk is a cleanly unmounted filesystem, never a crash image. Captures run only for rebuilt guests; reused guests carry their prior manifest records forward.
"""

import asyncio
import fcntl
import subprocess
import time
from collections.abc import Callable, Generator
from contextlib import contextmanager
from pathlib import Path

from pydantic import BaseModel, ConfigDict

from .._channel.channel import MessageChannel, request_id
from .._channel.protocol import Budget, ExecRequest
from .._channel.vsock import VsockTransport
from .._runtime.images import sha256_file
from .errors import BuildError

CaptureRunner = Callable[[list[str]], str]
"""Host-command seam for docker/qemu-img/virsh calls; returns stdout, raises on failure."""

SHUTOFF_TIMEOUT_S = 120.0


class RealizedImageMeta(BaseModel):
    """Provenance sidecar (`<file>.realized.json`) for a captured realized image."""

    model_config = ConfigDict(frozen=True)

    type: str = "realized"
    range_name: str
    guest: str
    build_key: str
    golden_file: str
    sha256: str
    created: str


def default_capture_runner(argv: list[str]) -> str:
    """Run a host command for capture, surfacing stderr in the failure."""
    completed = subprocess.run(argv, capture_output=True, timeout=300)
    if completed.returncode != 0:
        stderr = completed.stderr.decode(errors="replace").strip()[-300:]
        raise BuildError(
            "capture",
            f"{argv[0]} {argv[1] if len(argv) > 1 else ''} exited {completed.returncode}: {stderr or '(no stderr)'}",
        )
    return completed.stdout.decode(errors="replace")


def scrub_guest(cids: dict[str, int], guest: str) -> None:
    """Pre-capture cleanup so the realized image is a clean golden-like artifact (parked-decisions item 2): `cloud-init clean --logs` removes the build boot's instance state (every runtime boot then seeds fresh) and the build seed's rendered netplan goes with it, so neither the build's egress nameserver (a deployment's VPC resolver IP) nor an already-run marker survives into the captured disk.

    Raises:
        BuildError: stage `capture`, when the scrub itself fails; a dirty capture must not pass silently.
    """

    async def scrub() -> None:
        channel = MessageChannel(VsockTransport(cids), label="build-capture")
        outcome = await channel.exec(
            guest,
            ExecRequest(
                id=request_id(),
                cmd=[
                    "sh",
                    "-c",
                    "cloud-init clean --logs && rm -f /etc/netplan/50-cloud-init.yaml",
                ],
                user="root",
                budget=Budget(command_ms=30_000),
            ),
        )
        if outcome.rc != 0:
            raise BuildError(
                "capture",
                f"pre-capture scrub exited {outcome.rc}: "
                f"{outcome.stderr.decode(errors='replace')[-200:]}",
                guest=guest,
            )

    asyncio.run(scrub())


def shutdown_guest(cids: dict[str, int], guest: str) -> str | None:
    """Ask the guest to power off cleanly; the channel dying mid-call is the expected outcome.

    Returns a short diagnosis when the poweroff visibly did NOT take (a nonzero exit from `systemctl poweroff`), else None; `wait_shutoff` folds it into its timeout error so a never-delivered poweroff is not reported as a slow one (round-1 review).
    """

    async def poweroff() -> str | None:
        channel = MessageChannel(VsockTransport(cids), label="build-capture")
        try:
            outcome = await channel.exec(
                guest,
                ExecRequest(
                    id=request_id(),
                    cmd=["systemctl", "poweroff"],
                    user="root",
                    budget=Budget(command_ms=5_000),
                ),
            )
        except Exception:
            return None  # the daemon dies with the guest; silence is success here
        if outcome.rc != 0:
            return (
                f"systemctl poweroff exited {outcome.rc}: "
                f"{outcome.stderr.decode(errors='replace')[-120:]}"
            )
        return None

    return asyncio.run(poweroff())


def wait_shutoff(
    runner: CaptureRunner,
    project: str,
    guest: str,
    timeout_s: float = SHUTOFF_TIMEOUT_S,
    *,
    shutdown_diagnosis: str | None = None,
) -> None:
    """Poll the domain state inside the range container until the guest is shut off.

    Raises:
        BuildError: stage `capture` when the guest does not reach `shut off` within the bound; carries `shutdown_diagnosis` when the poweroff itself visibly failed.
    """
    container = f"{project}-range-1"
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            state = runner(
                [
                    "docker",
                    "exec",
                    container,
                    "virsh",
                    "--connect",
                    "qemu:///system",
                    "domstate",
                    guest,
                ]
            ).strip()
        except BuildError:
            state = ""
        if "shut off" in state:
            return
        time.sleep(2.0)
    detail = f" ({shutdown_diagnosis})" if shutdown_diagnosis else ""
    raise BuildError(
        "capture",
        f"guest did not reach 'shut off' within {timeout_s:.0f} s after poweroff{detail}",
        guest=guest,
    )


def capture_guest(
    runner: CaptureRunner,
    project: str,
    guest: str,
    *,
    image_cache: Path,
    golden_file: str,
    realized_name: str,
    meta: RealizedImageMeta,
) -> str:
    """Copy the guest's provisioned overlay into the cache as a realized image; returns its sha256.

    The overlay is rebased (unsafe rebase, metadata only) onto the golden's cache file name so the chain resolves relatively inside the cache, exactly like derived goldens.
    """
    container = f"{project}-range-1"
    staging = image_cache / f".{realized_name}.capturing"
    sidecar = image_cache / f"{realized_name.removesuffix('.qcow2')}.realized.json"
    try:
        with _name_lock(image_cache, realized_name):
            return _capture_locked(
                runner,
                container,
                guest,
                image_cache,
                golden_file,
                realized_name,
                staging,
                sidecar,
                meta,
            )
    finally:
        staging.unlink(missing_ok=True)


def _capture_locked(
    runner: CaptureRunner,
    container: str,
    guest: str,
    image_cache: Path,
    golden_file: str,
    realized_name: str,
    staging: Path,
    sidecar: Path,
    meta: RealizedImageMeta,
) -> str:
    # a crashed prior capture may have left temps; we hold the lock
    staging.unlink(missing_ok=True)
    sidecar.with_suffix(".json.capturing").unlink(missing_ok=True)
    try:
        runner(["docker", "cp", f"{container}:/scratch/{guest}.qcow2", str(staging)])
        runner(
            ["qemu-img", "rebase", "-u", "-F", "qcow2", "-b", golden_file, str(staging)]
        )
        digest = sha256_file(staging)
        sidecar_temp = sidecar.with_suffix(".json.capturing")
        sidecar_temp.write_text(
            meta.model_copy(update={"sha256": digest}).model_dump_json(indent=2) + "\n"
        )
        # the image lands first: a crash between the two placements must
        # never leave a sidecar describing a file that is not there (round-1)
        staging.replace(image_cache / realized_name)
        sidecar_temp.replace(sidecar)
        return digest
    finally:
        staging.unlink(missing_ok=True)


def live_project_files(state_dir: Path) -> set[str]:
    """Every image or backing file a registered project's boot.json references: the precise concurrent-consumer exclusion for GC and prune (a stale owner record over-retains, which is the safe direction)."""
    import json

    from .._runtime.ownership import list_projects, read_owner

    files: set[str] = set()
    try:
        projects = list_projects(state_dir)
    except OSError:
        return files
    for project in projects:
        owner = read_owner(state_dir, project)
        if owner is None:
            continue
        try:
            boot = json.loads((Path(owner.bundle) / "boot.json").read_text())
            for guest in boot.get("guests", []):
                for field in ("image_file", "backing_file"):
                    value = guest.get(field)
                    if value:
                        files.add(str(value))
        except (OSError, ValueError):
            continue
    return files


def collect_realized_garbage(
    range_name: str,
    image_cache: Path,
    keep_files: set[str],
) -> tuple[int, int]:
    """Delete this range's realized images (and sidecars) whose file name is not in `keep_files`, each under its name lock; returns (files deleted, bytes reclaimed).

    The caller owns the liveness policy (parked-decisions item 1: the current manifest's generation, the immediately-prior one, and anything a running project references); this sweep only identifies candidates by their sidecars' recorded `range_name` and deletes what the caller did not keep. Unreadable sidecars are skipped (they surface through `images list`, and `images prune` handles orphans).
    """
    deleted = 0
    reclaimed = 0
    for sidecar in sorted(image_cache.glob("*.realized.json")):
        try:
            meta = RealizedImageMeta.model_validate_json(sidecar.read_text())
        except (OSError, ValueError):
            continue
        if meta.range_name != range_name:
            continue
        image_name = sidecar.name.removesuffix(".realized.json") + ".qcow2"
        if image_name in keep_files:
            continue
        image = image_cache / image_name
        with _name_lock(image_cache, image_name):
            try:
                size = image.stat().st_size if image.is_file() else 0
                image.unlink(missing_ok=True)
                sidecar.unlink(missing_ok=True)
                deleted += 1
                reclaimed += size
            except OSError:
                continue  # a stuck file surfaces through images list / prune
    return deleted, reclaimed


@contextmanager
def _name_lock(cache: Path, file: str) -> Generator[None]:
    """Per-name advisory lock (the images.py cache discipline): concurrent captures of one realized name serialize."""
    lock_path = cache / f".{file}.lock"
    with open(lock_path, "w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(lock, fcntl.LOCK_UN)

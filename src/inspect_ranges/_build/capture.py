"""Capture of provisioned guests into realized images (build-v1 slice 5).

After verification passes, each rebuilt guest is shut down cleanly (an in-guest `systemctl poweroff` over the channel, then a `virsh domstate` poll inside the range container until `shut off`), its per-guest overlay is copied out of the range container's scratch, rebased onto its golden's cache file name (relative backing, the cache convention), digested, and moved into the image cache atomically with a `.realized.json` provenance sidecar. The realized image is a boot-fresh scenario image in the Q4 sense: a chained qcow2 delta the runtime boots per sample with its own overlay on top.

Clean shutdown before capture is the slice-5 decision's crash-consistency rule: the captured disk is a cleanly unmounted filesystem, never a crash image. Captures run only for rebuilt guests; reused guests carry their prior manifest records forward.
"""

import asyncio
import subprocess
import time
from collections.abc import Callable
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


def shutdown_guest(cids: dict[str, int], guest: str) -> None:
    """Ask the guest to power off cleanly; the channel dying mid-call is the expected outcome."""

    async def poweroff() -> None:
        channel = MessageChannel(VsockTransport(cids), label="build-capture")
        try:
            await channel.exec(
                guest,
                ExecRequest(
                    id=request_id(),
                    cmd=["systemctl", "poweroff"],
                    user="root",
                    budget=Budget(command_ms=5_000),
                ),
            )
        except Exception:
            return  # the daemon dies with the guest; silence is success here

    asyncio.run(poweroff())


def wait_shutoff(
    runner: CaptureRunner,
    project: str,
    guest: str,
    timeout_s: float = SHUTOFF_TIMEOUT_S,
) -> None:
    """Poll the domain state inside the range container until the guest is shut off.

    Raises:
        BuildError: stage `capture` when the guest does not reach `shut off` within the bound.
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
    raise BuildError(
        "capture",
        f"guest did not reach 'shut off' within {timeout_s:.0f} s after poweroff",
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
        runner(["docker", "cp", f"{container}:/scratch/{guest}.qcow2", str(staging)])
        runner(
            ["qemu-img", "rebase", "-u", "-F", "qcow2", "-b", golden_file, str(staging)]
        )
        digest = sha256_file(staging)
        sidecar_temp = sidecar.with_suffix(".json.capturing")
        sidecar_temp.write_text(
            meta.model_copy(update={"sha256": digest}).model_dump_json(indent=2) + "\n"
        )
        sidecar_temp.replace(sidecar)
        staging.replace(image_cache / realized_name)
        return digest
    finally:
        staging.unlink(missing_ok=True)

"""ch-vmm battery probe: boot a range whose attacker runs on cloud-hypervisor, prove the hybrid channel, the unprivileged VMM, and the bridged dataplane."""

import asyncio
import secrets
import subprocess
import sys
import tempfile
from pathlib import Path

from inspect_ranges._channel.channel import MessageChannel
from inspect_ranges._channel.protocol import Budget, ExecRequest
from inspect_ranges._channel.vsock import VsockTransport
from inspect_ranges._compiler import render_bundle
from inspect_ranges._compiler.plan import PlanOptions
from inspect_ranges._runtime.down import down
from inspect_ranges._runtime.ownership import default_state_dir
from inspect_ranges._runtime.up import UpOptions, ch_uid, up
from inspect_ranges.types import (
    Attacker,
    Host,
    Interface,
    Network,
    Os,
    RangeMeta,
    RangeSpec,
)

CHECKS: list[tuple[bool, str]] = []


def check(ok: bool, label: str) -> None:
    CHECKS.append((ok, label))
    print(f"{'PASS ' if ok else 'FAIL '} {label}", flush=True)


def spec() -> RangeSpec:
    return RangeSpec(
        meta=RangeMeta(name="chvmm", description="cloud-hypervisor live battery"),
        networks=[Network(name="lab", cidr="10.39.0.0/24", mode="isolated")],
        hosts=[
            Host(
                name="web",
                os=Os(type="linux"),
                image="ch-golden",
                interfaces=[Interface(network="lab", ip="10.39.0.10")],
            )
        ],
        attacker=Attacker(
            image="ch-golden",
            vmm="cloud-hypervisor",
            interfaces=[Interface(network="lab")],
            entry="external",
        ),
    )


def main() -> int:
    image_cache = Path(sys.argv[1])
    state_dir = default_state_dir()
    staging = Path(tempfile.mkdtemp(prefix="chvmm-"))
    staging.chmod(0o755)
    render_bundle(spec(), staging, PlanOptions(image_cache=image_cache, cid_base=3900))
    result = up(
        staging,
        UpOptions(
            project="ir-chvmm-battery",
            image_cache=image_cache,
            state_dir=state_dir,
            readiness_timeout=300.0,
            keep_on_failure=False,
        ),
    )
    try:
        states = {guest.name: guest for guest in result.guests}
        check(
            all(guest.ready for guest in result.guests),
            "C1 both guests ready (CH readiness rides the hybrid channel)",
        )
        attacker = states["attacker"]
        check(
            attacker.hybrid_vsock is not None,
            "C2 the attacker reports its hybrid-vsock endpoint",
        )
        cids = {g.name: g.cid for g in result.guests}
        hybrid = {
            g.name: g.hybrid_vsock
            for g in result.guests
            if g.hybrid_vsock is not None
        }
        channel = MessageChannel(
            VsockTransport(cids, hybrid_sockets=hybrid), label="chvmm"
        )

        async def execute(guest: str, cmd: str) -> tuple[int, str]:
            outcome = await channel.exec(
                guest,
                ExecRequest(
                    id=secrets.token_hex(16),
                    cmd=["sh", "-c", cmd],
                    user="root",
                    data_size=0,
                    budget=Budget(command_ms=30_000),
                ),
                stdin=b"",
            )
            return outcome.rc, outcome.stdout.decode(errors="replace").strip()

        async def probes() -> None:
            rc, out = await execute("attacker", "hostname")
            check(rc == 0 and out == "attacker", f"C3 exec on the CH guest over hybrid vsock (hostname={out!r})")
            rc, out = await execute("web", "hostname")
            check(rc == 0 and out == "web", f"C4 the qemu sibling is unaffected (hostname={out!r})")
            rc, out = await execute("attacker", "ping -c 1 -W 3 10.39.0.10 >/dev/null && echo reached")
            check(rc == 0 and out == "reached", "C5 the CH guest's bridged tap carries the lab segment")

        asyncio.run(probes())

        container = "ir-chvmm-battery-range-1"
        pid = subprocess.run(
            ["docker", "exec", container, "cat", "/scratch/ch/attacker.pid"],
            capture_output=True,
            text=True,
        ).stdout.strip()
        uid = subprocess.run(
            ["docker", "exec", container, "ps", "-o", "uid=", "-p", pid],
            capture_output=True,
            text=True,
        ).stdout.strip()
        check(
            uid == str(ch_uid(attacker.cid)),
            f"C6 the VMM runs as its own unprivileged uid (uid={uid}, expected {ch_uid(attacker.cid)})",
        )
        console = subprocess.run(
            ["docker", "exec", container, "test", "-s", "/scratch/console/attacker.log"],
            capture_output=True,
        )
        check(console.returncode == 0, "C7 the CH guest's serial console log is non-empty")
    finally:
        down("ir-chvmm-battery", state_dir=state_dir, keep_state=False)
    leftovers = subprocess.run(
        ["docker", "ps", "-aq", "--filter", "name=ir-chvmm"],
        capture_output=True,
        text=True,
    ).stdout.strip()
    from inspect_ranges._runtime.ownership import ch_vsock_dir

    check(
        leftovers == "" and not ch_vsock_dir("ir-chvmm-battery").exists(),
        "C8 down removed the containers and the hybrid socket dir",
    )
    failed = sum(1 for ok, _ in CHECKS if not ok)
    print(f"\n{len(CHECKS) - failed} passed, {failed} failed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())

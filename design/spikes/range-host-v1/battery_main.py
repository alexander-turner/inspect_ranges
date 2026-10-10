#!/usr/bin/env python3
"""range-host-v1 slice-4 battery main: the separated topology on one host, for real.

A REAL `inspect-ranges applier` process serves the socket; this script is the real driver process. Stages: (A) realize-to-ready of the multi-guest range with the stage stream observed in seam vocabulary and the heartbeat polled across the whole lifecycle (pending/booting during realize, ready after, connect-refusal after teardown); (B) the portable conformance suite over the LIVE applier with `realize_digest()` pointed at a genuinely rendered bundle, driven in three sequential pytest phases (realize boots the suite's own range; guest tests ride the registered relay; teardown closes it); (C) inspect-ai's full `self_check` (44 checks, EMPTY two-sided pin) through `RemoteRangeHost` on a realizer-booted range reached purely through the registered entry point with `INSPECT_RANGES_HOST=uds:`, plus the local-versus-UDS wall-clock comparison.

Battery CID band: 20000+ for the battery's own direct allocations (documented beside the other bands in naming.py); provider-driven samples ride the allocator's 10000+ partition as in production.
"""

import asyncio
import json
import os
import subprocess
import sys
import time
from pathlib import Path

SPIKE = Path(__file__).parent
SPEC = SPIKE / "range.yaml"
ROOT = SPIKE.parent.parent.parent
sys.path.insert(0, str(SPIKE))
from applier_proc import SOCKET, start_applier  # noqa: E402 - spike-local helper

TASK = "range-host-battery"

failures: list[str] = []
timings: dict[str, float] = {}


def check(name: str, good: bool, detail: str = "") -> None:
    print(f"{'PASS ' if good else 'FAIL '} {name}" + (f"  [{detail}]" if detail and not good else ""))
    if not good:
        failures.append(name)


async def observed_realize(state_dir: Path, image_cache: Path) -> None:
    """Stage A: the seam-vocabulary stage stream, heartbeat across the lifecycle, relayed pings to real guests."""
    from inspect_ranges._compiler.plan import PlanOptions
    from inspect_ranges._compiler.render import render_bundle
    from inspect_ranges._host import LeasePlacement, RemoteHostProvider, SampleSpec
    from inspect_ranges._provider.naming import CidAllocator
    from inspect_ranges._runtime.up import bundle_digest
    from inspect_ranges.schema import load_range

    spec = load_range(SPEC)
    allocator = CidAllocator(state_dir, base=20_000)
    cid_lease = allocator.lease("ir-rh-observed", 2)
    check("battery CID lease sits in the 20000+ band", cid_lease.base >= 20_000, str(cid_lease.base))
    staging = SPIKE / "tmp" / "observed"
    bundle = staging / "bundle"
    plan = render_bundle(spec, bundle, PlanOptions(image_cache=image_cache, cid_base=cid_lease.base))
    digest = bundle_digest(bundle)
    provider = RemoteHostProvider(SOCKET, state_dir)
    host = await provider.acquire(
        SampleSpec(
            sample_id="observed",
            task_name=TASK,
            spec_sha256=plan.range.spec_sha256,
            bundle_digest=digest,
            totals=plan.totals,
        ),
        LeasePlacement(project="ir-rh-observed", bundle_path=str(bundle), staging=str(staging)),
    )
    channel = host.channel
    assert channel is not None

    snapshots: list[dict[str, str]] = []
    polling = True

    async def poll_heartbeat() -> None:
        while polling:
            try:
                beat = await channel.heartbeat()
                snapshots.append(dict(beat.guests))
            except Exception:  # noqa: BLE001 - the poller must survive transient windows
                pass
            await asyncio.sleep(1.0)

    poller = asyncio.ensure_future(poll_heartbeat())
    started = time.monotonic()
    reports = [report async for report in channel.realize(digest, [])]
    timings["observed realize to ready"] = time.monotonic() - started
    polling = False
    await poller
    stages = [report.stage for report in reports]
    check("stage stream is the seam sequence", stages == ["fetch", "construct", "boot", "verify", "ready"], str(stages))
    construct = next(report for report in reports if report.stage == "construct")
    check(
        "construct detail carries the triggering up stage",
        construct.detail in ("prepare", "range-image", "range-container"),
        construct.detail,
    )
    mid_states = {state for snap in snapshots for state in snap.values()}
    check(
        "heartbeat saw pending/booting during realize",
        bool(mid_states & {"pending", "booting"}),
        str(snapshots[:5]),
    )
    after = await channel.heartbeat()
    check("heartbeat reads ready after realize", set(after.guests.values()) == {"ready"}, str(after.guests))
    for guest in ("attacker", "web"):
        pong = await channel.ping(guest)
        check(f"relayed ping reaches the real {guest} daemon", pong.protocol == 3)

    await channel.teardown()
    await provider.release(host)
    allocator.release("ir-rh-observed")
    refused = ""
    try:
        await channel.heartbeat()
    except Exception as error:  # noqa: BLE001 - the released lease refuses at the preamble
        refused = f"{type(error).__name__}: {error}"
    check(
        "heartbeat after teardown+release is refused at connect",
        bool(refused) and ("lost" in refused or "refused" in refused),
        refused or "heartbeat unexpectedly succeeded",
    )


async def live_conformance(state_dir: Path, image_cache: Path) -> None:
    """Stage B: the portable suite over the live applier, realize_digest at a real rendered bundle (three sequential phases)."""
    from inspect_ranges._compiler.plan import PlanOptions
    from inspect_ranges._compiler.render import render_bundle
    from inspect_ranges._host import LeasePlacement, RemoteHostProvider, SampleSpec
    from inspect_ranges._provider.naming import CidAllocator
    from inspect_ranges._runtime.up import bundle_digest
    from inspect_ranges.schema import load_range

    spec = load_range(SPEC)
    allocator = CidAllocator(state_dir, base=20_000)
    cid_lease = allocator.lease("ir-rh-conform", 2)
    staging = SPIKE / "tmp" / "conform"
    bundle = staging / "bundle"
    plan = render_bundle(spec, bundle, PlanOptions(image_cache=image_cache, cid_base=cid_lease.base))
    digest = bundle_digest(bundle)
    provider = RemoteHostProvider(SOCKET, state_dir)
    host = await provider.acquire(
        SampleSpec(
            sample_id="conform",
            task_name=TASK,
            spec_sha256=plan.range.spec_sha256,
            bundle_digest=digest,
            totals=plan.totals,
        ),
        LeasePlacement(project="ir-rh-conform", bundle_path=str(bundle), staging=str(staging)),
    )
    env = {
        **os.environ,
        "IR_UDS_BATTERY_SOCKET": str(SOCKET),
        "IR_UDS_BATTERY_LEASE": host.lease.lease_id,
        "IR_UDS_BATTERY_DIGEST": digest,
        "IR_UDS_BATTERY_GUEST": "attacker",
    }

    def phase(expr: str, name: str) -> None:
        proc = subprocess.run(
            [
                sys.executable, "-m", "pytest", "tests/test_channel_uds.py", "-q", "-n", "0",
                "-k", f"TestUdsLiveApplier and ({expr})",
            ],
            cwd=ROOT,
            env=env,
            capture_output=True,
            text=True,
            timeout=1800,
        )
        tail = "\n".join(proc.stdout.splitlines()[-3:])
        print(f"       {name} tail: {tail.strip()[:200]}")
        check(f"portable suite over the live applier: {name}", proc.returncode == 0, tail)

    try:
        started = time.monotonic()
        phase("test_realize_streams_stages_to_ready", "realize phase (boots the range)")
        timings["suite realize phase (incl. pytest startup)"] = time.monotonic() - started
        phase(
            "not test_realize_streams_stages_to_ready and not test_teardown_acknowledges",
            "guest plane + heartbeat over the relay",
        )
        phase("test_teardown_acknowledges", "teardown phase")
    finally:
        await provider.release(host)
        allocator.release("ir-rh-conform")


async def self_check_and_timings(state_dir: Path) -> None:
    """Stage C: self_check 44/44 (EMPTY pin) through the entry point over `uds:`, then the local-versus-UDS wall clock."""
    import inspect_ai.util._sandbox.self_check as self_check_module
    from inspect_ai._util.entrypoints import ensure_entry_points
    from inspect_ai.util._sandbox.lifecycle import sandbox_lifecycle_scope
    from inspect_ai.util._sandbox.registry import registry_find_sandboxenv

    ensure_entry_points()
    env_type = registry_find_sandboxenv("libvirt_range")

    async def boot_and_cleanup(backend: str, run_checks: bool) -> float:
        os.environ["INSPECT_RANGES_HOST"] = backend
        started = time.monotonic()
        with sandbox_lifecycle_scope():
            await env_type.task_init(TASK, str(SPEC))
            envs = await env_type.sample_init(TASK, str(SPEC), {"__sample_id__": backend.split(":")[0]})
            try:
                attacker, web = envs["attacker"], envs["web"]
                result = await attacker.exec(["id", "-un"])
                check(f"[{backend.split(':')[0]}] exec runs as agent", result.success and result.stdout.strip() == "agent", result.stderr)
                if run_checks:
                    handle = attacker._handle
                    lease = handle.host.lease
                    check("the sample's lease is uds-origin", lease.origin.startswith("uds:"), lease.origin)
                    ping = await attacker.exec(["ping", "-c", "1", "-W", "2", "10.92.10.10"])
                    check("attacker reaches web over the compiled segment", ping.success, ping.stderr)
                    await web.write_file("probe.txt", "cross-guest")
                    body = await web.read_file("probe.txt")
                    check("file round trip on the named guest over the relay", body == "cross-guest")
                    checks = [(name, getattr(self_check_module, name)) for name in self_check_module.__all__]
                    check("self_check exports 44 checks", len(checks) == 44, str(len(checks)))
                    failed: list[tuple[str, str]] = []
                    for name, fn in sorted(checks):
                        try:
                            await fn(attacker)
                        except Exception as error:  # noqa: BLE001 - tally and report
                            failed.append((name, f"{type(error).__name__}: {error}"))
                    for name, reason in failed:
                        print(f"       self_check FAIL {name}: {reason[:140]}")
                    check("self_check 44/44 through RemoteRangeHost (empty pin)", not failed, f"{len(failed)} failed")
            finally:
                try:
                    await env_type.sample_cleanup(TASK, str(SPEC), envs, False)
                finally:
                    await env_type.task_cleanup(TASK, str(SPEC), True)
        return time.monotonic() - started

    timings["uds boot+battery+teardown"] = await boot_and_cleanup(f"uds:{SOCKET}", run_checks=True)
    timings["uds boot+teardown only"] = await boot_and_cleanup(f"uds:{SOCKET}", run_checks=False)
    timings["local boot+teardown only"] = await boot_and_cleanup("local", run_checks=False)
    os.environ["INSPECT_RANGES_HOST"] = f"uds:{SOCKET}"


async def main() -> int:
    from inspect_ranges._runtime.ownership import default_state_dir

    state_dir = default_state_dir()
    image_cache = Path(os.environ["INSPECT_RANGES_IMAGE_CACHE"])
    (SPIKE / "tmp" / "logs").mkdir(parents=True, exist_ok=True)
    applier = start_applier(ROOT, state_dir, SPIKE / "tmp" / "logs" / "applier-main.txt")
    check("applier process is serving", applier.poll() is None)
    try:
        await observed_realize(state_dir, image_cache)
        await live_conformance(state_dir, image_cache)
        await self_check_and_timings(state_dir)
    finally:
        applier.terminate()
        applier.wait(timeout=10)
    (SPIKE / "tmp" / "timings.json").write_text(json.dumps(timings, indent=2))
    for name, seconds in timings.items():
        print(f"       timing: {name}: {seconds:.1f}s")
    if failures:
        print(f"{len(failures)} battery checks failed: {failures}")
        return 1
    print("all battery_main checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))

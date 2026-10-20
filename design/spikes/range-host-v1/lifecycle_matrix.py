#!/usr/bin/env python3
"""range-host-v1 slice-4 lifecycle matrix: the lease lifecycle against real VMs and a real applier.

Scenarios, in order: two concurrent samples through ONE applier (distinct leases, wall-time concurrency proven as total elapsed well under the sum of the two boot durations, same-name guests reaching their own guests, disjoint CID blocks, independent teardowns); a failing teardown under `RemoteRangeHost` (the applier killed mid-sample) leaving lease, CID lease, and registry findable with NOTHING freed, then an applier restart serving a NEW sample cleanly while the old sample's teardown recovers from disk; kill -9 of a driver mid-sample with a fresh-shell `inspect-ranges reaper` reclaiming through the live applier after expiry; and forced expiry mid-sample (the reaper-versus-renewal race pinned both ways against the real store) with the driver failing loudly as `LeaseLostError`.

Runs with a short lease TTL (`INSPECT_RANGES_LEASE_TTL_S=12`, renewal every 4 s) so expiry-driven scenarios complete in seconds.
"""

import asyncio
import json
import os
import subprocess
import sys
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path

SPIKE = Path(__file__).parent
SPEC = SPIKE / "range.yaml"
ROOT = SPIKE.parent.parent.parent
sys.path.insert(0, str(SPIKE))
from applier_proc import SOCKET, start_applier  # noqa: E402 - spike-local helper

TASK = "range-host-matrix"
TTL_S = 12.0

os.environ["INSPECT_RANGES_LEASE_TTL_S"] = str(TTL_S)
os.environ["INSPECT_RANGES_HOST"] = f"uds:{SOCKET}"

failures: list[str] = []
evidence: dict[str, object] = {}


def check(name: str, good: bool, detail: str = "") -> None:
    print(f"{'PASS ' if good else 'FAIL '} {name}" + (f"  [{detail}]" if detail and not good else ""))
    if not good:
        failures.append(name)


def running_project_containers(project: str) -> int:
    out = subprocess.run(
        ["docker", "ps", "--format", "{{.Names}}"], capture_output=True, text=True
    ).stdout
    return sum(1 for line in out.splitlines() if line.startswith(project))


def force_expire(state_dir: Path, lease_id: str) -> None:
    """Rewrite one lease's absolute expiry into the past (expiry is the contract; no liveness is consulted)."""
    from inspect_ranges._host import LeaseStore

    store = LeaseStore(state_dir)
    lease = store.get(lease_id)
    assert lease is not None
    past = (datetime.now(UTC) - timedelta(seconds=60)).isoformat()
    with store._registry.locked(write=True) as view:  # noqa: SLF001 - battery surgery
        view.entries[lease_id] = lease.model_copy(update={"expires_at": past})


def run_reaper(state_dir: Path) -> "subprocess.CompletedProcess[str]":
    return subprocess.run(
        ["uv", "run", "inspect-ranges", "reaper", "--state-dir", str(state_dir)],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=300,
    )


async def concurrent_samples(env_type: object, state_dir: Path) -> None:
    from inspect_ranges._host import LeaseStore

    durations: dict[str, float] = {}

    async def boot(sample: str) -> dict[str, object]:
        started = time.monotonic()
        envs = await env_type.sample_init(TASK, str(SPEC), {"__sample_id__": sample})
        durations[sample] = time.monotonic() - started
        return envs

    gathered = time.monotonic()
    first, second = await asyncio.gather(boot("c1"), boot("c2"))
    elapsed_total = time.monotonic() - gathered
    try:
        # window-overlap checks around gathered awaits are vacuous (they
        # overlap by construction); wall time versus the sum of durations is
        # what actually proves concurrency
        serial_sum = durations["c1"] + durations["c2"]
        check(
            "two boots complete in well under the sum of their durations",
            elapsed_total < 0.8 * serial_sum,
            f"total={elapsed_total:.1f}s vs sum={serial_sum:.1f}s",
        )
        leases = LeaseStore(state_dir).leases()
        check("two distinct leases held", len(leases) == 2 and leases[0].lease_id != leases[1].lease_id)
        handles = [first["attacker"]._handle, second["attacker"]._handle]
        spans = sorted(
            (handle.cid_base, handle.cid_base + handle.totals.guests) for handle in handles
        )
        check("CID blocks are disjoint", spans[0][1] <= spans[1][0], str(spans))
        await first["web"].write_file("who.txt", "sample-one")
        await second["web"].write_file("who.txt", "sample-two")
        one = await first["web"].read_file("who.txt")
        two = await second["web"].read_file("who.txt")
        check(
            "same-name guests reach their own guests through one applier",
            one == "sample-one" and two == "sample-two",
            f"{one!r} {two!r}",
        )
        evidence["concurrency"] = {
            "durations": durations,
            "elapsed_total": round(elapsed_total, 1),
            "spans": spans,
        }
        await env_type.sample_cleanup(TASK, str(SPEC), first, False)
        still = await second["web"].exec(["echo", "alive"])
        check("the surviving sample serves ops after the other's teardown", still.success and still.stdout == "alive\n")
    finally:
        await env_type.sample_cleanup(TASK, str(SPEC), second, False)
    check("both samples' leases released", LeaseStore(state_dir).leases() == [])


async def wedged_teardown_and_restart(
    env_type: object, state_dir: Path, procs: "dict[str, subprocess.Popen[bytes]]"
) -> None:
    from inspect_ranges._host import LeaseStore
    from inspect_ranges._provider.state import provider_runtime

    applier = procs["applier"]
    envs = await env_type.sample_init(TASK, str(SPEC), {"__sample_id__": "wedge"})
    project = envs["attacker"]._handle.project
    applier.kill()
    applier.wait(timeout=10)
    raised = ""
    try:
        await env_type.sample_cleanup(TASK, str(SPEC), envs, False)
    except Exception as error:  # noqa: BLE001 - the wedge is the point
        raised = f"{type(error).__name__}"
    check("teardown with the applier dead fails loudly", bool(raised), raised or "no error")
    runtime = provider_runtime()
    check(
        "a failed down frees NOTHING: lease, CID lease, and registry all findable",
        len(LeaseStore(state_dir).leases()) == 1
        and runtime.allocator.leased_projects() == [project]
        and project in runtime.registry,
        f"leases={len(LeaseStore(state_dir).leases())} cids={runtime.allocator.leased_projects()}",
    )
    check("the range is still running (nothing was freed under it)", running_project_containers(project) > 0)

    fresh = start_applier(ROOT, state_dir, SPIKE / "tmp" / "logs" / "applier-restarted.txt")
    procs["applier"] = fresh  # immediately: a later failure must terminate THIS one
    # the restarted applier serves a NEW sample cleanly (recorded limitation:
    # the old charge is lost applier-side; disk-driven teardown recovers)
    new_envs = await env_type.sample_init(TASK, str(SPEC), {"__sample_id__": "after-restart"})
    ok = await new_envs["attacker"].exec(["echo", "fresh"])
    check("an applier restart between samples serves the new sample cleanly", ok.success)
    await env_type.sample_cleanup(TASK, str(SPEC), new_envs, False)
    # the OLD sample's teardown now recovers from disk through task_cleanup
    await env_type.task_cleanup(TASK, str(SPEC), True)
    check(
        "the wedged sample's teardown recovered from disk after the restart",
        LeaseStore(state_dir).leases() == []
        and runtime.allocator.leased_projects() == []
        and running_project_containers(project) == 0,
    )


def kill9_and_reaper(state_dir: Path) -> None:
    from inspect_ranges._host import LeaseStore

    proc = subprocess.run(
        ["uv", "run", "python", "design/spikes/range-host-v1/boot_and_die.py"],
        cwd=ROOT,
        env={**os.environ, "INSPECT_RANGES_LEASE_TTL_S": "10"},
        capture_output=True,
        text=True,
        timeout=600,
    )
    check(
        "the driver died by SIGKILL",
        proc.returncode in (-9, 137),  # 137 = 128+9 through the uv wrapper
        f"rc={proc.returncode} err={proc.stderr[-200:]}",
    )
    info = json.loads((SPIKE / "tmp" / "kill9.json").read_text())
    project, lease_id = info["project"], info["lease_id"]
    check("kill -9 left the range running", running_project_containers(project) > 0)
    lease = LeaseStore(state_dir).get(lease_id)
    check("the lease is findable and active, renewal dead with the driver", lease is not None and lease.state == "active")

    # expiry, not liveness: wait out the dead driver's TTL, then a FRESH
    # process reaper reclaims through the live applier
    time.sleep(14)
    started = time.monotonic()
    reap = run_reaper(state_dir)
    evidence["reaper reclaim seconds"] = round(time.monotonic() - started, 1)
    check("the fresh-shell reaper reports the reclaim", f"reaped: {project}" in reap.stdout, reap.stdout + reap.stderr)
    check(
        "the reclaim went THROUGH the applier (no direct-down fallback warning)",
        "falling back to direct down" not in reap.stderr,
        reap.stderr[-300:],
    )
    check("zero residue after the reap", running_project_containers(project) == 0)
    check("lease and CID lease released by the reaper", LeaseStore(state_dir).get(lease_id) is None)


async def forced_expiry_and_race(env_type: object, state_dir: Path) -> None:
    from inspect_ranges._host import LeaseLostError, LeaseStore

    envs = await env_type.sample_init(TASK, str(SPEC), {"__sample_id__": "expire"})
    handle = envs["attacker"]._handle
    host = handle.host
    lease_id = host.lease.lease_id
    try:
        # race, direction one: a renewal landing before the sweep spares the
        # lease (the sweep re-checks expiry under the flock)
        force_expire(state_dir, lease_id)
        await host.renew_now()
        spared = run_reaper(state_dir)
        check("a just-renewed lease is spared by the sweep", f"reaped" not in spared.stdout, spared.stdout)
        alive = await envs["attacker"].exec(["echo", "still-mine"])
        check("the spared sample keeps serving ops", alive.success)

        # direction two: the sweep marks first; the running sample is
        # reclaimed and the driver fails loudly as lease loss. The live
        # renewal (every TTL/3) can legitimately re-extend between the forced
        # expiry and the sweep (that IS direction one), so the sweep gets a
        # bounded number of tries to win the race.
        reap = None
        for _ in range(5):
            force_expire(state_dir, lease_id)
            reap = run_reaper(state_dir)
            if f"reaped: {handle.project}" in reap.stdout:
                break
        assert reap is not None
        check("forced expiry reclaims the RUNNING sample", f"reaped: {handle.project}" in reap.stdout, reap.stdout + reap.stderr)
        check("the reclaim went through the applier", "falling back" not in reap.stderr)
        deadline = time.monotonic() + TTL_S
        loud = ""
        while time.monotonic() < deadline:
            try:
                await envs["attacker"].exec(["echo", "zombie"])
            except LeaseLostError as error:
                loud = f"LeaseLostError: {error}"
                break
            except Exception as error:  # noqa: BLE001 - transport noise before the renewal tick
                await asyncio.sleep(1.0)
                continue
            await asyncio.sleep(1.0)
        check("the driver fails loudly with LeaseLostError (the deliberate policy)", loud.startswith("LeaseLostError"), loud or "never surfaced")
        check("the reclaimed range is gone", running_project_containers(handle.project) == 0)
    finally:
        # the handle is still registered; cleanup must tolerate the already-
        # reclaimed project (down of a gone project is a no-op)
        await env_type.task_cleanup(TASK, str(SPEC), True)
    check("post-reclaim cleanup leaves no leases", LeaseStore(state_dir).leases() == [])


async def main() -> int:
    from inspect_ai._util.entrypoints import ensure_entry_points
    from inspect_ai.util._sandbox.lifecycle import sandbox_lifecycle_scope
    from inspect_ai.util._sandbox.registry import registry_find_sandboxenv
    from inspect_ranges._runtime.ownership import default_state_dir

    ensure_entry_points()
    env_type = registry_find_sandboxenv("range")
    state_dir = default_state_dir()
    (SPIKE / "tmp" / "logs").mkdir(parents=True, exist_ok=True)
    procs: "dict[str, subprocess.Popen[bytes]]" = {
        "applier": start_applier(ROOT, state_dir, SPIKE / "tmp" / "logs" / "applier-matrix.txt")
    }
    try:
        with sandbox_lifecycle_scope():
            await env_type.task_init(TASK, str(SPEC))
            await concurrent_samples(env_type, state_dir)
            await wedged_teardown_and_restart(env_type, state_dir, procs)
        await asyncio.to_thread(kill9_and_reaper, state_dir)
        with sandbox_lifecycle_scope():
            await env_type.task_init(TASK, str(SPEC))
            await forced_expiry_and_race(env_type, state_dir)
    finally:
        procs["applier"].terminate()
        procs["applier"].wait(timeout=10)
    (SPIKE / "tmp" / "matrix.json").write_text(json.dumps(evidence, indent=2))
    if failures:
        print(f"{len(failures)} matrix checks failed: {failures}")
        return 1
    print("all lifecycle matrix checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))

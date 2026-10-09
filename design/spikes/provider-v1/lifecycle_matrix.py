#!/usr/bin/env python3
"""provider-v1 slice-5 lifecycle matrix, scenarios that live in one process.

1. Interrupt deferral: `sample_cleanup(interrupted=True)` leaves the range booted (containment, never a stalled cancellation) and `task_cleanup(cleanup=True)` sweeps it.
2. `cleanup=False`: the range stays up, the logged guidance names the removal commands, and running the printed `inspect sandbox cleanup libvirt_range <project>` from a FRESH process removes it.
3. Concurrency: two same-spec samples boot concurrently with distinct projects and disjoint CID leases, both serve ops mid-overlap, and both tear down; the overlap evidence is persisted to tmp/concurrency.json.

The kill-9 recovery scenario lives in boot_and_die.py + run.sh (it needs a process to die). The provider is reached only through the entry-point registry.
"""

import asyncio
import json
import logging
import subprocess
import sys
import time
from pathlib import Path

from inspect_ai._util.entrypoints import ensure_entry_points
from inspect_ai.util._sandbox.lifecycle import sandbox_lifecycle_scope
from inspect_ai.util._sandbox.registry import registry_find_sandboxenv

SPIKE = Path(__file__).parent
SPEC = SPIKE / "range.yaml"
ROOT = SPIKE.parent.parent.parent

failures: list[str] = []


def check(name: str, good: bool, detail: str = "") -> None:
    print(f"{'PASS ' if good else 'FAIL '} {name}" + (f"  [{detail}]" if detail and not good else ""))
    if not good:
        failures.append(name)


def project_container_up(project: str) -> bool:
    out = subprocess.run(
        ["docker", "ps", "--format", "{{.Names}}"], capture_output=True, text=True
    ).stdout
    return f"{project}-range-1" in out


async def interrupt_defers_then_sweeps(env_type: type) -> None:
    with sandbox_lifecycle_scope():
        await env_type.task_init("matrix-interrupt", str(SPEC))
        envs = await env_type.sample_init(
            "matrix-interrupt", str(SPEC), {"__sample_id__": "int1"}
        )
        project = next(iter(envs.values()))._handle.project
        await env_type.sample_cleanup("matrix-interrupt", str(SPEC), envs, True)
        check(
            "interrupted sample leaves the range booted (deferred containment)",
            project_container_up(project),
        )
        await env_type.task_cleanup("matrix-interrupt", str(SPEC), True)
        check(
            "task_cleanup sweeps the deferred range",
            not project_container_up(project),
        )


async def cleanup_false_prints_the_recovery_command(env_type: type) -> None:
    records: list[logging.LogRecord] = []

    class Capture(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            records.append(record)

    handler = Capture()
    logging.getLogger("inspect_ranges.provider").addHandler(handler)
    try:
        with sandbox_lifecycle_scope():
            await env_type.task_init("matrix-keep", str(SPEC))
            envs = await env_type.sample_init(
                "matrix-keep", str(SPEC), {"__sample_id__": "keep1"}
            )
            project = next(iter(envs.values()))._handle.project
            await env_type.task_cleanup("matrix-keep", str(SPEC), False)
    finally:
        logging.getLogger("inspect_ranges.provider").removeHandler(handler)
    check("cleanup=False leaves the range up", project_container_up(project))
    guidance = [r.getMessage() for r in records if "left up" in r.getMessage()]
    check(
        "the kept range's removal commands are logged",
        bool(guidance) and project in guidance[0] and "inspect sandbox cleanup" in guidance[0],
        guidance[0] if guidance else "no guidance logged",
    )
    # run the printed command from a FRESH process (the operator's path)
    recovered = subprocess.run(
        ["uv", "run", "inspect", "sandbox", "cleanup", "libvirt_range", project],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=600,
    )
    check(
        "the printed command removes the kept range",
        recovered.returncode == 0 and not project_container_up(project),
        recovered.stderr[-200:],
    )


async def concurrent_samples_are_disjoint(env_type: type) -> None:
    async def timed_boot(sample_id: str) -> tuple[float, float, dict]:
        start = time.monotonic()
        envs = await env_type.sample_init(
            "matrix-pair", str(SPEC), {"__sample_id__": sample_id}
        )
        return start, time.monotonic(), envs

    with sandbox_lifecycle_scope():
        await env_type.task_init("matrix-pair", str(SPEC))
        started = time.monotonic()
        (start_a, end_a, envs_a), (start_b, end_b, envs_b) = await asyncio.gather(
            timed_boot("pairA"), timed_boot("pairB")
        )
        pair = [envs_a, envs_b]
        booted = time.monotonic() - started
        check(
            "the two boots overlapped in time (not serialized)",
            start_a < end_b and start_b < end_a,
            f"A [{start_a:.1f},{end_a:.1f}] B [{start_b:.1f},{end_b:.1f}]",
        )
        handles = [next(iter(envs.values()))._handle for envs in pair]
        projects = [h.project for h in handles]
        cids = [set(h.guest_cids.values()) for h in handles]
        check(
            "concurrent same-spec samples get distinct projects",
            len(set(projects)) == 2,
            str(projects),
        )
        check(
            "concurrent samples hold disjoint CID leases",
            not (cids[0] & cids[1]),
            str(cids),
        )
        both_up = all(project_container_up(p) for p in projects)
        check("both ranges are up simultaneously", both_up)
        results = await asyncio.gather(
            pair[0]["attacker"].exec(["sh", "-c", "echo A $(id -un)"]),
            pair[1]["attacker"].exec(["sh", "-c", "echo B $(id -un)"]),
        )
        check(
            "both samples serve ops mid-overlap",
            results[0].stdout == "A agent\n" and results[1].stdout == "B agent\n",
            f"{results[0].stdout!r} {results[1].stdout!r}",
        )
        (SPIKE / "tmp" / "concurrency.json").write_text(
            json.dumps(
                {
                    "projects": projects,
                    "cids": [sorted(c) for c in cids],
                    "boot_s": round(booted, 1),
                    "overlap_proven_at": time.time(),
                    "outputs": [r.stdout for r in results],
                },
                indent=2,
            )
        )
        for envs in pair:
            await env_type.sample_cleanup("matrix-pair", str(SPEC), envs, False)
        await env_type.task_cleanup("matrix-pair", str(SPEC), True)
        check(
            "both concurrent ranges tore down",
            not any(project_container_up(p) for p in projects),
        )


async def _sweep(env_type: type, task_name: str) -> None:
    """Failure containment: whatever a scenario left in the registry goes down."""
    try:
        await env_type.task_cleanup(task_name, str(SPEC), True)
    except Exception as error:  # noqa: BLE001 - best effort, reported
        print(f"       sweep after failure also failed: {error}")


async def main() -> int:
    ensure_entry_points()
    env_type = registry_find_sandboxenv("libvirt_range")
    for scenario, task_name in (
        (interrupt_defers_then_sweeps, "matrix-interrupt"),
        (cleanup_false_prints_the_recovery_command, "matrix-keep"),
        (concurrent_samples_are_disjoint, "matrix-pair"),
    ):
        try:
            await scenario(env_type)
        except Exception as error:  # noqa: BLE001 - fail the run, never leak
            failures.append(f"{task_name}: {type(error).__name__}")
            print(f"FAIL  {task_name} raised {type(error).__name__}: {error}")
            with sandbox_lifecycle_scope():
                await _sweep(env_type, task_name)
    if failures:
        print(f"{len(failures)} matrix checks failed: {failures}")
        return 1
    print("all matrix checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))

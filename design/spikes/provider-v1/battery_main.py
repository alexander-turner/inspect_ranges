#!/usr/bin/env python3
"""provider-v1 slice-5 battery: the provider-driven lifecycle on a realizer-booted multi-guest range.

Deliberately NEVER imports the provider: the sandboxenv is resolved through inspect-ai's entry-point registry by name, so registration itself is under test. Everything else (handle internals for diagnostics) is reached through the resolved objects.

Stages, in order against ONE booted range: basic cross-guest ops; Inspect's full `self_check` (44 checks, EMPTY pin, two-sided); the portable conformance suite over the provider-booted attacker guest (subprocess pytest, real vsock); the third-user wrapper battery (in-guest useradd, env exec, self-deletion, write-mode ownership); the agent-identity pins (default user, HOME/PATH wrapper routing, no root-fallback diag); retry fault (b): virsh suspend/resume with transient recovery and moving counters; retry fault (a) LAST because it is destructive to the session pin: vsockd restarted mid-exec surfaces `SessionChangedError`, the follow-up op succeeds on the re-pin, and teardown still runs clean.

Run from the repo root via run.sh (image cache and state dir ride INSPECT_RANGES_IMAGE_CACHE / XDG_STATE_HOME).
"""

import asyncio
import json
import os
import subprocess
import sys
import time
from pathlib import Path

import inspect_ai.util._sandbox.self_check as self_check_module
from inspect_ai._util.entrypoints import ensure_entry_points
from inspect_ai.util._sandbox.lifecycle import sandbox_lifecycle_scope
from inspect_ai.util._sandbox.registry import registry_find_sandboxenv

SPIKE = Path(__file__).parent
SPEC = SPIKE / "range.yaml"
ROOT = SPIKE.parent.parent.parent
TASK = "provider-battery"

failures: list[str] = []


def check(name: str, good: bool, detail: str = "") -> None:
    print(f"{'PASS ' if good else 'FAIL '} {name}" + (f"  [{detail}]" if detail and not good else ""))
    if not good:
        failures.append(name)


def run_in_range_container(project: str, command: str) -> "subprocess.CompletedProcess[str]":
    return subprocess.run(
        ["docker", "exec", f"{project}-range-1", "sh", "-c", command],
        capture_output=True,
        text=True,
    )


async def basic_ops(attacker: object, web: object) -> None:
    result = await attacker.exec(["id", "-un"])  # type: ignore[attr-defined]
    check(
        "default exec on the attacker runs as agent",
        result.success and result.stdout.strip() == "agent",
        f"rc={result.returncode} out={result.stdout!r} err={result.stderr!r}",
    )
    result = await web.exec(["id", "-un"])  # type: ignore[attr-defined]
    check("named guest exec works", result.success and result.stdout.strip() == "agent")
    await web.write_file("probe.txt", "cross-guest")  # type: ignore[attr-defined]
    body = await web.read_file("probe.txt")  # type: ignore[attr-defined]
    check("file round trip on the named guest", body == "cross-guest")
    ping = await attacker.exec(["ping", "-c", "1", "-W", "2", "10.91.10.10"])  # type: ignore[attr-defined]
    check("attacker reaches web over the compiled segment", ping.success, ping.stderr)


async def self_check_44(attacker: object) -> None:
    checks = [
        (name, getattr(self_check_module, name)) for name in self_check_module.__all__
    ]
    check("self_check exports 44 checks", len(checks) == 44, str(len(checks)))
    passed: list[str] = []
    failed: list[tuple[str, str]] = []
    for name, fn in sorted(checks):
        try:
            await fn(attacker)
            passed.append(name)
        except Exception as error:  # noqa: BLE001 - tally and report
            failed.append((name, f"{type(error).__name__}: {error}"))
    for name, reason in failed:
        print(f"       self_check FAIL {name}: {reason[:140]}")
    # the pin is EMPTY and two-sided by construction: any failure fails
    check("self_check 44/44 over the provider (empty pin)", not failed, f"{len(passed)} passed")


def portable_conformance(cid: int) -> None:
    env = {**os.environ, "IR_VSOCK_BATTERY_CID": str(cid)}
    proc = subprocess.run(
        [sys.executable, "-m", "pytest", "tests/test_channel_vsock.py", "-q", "-n", "0"],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=1200,
    )
    tail = "\n".join(proc.stdout.splitlines()[-3:])
    print(f"       conformance tail: {tail.strip()[:200]}")
    check("portable conformance over the provider-booted guest", proc.returncode == 0, tail)


async def third_user_battery(attacker: object) -> None:
    useradd = await attacker.exec(  # type: ignore[attr-defined]
        ["useradd", "--create-home", "--shell", "/bin/sh", "scratchuser"], user="root"
    )
    check("in-guest useradd for the third-user path", useradd.success, useradd.stderr)
    # oversized env forces the wrapper; the explicit third user can only read
    # the 0600 script if the root chown ran (agent-owned would be EACCES)
    big_env = {"HOME": "/home/scratchuser", "IR_PAD": "x" * 40_000}
    result = await attacker.exec(  # type: ignore[attr-defined]
        ["sh", "-c", "printf '%s %s' \"$(id -un)\" \"$HOME\""],
        env=big_env,
        user="scratchuser",
    )
    check(
        "third-user wrapper exec runs as that user with the caller's env",
        result.success and result.stdout == "scratchuser /home/scratchuser",
        f"rc={result.returncode} out={result.stdout!r} err={result.stderr!r}",
    )
    leftovers = await attacker.exec(["sh", "-c", "ls /tmp/.ir-exec-* 2>/dev/null | wc -l"])  # type: ignore[attr-defined]
    check(
        "wrapper scripts self-deleted (owner rm under sticky /tmp)",
        leftovers.success and leftovers.stdout.strip() == "0",
        leftovers.stdout,
    )
    # the write-mode + ownership ground truth on a real guest: a channel-level
    # 0600 write lands agent-owned with exactly those bits
    handle = attacker._handle  # type: ignore[attr-defined]
    await handle.channel.write_file("attacker", "/tmp/mode-probe", b"secret", mode=0o600)
    stat = await attacker.exec(["stat", "-c", "%a %U", "/tmp/mode-probe"])  # type: ignore[attr-defined]
    check(
        "mode-carrying write lands 0600 agent-owned on the real guest",
        stat.success and stat.stdout.strip() == "600 agent",
        stat.stdout + stat.stderr,
    )


async def agent_identity_pins(attacker: object) -> None:
    result = await attacker.exec(["sh", "-c", "echo $HOME"], env={"HOME": "/custom-home"})  # type: ignore[attr-defined]
    check(
        "caller HOME survives the runuser reset",
        result.success and result.stdout.strip() == "/custom-home",
        result.stdout,
    )
    handle = attacker._handle  # type: ignore[attr-defined]
    diag = await handle.channel.diag("attacker", max_entries=256)
    fallback = [e for e in diag.entries if e.event == "agent-user-unavailable"]
    check("no agent-user-unavailable diag on the booted golden", not fallback)


async def retry_suspend_recovers(attacker: object, project: str) -> None:
    # measured on this stack: a suspended domain PARKS vsock connects in the
    # vhost queue rather than refusing them, so the op simply completes after
    # resume with no retry at any layer; the counters evidence therefore rides
    # the restart fault below, where real transients occur
    async def resume_later() -> None:
        await asyncio.sleep(5.0)
        await asyncio.to_thread(
            run_in_range_container, project, "virsh -c qemu:///system resume attacker"
        )

    suspended = await asyncio.to_thread(
        run_in_range_container, project, "virsh -c qemu:///system suspend attacker"
    )
    check("domain suspended for the fault window", suspended.returncode == 0, suspended.stderr)
    resumer = asyncio.ensure_future(resume_later())
    started = time.monotonic()
    result = await attacker.exec(["echo", "alive"])  # type: ignore[attr-defined]
    await resumer
    elapsed = time.monotonic() - started
    check(
        "exec recovers across suspend/resume within deadline",
        result.success and result.stdout == "alive\n" and elapsed < 60,
        f"rc={result.returncode} elapsed={elapsed:.1f}s",
    )


async def retry_restart_surfaces_session_change(web: object) -> None:
    from inspect_ranges._provider.errors import SessionChangedError  # the typed verdict under test

    handle = web._handle  # type: ignore[attr-defined]
    retries_before = handle.stats.counters("exec").retries

    # the restart trigger must be DETACHED from its own delivery: a plain
    # `systemctl restart` through the channel is self-amplifying (the reply
    # dies with the daemon, the resend re-runs the restart on the fresh
    # daemon's empty dedupe store, repeatedly), the exact non-idempotent
    # double-run hazard layer 2b exists to surface. systemd-run hands pid1 a
    # transient timer OUTSIDE the unit's cgroup, so the trigger fires once.
    # AccuracySec pinned: systemd timers default to 1 MINUTE of coalescing
    # slack, which would fire the restart anywhere in the next minute
    # (measured), not inside the in-flight exec below
    armed = await web.exec(  # type: ignore[attr-defined]
        [
            "systemd-run",
            "--on-active=1",
            "--timer-property=AccuracySec=100ms",
            "systemctl",
            "restart",
            "vsockd",
        ],
        user="root",
        timeout=20,
    )
    check("restart timer armed (detached from its own delivery)", armed.success, armed.stderr)
    verdict = "no error"
    try:
        # in flight across the restart; the re-run (wire resend or fresh-id
        # retry) completes after the daemon is back, so the confirm ping
        # lands on the NEW session
        await web.exec(["sh", "-c", "echo started; sleep 6; echo done"])  # type: ignore[attr-defined]
    except SessionChangedError as error:
        verdict = f"SessionChangedError ({error.pinned[:8]}.. -> {error.observed[:8]}..)"
    except Exception as error:  # noqa: BLE001 - tally the honest shape
        verdict = f"{type(error).__name__}: {error}"
    check(
        "vsockd restart mid-exec surfaces SessionChangedError",
        verdict.startswith("SessionChangedError"),
        verdict,
    )
    retries_after = handle.stats.counters("exec").retries
    print(f"       retry counters across the fault: {retries_before} -> {retries_after}")
    check(
        "the fault's re-delivery is accounted for (retry counter moved, or the wire resend carried it as the SessionChangedError proves)",
        retries_after > retries_before or verdict.startswith("SessionChangedError"),
        f"retries {retries_before} -> {retries_after}; verdict {verdict}",
    )
    # the re-pin lets the sample continue (and teardown proceed) honestly
    fresh = await web.exec(["echo", "post-restart"])  # type: ignore[attr-defined]
    check("fresh op after the re-pin succeeds", fresh.success and fresh.stdout == "post-restart\n")


async def main() -> int:
    ensure_entry_points()
    env_type = registry_find_sandboxenv("libvirt_range")
    check(
        "entry point resolves libvirt_range",
        env_type.__name__ == "LibvirtRangeSandboxEnvironment",
        env_type.__name__,
    )
    with sandbox_lifecycle_scope():
        await env_type.task_init(TASK, str(SPEC))
        boot_started = time.monotonic()
        envs = await env_type.sample_init(TASK, str(SPEC), {"__sample_id__": "battery"})
        print(f"       booted in {time.monotonic() - boot_started:.1f}s")
        check(
            "sample_init returns the attacker first plus the named guest",
            list(envs) == ["attacker", "web"],
            str(list(envs)),
        )
        attacker, web = envs["attacker"], envs["web"]
        handle = attacker._handle  # type: ignore[attr-defined]
        project: str = handle.project
        cids: dict[str, int] = dict(handle.guest_cids)
        check(
            "provider CID band (10000+) and disjoint guest CIDs",
            all(cid >= 10_000 for cid in cids.values()) and len(set(cids.values())) == 2,
            str(cids),
        )
        (SPIKE / "tmp" / "range.json").write_text(json.dumps({"project": project, "cids": cids}))

        try:
            await basic_ops(attacker, web)
            await self_check_44(attacker)
            await asyncio.to_thread(portable_conformance, cids["attacker"])
            await third_user_battery(attacker)
            await agent_identity_pins(attacker)
            await retry_suspend_recovers(attacker, project)
            await retry_restart_surfaces_session_change(web)
        finally:
            await env_type.sample_cleanup(TASK, str(SPEC), envs, False)
            await env_type.task_cleanup(TASK, str(SPEC), True)
        gone = subprocess.run(
            ["docker", "ps", "-a", "--format", "{{.Names}}"], capture_output=True, text=True
        )
        check(
            "teardown leaves no project containers",
            project not in gone.stdout,
            gone.stdout,
        )

    if failures:
        print(f"{len(failures)} battery checks failed: {failures}")
        return 1
    print("all battery checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))

#!/usr/bin/env python3
"""Slice-4 derive-battery checks: the recipe-v4 golden's agent user, driven through the provider's op surface over real vsock.

Pins, per provider-v1 slice 4: the default exec identity is the unprivileged `agent` user; an explicit user still works through the absolute-path runuser; an unknown user stays a failed result naming the user (never an exception); the daemon binary carries the absolute runuser path (the PATH-resolution escalation stays closed); and a root-owned write/read surfaces as `PermissionError` through the provider mapping.

Run from the repo root with `IR_VSOCK_BATTERY_CID` pointing at a booted recipe-v4 golden (images-derive/run.sh drives this).
"""

import asyncio
import os
import sys
from pathlib import Path

from inspect_ranges._channel.channel import MessageChannel
from inspect_ranges._channel.vsock import VsockTransport
from inspect_ranges._compiler.plan import Totals
from inspect_ranges._provider.ops import (
    provider_exec,
    provider_read_file,
    provider_write_file,
)
from inspect_ranges._provider.state import SampleHandle

CID = int(os.environ["IR_VSOCK_BATTERY_CID"])
GUEST = "guest"

failures: list[str] = []


def check(name: str, good: bool, detail: str = "") -> None:
    print(f"{'PASS ' if good else 'FAIL '} {name}" + (f"  [{detail}]" if detail and not good else ""))
    if not good:
        failures.append(name)


async def main() -> int:
    channel = MessageChannel(VsockTransport({GUEST: CID}), label="derive-battery")
    handle = SampleHandle(
        project="ir-derive-battery",
        task_name="derive",
        staging=Path("/tmp"),
        totals=Totals(guests=1, cpus=1, memory_mb=1024),
        cid_base=CID,
        guest_cids={GUEST: CID},
        channel=channel,
    )

    result = await provider_exec(
        handle, GUEST, ["id", "-un"], None, None, None, None, 30
    )
    check(
        "default exec runs as the agent user",
        result.success and result.stdout.strip() == "agent",
        f"rc={result.returncode} out={result.stdout!r} err={result.stderr!r}",
    )

    result = await provider_exec(
        handle, GUEST, ["id", "-un"], None, None, None, "root", 30
    )
    check(
        "explicit user=root still honored (runuser)",
        result.success and result.stdout.strip() == "root",
        f"rc={result.returncode} out={result.stdout!r} err={result.stderr!r}",
    )

    result = await provider_exec(
        handle, GUEST, ["id", "-un"], None, None, None, "nosuchuser", 30
    )
    check(
        "unknown user is a failed result naming the user",
        (not result.success) and "nosuchuser" in (result.stderr + result.stdout),
        f"rc={result.returncode} out={result.stdout!r} err={result.stderr!r}",
    )

    result = await provider_exec(
        handle, GUEST, ["getent", "passwd", "agent"], None, None, None, None, 30
    )
    check(
        "agent user shaped: home /home/agent, shell /bin/sh",
        result.success
        and ":/home/agent:" in result.stdout
        and result.stdout.rstrip().endswith("/bin/sh"),
        f"rc={result.returncode} out={result.stdout!r}",
    )

    result = await provider_exec(
        handle,
        GUEST,
        ["grep", "-ac", "/usr/sbin/runuser", "/opt/inspect-ranges/vsockd"],
        None,
        None,
        None,
        None,
        30,
    )
    check(
        "daemon pins the absolute runuser path",
        result.success and int(result.stdout.strip() or "0") >= 1,
        f"rc={result.returncode} out={result.stdout!r} err={result.stderr!r}",
    )

    result = await provider_exec(
        handle, GUEST, ["sh", "-c", "echo $HOME"], None, None, None, None, 30
    )
    check(
        "default HOME is the agent home",
        result.success and result.stdout.strip() == "/home/agent",
        f"rc={result.returncode} out={result.stdout!r}",
    )

    result = await provider_exec(
        handle,
        GUEST,
        ["sh", "-c", "echo $HOME"],
        None,
        None,
        {"HOME": "/custom-home"},
        None,
        30,
    )
    check(
        "caller HOME survives the runuser reset (wrapper routing)",
        result.success and result.stdout.strip() == "/custom-home",
        f"rc={result.returncode} out={result.stdout!r} err={result.stderr!r}",
    )

    result = await provider_exec(
        handle,
        GUEST,
        ["sh", "-c", "echo $PATH"],
        None,
        None,
        {"PATH": "/custom-bin:/usr/bin:/bin"},
        None,
        30,
    )
    check(
        "caller PATH survives the runuser reset (wrapper routing)",
        result.success and result.stdout.strip() == "/custom-bin:/usr/bin:/bin",
        f"rc={result.returncode} out={result.stdout!r} err={result.stderr!r}",
    )

    diag = await channel.diag(GUEST, max_entries=256)
    fallback = [entry for entry in diag.entries if entry.event == "agent-user-unavailable"]
    check(
        "recipe-v4 golden never falls back to root (no agent-user-unavailable diag)",
        not fallback,
        "; ".join(entry.detail for entry in fallback),
    )

    try:
        await provider_write_file(handle, GUEST, "/etc/ir-denied-probe", "nope")
        check(
            "root-owned write maps to PermissionError", False, "write succeeded as agent"
        )
    except PermissionError as denied:
        check(
            "root-owned write maps to PermissionError",
            "/etc/ir-denied-probe" in str(denied),
            str(denied),
        )

    try:
        await provider_read_file(handle, GUEST, "/etc/shadow")
        check("protected read maps to PermissionError", False, "read succeeded as agent")
    except PermissionError as denied:
        check("protected read maps to PermissionError", True, str(denied))

    if failures:
        print(f"{len(failures)} agent-user checks failed: {failures}")
        return 1
    print("all agent-user checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))

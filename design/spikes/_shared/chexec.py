#!/usr/bin/env python3
"""Battery guest-exec over the v3 channel client (replaces the spike-era v2 clients).

Usage, run from the repo root with the project venv:
  chexec.py --cid 3000 wait [timeout]
  chexec.py --cid 3000 exec 'shell command'
  chexec.py --boot path/to/bundle/boot.json --guest web exec 'shell command'
"""

import argparse
import asyncio
import json
import sys
import time
from pathlib import Path

from inspect_ranges._channel.channel import MessageChannel, request_id
from inspect_ranges._channel.protocol import Budget, ExecRequest
from inspect_ranges._channel.vsock import VsockTransport

GUEST = "guest"


def cid_map(args: argparse.Namespace) -> tuple[dict[str, int], str]:
    if args.cid is not None:
        return {GUEST: args.cid}, GUEST
    boot = json.loads(Path(args.boot).read_text())
    cids = {g["name"]: g["cid"] for g in boot["guests"]}
    return cids, args.guest


async def wait(channel: MessageChannel, guest: str, timeout: float) -> int:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            await channel.ping(guest)
            return 0
        except Exception:
            await asyncio.sleep(1.0)
    print(f"{guest}: daemon did not answer", file=sys.stderr)
    return 1


async def run_exec(
    channel: MessageChannel, guest: str, command: str, user: str | None = None
) -> int:
    outcome = await channel.exec(
        guest,
        ExecRequest(
            id=request_id(),
            cmd=["sh", "-c", command],
            user=user,
            budget=Budget(command_ms=120_000),
        ),
    )
    sys.stdout.write(outcome.stdout.decode(errors="replace"))
    sys.stderr.write(outcome.stderr.decode(errors="replace"))
    return outcome.rc


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--cid", type=int, default=None)
    parser.add_argument("--boot", default=None)
    parser.add_argument("--guest", default=GUEST)
    parser.add_argument("--user", default=None)
    parser.add_argument("op", choices=["wait", "exec", "diag"])
    parser.add_argument("arg", nargs="?")
    args = parser.parse_args()
    cids, guest = cid_map(args)
    channel = MessageChannel(VsockTransport(cids), label="battery")

    async def diag() -> int:
        reply = await channel.diag(guest, max_entries=1000)
        print(
            f"listener_restarts={reply.listener_restarts} entries={len(reply.entries)}"
        )
        return 0

    async def dispatch() -> int:
        if args.op == "wait":
            return await wait(channel, guest, float(args.arg or 180))
        if args.op == "diag":
            return await diag()
        assert args.arg is not None, "exec needs a command"
        return await run_exec(channel, guest, args.arg, args.user)

    return asyncio.run(dispatch())


if __name__ == "__main__":
    sys.exit(main())

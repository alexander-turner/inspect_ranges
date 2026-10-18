"""Guest connection helper handed to recipe entrypoints (`IR_EXEC` / `IR_PUSH`).

Online recipes run on the host; this tool is their connection to the target guest, invoked through the generated wrappers the executor exports. The executor sets `IR_GUEST` (target name), `IR_GUEST_CIDS` (JSON name-to-CID map), and `IR_EXEC_BUDGET_MS` (default per-exec budget); `exec` runs an argv or an uploaded script in the guest as root by default with an explicit `command_ms` budget, and `push` installs a local file into the guest, root-owned at the given mode (staged through `/tmp` because the daemon file plane acts as the agent user; recipes needing other ownership chown via `exec`). Every exec carries a budget because an unbudgeted exec that leaves live background children holds the exec plane (the challenges-v1 lesson); recipes that launch services should still redirect fds and use short budgets.

Exit status: the in-guest rc passes through (signal deaths map to 128+signal); a budget expiry exits 124; any other channel failure exits 125 with the error on stderr.
"""

import argparse
import asyncio
import json
import os
import shlex
import sys
from pathlib import Path
from typing import cast

from .._channel.channel import (
    ChannelBudgetError,
    ChannelError,
    MessageChannel,
    request_id,
)
from .._channel.protocol import Budget, ExecRequest
from .._channel.vsock import VsockTransport

EXIT_BUDGET = 124
EXIT_CHANNEL = 125
EXIT_USAGE = 2


def cids_from_env(environ: dict[str, str]) -> tuple[str, dict[str, int]]:
    """The target guest and CID map from the `IR_*` contract environment.

    Raises:
        ValueError: when the contract variables are absent or malformed (the tool was run outside a recipe).
    """
    guest = environ.get("IR_GUEST", "")
    raw = environ.get("IR_GUEST_CIDS", "")
    if not guest or not raw:
        raise ValueError(
            "IR_GUEST / IR_GUEST_CIDS are not set; this tool runs inside a recipe entrypoint"
        )
    try:
        parsed: object = json.loads(raw)
    except ValueError as error:
        raise ValueError(f"IR_GUEST_CIDS is not valid JSON: {error}") from error
    if not isinstance(parsed, dict):
        raise ValueError("IR_GUEST_CIDS must map guest names to integer CIDs")
    cids: dict[str, int] = {}
    for name, cid in cast(dict[object, object], parsed).items():
        if (
            not isinstance(name, str)
            or isinstance(cid, bool)
            or not isinstance(cid, int)
        ):
            raise ValueError("IR_GUEST_CIDS must map guest names to integer CIDs")
        cids[name] = cid
    if guest not in cids:
        raise ValueError(f"IR_GUEST {guest!r} is not in IR_GUEST_CIDS")
    return guest, cids


def exit_code(rc: int) -> int:
    """Map a signed in-guest rc to a shell exit status (killed-by-signal becomes 128+signal)."""
    return 128 - rc if rc < 0 else rc


async def _run_exec(args: argparse.Namespace) -> int:
    guest, cids = cids_from_env(dict(os.environ))
    channel = MessageChannel(VsockTransport(cids), label="recipe")
    budget = Budget(command_ms=int(args.budget_ms))
    script: str | None = args.script
    if script is not None:
        remote = f"/tmp/.ir-recipe-{request_id()}.sh"
        body = b'rm -f -- "$0"\n' + Path(script).read_bytes()
        await channel.write_file(guest, remote, body, mode=0o700)
        cmd = ["sh", remote]
    else:
        cmd = [str(part) for part in args.argv]
        if not cmd:
            print("ir-exec: no command given (argv or --script)", file=sys.stderr)
            return EXIT_USAGE
    outcome = await channel.exec(
        guest,
        ExecRequest(
            id=request_id(),
            cmd=cmd,
            cwd=args.cwd,
            user=str(args.user),
            budget=budget,
        ),
    )
    sys.stdout.buffer.write(outcome.stdout)
    sys.stderr.buffer.write(outcome.stderr)
    return exit_code(outcome.rc)


async def _run_push(args: argparse.Namespace) -> int:
    # The daemon file plane acts as the agent user, so privileged destinations
    # stage through /tmp and promote via a root exec (install creates parents
    # and applies the mode atomically with the copy).
    guest, cids = cids_from_env(dict(os.environ))
    channel = MessageChannel(VsockTransport(cids), label="recipe")
    data = Path(str(args.local)).read_bytes()
    mode = int(str(args.mode), 8)
    staging = f"/tmp/.ir-push-{request_id()}"
    await channel.write_file(guest, staging, data, mode=0o600)
    promote = (
        f"rc=0; install -D -m {mode:o} -- {shlex.quote(staging)} {shlex.quote(str(args.remote))}"
        f" || rc=$?; rm -f -- {shlex.quote(staging)}; exit $rc"
    )
    outcome = await channel.exec(
        guest,
        ExecRequest(
            id=request_id(),
            cmd=["sh", "-c", promote],
            user="root",
            budget=Budget(command_ms=60_000),
        ),
    )
    if outcome.rc != 0:
        sys.stderr.buffer.write(outcome.stderr)
        print(
            f"ir-push: install to {args.remote!r} exited {outcome.rc}", file=sys.stderr
        )
    return exit_code(outcome.rc)


def main(argv: list[str] | None = None) -> int:
    """CLI entry: `exec [--user U] [--budget-ms N] [--cwd DIR] (--script FILE | -- ARGV...)` or `push LOCAL REMOTE [--mode 644]`."""
    parser = argparse.ArgumentParser(prog="ir-guesttool", add_help=True)
    commands = parser.add_subparsers(dest="verb", required=True)
    default_budget = int(os.environ.get("IR_EXEC_BUDGET_MS", "600000"))
    run = commands.add_parser("exec", help="run a command in the target guest")
    run.add_argument("--user", default="root")
    run.add_argument("--budget-ms", dest="budget_ms", type=int, default=default_budget)
    run.add_argument("--cwd", default=None)
    run.add_argument(
        "--script", default=None, help="upload and run a local script file"
    )
    run.add_argument("argv", nargs="*", help="command argv (after --)")
    push = commands.add_parser("push", help="write a local file into the target guest")
    push.add_argument("local")
    push.add_argument("remote")
    push.add_argument("--mode", default="644", help="octal file mode, default 644")
    args = parser.parse_args(argv)
    try:
        if args.verb == "exec":
            return asyncio.run(_run_exec(args))
        return asyncio.run(_run_push(args))
    except ChannelBudgetError as error:
        print(f"ir-guesttool: exec budget expired: {error}", file=sys.stderr)
        return EXIT_BUDGET
    except ChannelError as error:
        print(f"ir-guesttool: channel failure: {error}", file=sys.stderr)
        return EXIT_CHANNEL
    except ValueError as error:
        print(f"ir-guesttool: {error}", file=sys.stderr)
        return EXIT_USAGE


if __name__ == "__main__":  # pragma: no cover - exercised by the battery
    sys.exit(main())

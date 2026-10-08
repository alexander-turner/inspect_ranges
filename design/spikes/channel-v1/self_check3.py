"""Run Inspect's sandbox self_check against the booted battery guest over protocol v3.

A minimal SandboxEnvironment adapter over MessageChannel + VsockTransport (no lifecycle; the harness boots the guest). Usage: `IR_VSOCK_BATTERY_CID=<cid> uv run python design/spikes/channel-v1/self_check3.py`.
"""

import asyncio
import inspect as pyinspect
import os
import sys
import traceback
from typing import Union

import inspect_ai.util._sandbox.self_check as self_check_module
from inspect_ai.util import ExecResult, OutputLimitExceededError, SandboxEnvironment
from inspect_ai.util._sandbox.limits import SandboxEnvironmentLimits

from inspect_ranges._channel.channel import (
    ChannelBudgetError,
    FileLimitExceeded,
    GuestError,
    MessageChannel,
)
from inspect_ranges._channel.protocol import Budget, ExecRequest
from inspect_ranges._channel.vsock import VsockTransport
from inspect_ranges._channel.channel import request_id

CID = int(os.environ["IR_VSOCK_BATTERY_CID"])
PORT = int(os.environ.get("IR_VSOCK_BATTERY_PORT", "5000"))

DOCUMENTED_XFAILS = frozenset(
    {
        # the daemon runs as root (default unprivileged exec user is
        # build-phase image work); root reads/writes chmod-000 files happily
        "test_read_file_not_allowed",
        "test_write_binary_file_without_permissions",
        "test_write_text_file_without_permissions",
    }
)

_ERRNO_EXC: dict[str, type[Exception]] = {
    "ENOENT": FileNotFoundError,
    "EISDIR": IsADirectoryError,
    "ENOTDIR": NotADirectoryError,
    "EACCES": PermissionError,
    "EPERM": PermissionError,
}


def _map_guest_error(error: GuestError, path: str = "") -> Exception:
    exc = _ERRNO_EXC.get(error.errno)
    if exc is not None:
        return exc(f"{error} {path}".strip())
    return RuntimeError(str(error))


class V3Sandbox(SandboxEnvironment):
    """exec/read/write over the v3 channel against one booted guest (no lifecycle: the harness boots it)."""

    @classmethod
    async def sample_init(cls, task_name, config, metadata):  # pragma: no cover - unused
        raise NotImplementedError("the battery harness boots the guest")

    @classmethod
    async def sample_cleanup(cls, task_name, config, environments, interrupted):
        return None

    def __init__(self) -> None:
        self.channel = MessageChannel(
            VsockTransport({"guest": CID}, port=PORT), label="self-check"
        )

    async def exec(
        self,
        cmd: list[str],
        input: str | bytes | None = None,
        cwd: str | None = None,
        env: dict[str, str] | None = None,
        user: str | None = None,
        timeout: int | None = None,
        timeout_retry: bool = True,
        concurrency: bool = True,
    ) -> ExecResult[str]:
        stdin = input.encode() if isinstance(input, str) else input
        # the control frame caps at 32 KiB: huge argv rides an uploaded script
        # (the guest-exec-lessons wrapper pattern), never the control payload
        if sum(len(part) for part in cmd) > 24_000:
            import shlex

            script = "/tmp/.ir-exec-" + request_id() + ".sh"
            await self.write_file(
                script, "#!/bin/sh\nexec " + " ".join(shlex.quote(p) for p in cmd)
            )
            cmd = ["sh", script]
        budget = Budget(command_ms=timeout * 1000 if timeout else None)
        request = ExecRequest(
            id=request_id(),
            cmd=cmd,
            cwd=cwd,
            env=env or {},
            user=user,
            budget=budget,
            data_size=len(stdin) if stdin is not None else None,
        )
        try:
            outcome = await self.channel.exec("guest", request, stdin=stdin)
        except ChannelBudgetError as error:
            if error.layer == "command":
                raise TimeoutError("Command timed out") from error
            raise
        except GuestError as error:
            raise _map_guest_error(error) from error
        stdout = outcome.stdout.decode("utf-8", errors="replace")
        stderr = outcome.stderr.decode("utf-8", errors="replace")
        if outcome.stdout_truncated or outcome.stderr_truncated:
            raise OutputLimitExceededError("16 MiB", stdout)
        rc = outcome.rc
        if rc < 0:  # signal death: shell convention is 128+N
            rc = 128 - rc
        if rc == 126 and "permission denied" in stderr.lower():
            raise PermissionError(stderr.strip())
        return ExecResult(success=rc == 0, returncode=rc, stdout=stdout, stderr=stderr)

    async def write_file(self, file: str, contents: str | bytes) -> None:
        data = contents.encode() if isinstance(contents, str) else contents
        try:
            await self.channel.write_file("guest", file, data)
        except GuestError as error:
            raise _map_guest_error(error, file) from error

    async def read_file(self, file: str, text: bool = True) -> Union[str, bytes]:  # type: ignore[override]
        limit = SandboxEnvironmentLimits.MAX_READ_FILE_SIZE
        try:
            body = await self.channel.read_file("guest", file, cap=limit)
        except FileLimitExceeded as error:
            raise OutputLimitExceededError(
                SandboxEnvironmentLimits.MAX_READ_FILE_SIZE_STR, None
            ) from error
        except GuestError as error:
            raise _map_guest_error(error, file) from error
        return body.decode("utf-8") if text else body


async def main() -> int:
    env = V3Sandbox()
    passed: list[str] = []
    failed: list[tuple[str, str]] = []
    tests = [
        (name, fn)
        for name, fn in pyinspect.getmembers(
            self_check_module, pyinspect.iscoroutinefunction
        )
        if name.startswith("test_")
    ]
    for name, fn in sorted(tests):
        try:
            await fn(env)
            passed.append(name)
            print(f"  PASS {name}")
        except Exception as error:  # noqa: BLE001 - tally and report
            reason = "".join(traceback.format_exception_only(error)).strip()
            failed.append((name, reason[:160]))
            print(f"  FAIL {name}: {reason[:160]}")
    print(
        f"\nself_check: {len(passed)} passed, {len(failed)} failed of {len(passed) + len(failed)}"
    )
    for name, reason in failed:
        print(f"  - {name}: {reason}")
    # the gate pins the xfail NAMES: a traded regression (a documented xfail
    # starts passing while something else breaks) fails even at equal counts
    unexpected = {name for name, _ in failed} - DOCUMENTED_XFAILS
    if unexpected:
        print(f"UNEXPECTED failures: {sorted(unexpected)}")
    return len(unexpected)


if __name__ == "__main__":
    sys.exit(0 if asyncio.run(main()) == 0 else 1)

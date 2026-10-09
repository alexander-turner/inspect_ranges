"""`LocalEndpoint`: a `FakeGuest` whose exec runs REAL argv on this host under a temp root.

Test infrastructure (deliberately not shipped in the package: it executes arbitrary host commands), existing so inspect-ai's full `self_check` suite can run against the provider on CI with zero VMs. It emulates the Go daemon's observable contract: real subprocesses in their own process group with the in-guest command budget enforced by a group TERM-then-KILL (so the timeout-kills-children checks are genuine), per-stream output caps with truncation flags, rc 127/126 for missing/unexecutable commands, the daemon's unknown-user error shape, and errno-tagged file replies. Path translation maps the agent home (`/home/agent`) onto the temp root; other absolute paths touch the host (the suite uses `/tmp/...` and reads `/etc`).
"""

import asyncio
import os
import signal
from pathlib import Path

from inspect_ranges._channel.channel import (  # pyright: ignore[reportPrivateUsage]
    FakeGuest,
    _StoredReply,
)
from inspect_ranges._channel.protocol import (
    DEFAULT_BULK_CAP,
    ErrorReply,
    ExecRequest,
    ExecResult,
    FileData,
    Message,
    OkReply,
    ReadFileRequest,
    WriteFileRequest,
)
from inspect_ranges._provider.ops import AGENT_HOME

STREAM_CAP = DEFAULT_BULK_CAP
"""Per-stream output cap, mirroring the daemon's 16 MiB `OutputCap`."""


class LocalEndpoint(FakeGuest):
    """A guest endpoint backed by the local host (see module docstring)."""

    def __init__(self, name: str, root: Path) -> None:
        super().__init__(name)
        self.root = root
        root.mkdir(parents=True, exist_ok=True)

    # -- path translation -----------------------------------------------------

    def translate(self, path: str) -> Path:
        """The in-guest path as a host path: the agent home maps onto the temp root."""
        if path == AGENT_HOME:
            return self.root
        prefix = AGENT_HOME + "/"
        if path.startswith(prefix):
            return self.root / path[len(prefix) :]
        if path.startswith("/"):
            return Path(path)
        return self.root / path

    # -- file ops over the real filesystem -------------------------------------

    def _read(self, request: ReadFileRequest) -> _StoredReply:
        try:
            with open(self.translate(request.path), "rb") as handle:
                limit = request.max_bytes
                data = handle.read(limit + 1) if limit is not None else handle.read()
        except OSError as error:
            return _StoredReply(self._errno_reply(request.id, error), None)
        truncated = request.max_bytes is not None and len(data) > request.max_bytes
        if truncated:
            assert request.max_bytes is not None
            data = data[: request.max_bytes]
        return _StoredReply(
            FileData(
                id=request.id,
                size=len(data),
                data_size=len(data) or None,
                truncated=truncated,
            ),
            data if data else None,
        )

    def _write(self, request: WriteFileRequest, data: bytes) -> _StoredReply:
        self.write_count += 1
        target = self.translate(request.path)
        try:
            target.parent.mkdir(parents=True, exist_ok=True)
            with open(target, "wb") as handle:
                handle.write(data)
        except OSError as error:
            return _StoredReply(self._errno_reply(request.id, error), None)
        return _StoredReply(OkReply(id=request.id), None)

    @staticmethod
    def _errno_reply(request_id: str, error: OSError) -> Message:
        match error:
            case FileNotFoundError():
                errno_name, message = "ENOENT", "No such file or directory"
            case IsADirectoryError():
                errno_name, message = "EISDIR", "Is a directory"
            case NotADirectoryError():
                errno_name, message = "ENOTDIR", "Not a directory"
            case PermissionError():
                errno_name, message = "EACCES", "Permission denied"
            case _:
                errno_name, message = "EIO", str(error)
        return ErrorReply(id=request_id, errno=errno_name, message=message)

    # -- exec over real subprocesses --------------------------------------------

    async def _run_command(self, request: ExecRequest, stdin: bytes) -> _StoredReply:
        self.exec_count += 1
        current_user = os.environ.get("USER", "")
        if request.user is not None and request.user != current_user:
            # the daemon's unknown/unswitchable-user shape: a failed result
            # naming the user, never an exception (self_check expects this)
            reply = _result_reply(
                request,
                rc=1,
                stdout=b"",
                stderr=(
                    f"runuser: cannot switch to user {request.user!r} "
                    "from the CI endpoint\n"
                ).encode(),
            )
            self._store(request.id, reply)
            return reply
        try:
            process = await asyncio.create_subprocess_exec(
                *request.cmd,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=self.translate(request.cwd) if request.cwd else self.root,
                env={**os.environ, **request.env},
                start_new_session=True,  # its own process group: the budget kill is a group kill
            )
        except FileNotFoundError:
            reply = _result_reply(
                request,
                rc=127,
                stdout=b"",
                stderr=f"{request.cmd[0]}: command not found\n".encode(),
            )
            self._store(request.id, reply)
            return reply
        except (PermissionError, OSError):
            reply = _result_reply(
                request,
                rc=126,
                stdout=b"",
                stderr=f"{request.cmd[0]}: permission denied\n".encode(),
            )
            self._store(request.id, reply)
            return reply
        budget_s = (
            request.budget.command_ms / 1000
            if request.budget.command_ms is not None and not self.ignore_command_budget
            else None
        )
        try:
            stdout, stderr = await asyncio.wait_for(
                process.communicate(stdin), timeout=budget_s
            )
        except TimeoutError:
            self._group_kill(process)
            await process.wait()  # SIGKILL closes the pipes; wait reaps
            reply = _StoredReply(
                ErrorReply(
                    id=request.id,
                    errno="ETIME",
                    message=f"command budget expired after {request.budget.command_ms} ms",
                    layer="command",
                ),
                None,
            )
            self._store(request.id, reply)
            return reply
        stdout, stdout_truncated = stdout[:STREAM_CAP], len(stdout) > STREAM_CAP
        stderr, stderr_truncated = stderr[:STREAM_CAP], len(stderr) > STREAM_CAP
        payload = stdout + stderr
        reply = _StoredReply(
            ExecResult(
                id=request.id,
                rc=process.returncode or 0,
                stdout_size=len(stdout),
                stderr_size=len(stderr),
                stdout_truncated=stdout_truncated,
                stderr_truncated=stderr_truncated,
                data_size=len(payload) or None,
            ),
            payload if payload else None,
        )
        self._store(request.id, reply)
        return reply

    @staticmethod
    def _group_kill(process: asyncio.subprocess.Process) -> None:
        """TERM then KILL the whole process group (the daemon's kill-grace shape, compressed for tests)."""
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            return
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass


def _result_reply(
    request: ExecRequest, rc: int, stdout: bytes, stderr: bytes
) -> _StoredReply:
    """An ExecResult reply whose declared sizes and bulk always agree."""
    payload = stdout + stderr
    return _StoredReply(
        ExecResult(
            id=request.id,
            rc=rc,
            stdout_size=len(stdout),
            stderr_size=len(stderr),
            data_size=len(payload) or None,
        ),
        payload if payload else None,
    )

"""`LocalEndpoint`: a `FakeGuest` whose exec runs REAL argv on this host under a temp root.

Test infrastructure (deliberately not shipped in the package: it executes arbitrary host commands), existing so inspect-ai's full `self_check` suite can run against the provider on CI with zero VMs. It emulates the Go daemon's observable contract: real subprocesses in their own process group with the in-guest command budget enforced by a group TERM-then-KILL (so the timeout-kills-children checks are genuine), per-stream output caps with truncation flags, rc 127/126 for missing/unexecutable commands, the daemon's unknown-user error shape, and errno-tagged file replies. Path translation maps the agent home (`/home/agent`) onto the temp root; other absolute paths touch the host (the suite uses `/tmp/...` and reads `/etc`).
"""

import asyncio
import os
import pwd
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
"""Per-stream output cap, mirroring the daemon's 16 MiB `OutputCap`.

Known emulation limits, stated: paths embedded inside `sh -c` COMMAND STRINGS are not translated (only path-shaped argv elements and file-op paths are), and the budget kill is TERM-then-immediate-KILL with zero grace (the real daemon waits its kill grace between the two)."""


class LocalEndpoint(FakeGuest):
    """A guest endpoint backed by the local host (see module docstring)."""

    def __init__(self, name: str, root: Path) -> None:
        super().__init__(name)
        self.root = root
        self.file_owners: dict[str, str] = {}
        """Ownership emulation: who owns each written path (the daemon writes as agent; a root chown transfers). The CI host cannot really chown, so tests pin the third-user wrapper flow through this record."""
        root.mkdir(parents=True, exist_ok=True)
        (root / "tmp").mkdir(exist_ok=True)

    # -- path translation -----------------------------------------------------

    def translate(self, path: str) -> Path:
        """The in-guest path as a host path.

        The agent home maps onto the temp root, and `/tmp` maps onto a PRIVATE tmp under the root: the self_check suite uses fixed `/tmp/...` paths, and two parametrizations racing on the real host `/tmp` under pytest-xdist would share mutable state (and litter the machine). Other absolute paths (the suite reads `/etc`, lists `/usr/bin`) touch the host read-only.
        """
        if path == AGENT_HOME:
            return self.root
        agent_prefix = AGENT_HOME + "/"
        if path.startswith(agent_prefix):
            return self.root / path[len(agent_prefix) :]
        if path == "/tmp":
            return self.root / "tmp"
        if path.startswith("/tmp/"):
            return self.root / "tmp" / path[len("/tmp/") :]
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
        self.file_modes[request.path] = request.mode
        self.file_owners[request.path] = "agent"  # the daemon's write identity
        target = self.translate(request.path)
        try:
            target.parent.mkdir(parents=True, exist_ok=True)
            if request.mode is not None:
                # mirror the daemon's ordering: pin the permission bits BEFORE
                # any content lands (a pre-existing file's old, wider bits must
                # never cover the fresh bytes), so open without truncating,
                # fchmod, then truncate and write
                descriptor = os.open(target, os.O_WRONLY | os.O_CREAT, request.mode)
                with open(descriptor, "wb") as handle:
                    os.fchmod(handle.fileno(), request.mode)
                    handle.truncate(0)
                    handle.write(data)
            else:
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
        if request.cmd and request.cmd[0] == "chown" and request.user == "root":
            # ownership emulation: the CI host cannot chown as root, so record
            # what the daemon-side chown would set (the third-user wrapper
            # flow) and answer success
            owner = next(part for part in request.cmd[1:] if part != "--")
            self.file_owners[request.cmd[-1]] = owner
            reply = _result_reply(request, rc=0, stdout=b"", stderr=b"")
            self._store(request.id, reply)
            return reply
        current_user = pwd.getpwuid(os.geteuid()).pw_name
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
        # argv elements that are agent-home or /tmp paths are translated the
        # same way file paths are: self_check manipulates its fixed /tmp
        # fixtures through exec (mkdir/rm/ls) and the provider's wrapper
        # script is invoked by its uploaded path, so argv and the filesystem
        # must see one coherent namespace
        argv = [
            str(self.translate(part))
            if part == "/tmp"
            or part.startswith("/tmp/")
            or part == AGENT_HOME
            or part.startswith(AGENT_HOME + "/")
            else part
            for part in request.cmd
        ]
        host_cwd = self.translate(request.cwd) if request.cwd else self.root
        if not host_cwd.is_dir():
            # the real daemon reports a missing or non-directory cwd as an
            # errno error, never as command-not-found (a spawn error is
            # ambiguous between the two: distinguish before spawning)
            not_dir = host_cwd.exists()
            reply = _StoredReply(
                ErrorReply(
                    id=request.id,
                    errno="ENOTDIR" if not_dir else "ENOENT",
                    message=f"chdir {request.cwd}: "
                    + ("not a directory" if not_dir else "no such file or directory"),
                ),
                None,
            )
            self._store(request.id, reply)
            return reply
        try:
            process = await asyncio.create_subprocess_exec(
                *argv,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=host_cwd,
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
        except OSError:  # deliberate collapse: every spawn OSError is the 126 shape
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
        partial_sink: dict[str, bytes] = {}
        try:
            async with asyncio.timeout(budget_s):
                (stdout, stdout_truncated), (stderr, stderr_truncated) = await _pump(
                    process, stdin, partial_sink
                )
        except TimeoutError:
            self._group_kill(process)
            await process.wait()  # SIGKILL closes the pipes; wait reaps
            # the daemon-shaped partial: the killed command's output tail
            # (stdout when it produced any, else stderr), capped, text-only
            source = partial_sink.get("stdout") or partial_sink.get("stderr") or b""
            tail = source[-4096:].decode("utf-8", errors="ignore") or None
            reply = _StoredReply(
                ErrorReply(
                    id=request.id,
                    errno="ETIME",
                    message=f"command budget expired after {request.budget.command_ms} ms",
                    layer="command",
                    partial=tail,
                ),
                None,
            )
            self._store(request.id, reply)
            return reply
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


async def _pump(
    process: asyncio.subprocess.Process,
    stdin: bytes,
    partial_sink: dict[str, bytes] | None = None,
) -> tuple[tuple[bytes, bool], tuple[bytes, bool]]:
    """Feed stdin and read both streams with the per-stream cap applied WHILE reading, mirroring the daemon's bounded memory (never buffer-then-slice).

    `partial_sink` (keys `stdout`/`stderr`) receives whatever had been read so far even when this coroutine is cancelled by the caller's budget, so the ETIME reply can carry the daemon-shaped `partial` tail.
    """

    async def feed() -> None:
        writer = process.stdin
        if writer is None:
            return
        try:
            if stdin:
                writer.write(stdin)
                await writer.drain()
        except (BrokenPipeError, ConnectionResetError):
            pass  # the command exited without reading its stdin
        finally:
            writer.close()

    async def read_capped(
        reader: asyncio.StreamReader | None, sink_key: str
    ) -> tuple[bytes, bool]:
        if reader is None:
            return b"", False
        buffer = bytearray()
        try:
            while chunk := await reader.read(1 << 16):
                if len(buffer) <= STREAM_CAP:
                    buffer.extend(chunk[: STREAM_CAP + 1 - len(buffer)])
                # keep draining so the child never blocks on a full pipe
        finally:
            if partial_sink is not None:
                partial_sink[sink_key] = bytes(buffer[:STREAM_CAP])
        truncated = len(buffer) > STREAM_CAP
        return bytes(buffer[:STREAM_CAP]), truncated

    _, out, err = await asyncio.gather(
        feed(),
        read_capped(process.stdout, "stdout"),
        read_capped(process.stderr, "stderr"),
    )
    await process.wait()
    return out, err


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

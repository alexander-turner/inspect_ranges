"""The provider's operation surface: exec/read_file/write_file over the per-sample channel.

Each layer-2 attempt mints a FRESH request id (layer-1 same-id recovery already happened inside the channel), the error mapping is `errors.py`'s single table, and `SandboxEnvironmentLimits` values are read per call because `self_check` overrides them through ContextVars. The session-invalidation hook runs after a post-retry transient failure and after any side-effecting success that needed a same-id resend; it becomes load-bearing when the protocol's session field lands (provider-v1 slice 4) and is a no-op while no session is pinned.
"""

import logging
import shlex
from pathlib import PurePosixPath

from inspect_ai.util import SandboxEnvironmentLimits
from inspect_ai.util._subprocess import ExecResult as InspectExecResult

from .._channel.channel import (
    ChannelBudgetError,
    ExecOutcome,
    FileLimitExceeded,
    GuestError,
    MessageChannel,
    TransportFailure,
    request_id,
)
from .._channel.codec import MAX_CONTROL_PAYLOAD, EncodeError, encode_message
from .._channel.protocol import DEFAULT_BULK_CAP, Budget, ExecRequest
from .errors import (
    exec_permission_error,
    file_limit_error,
    human_size,
    map_file_failure,
    output_limit_error,
    timeout_error,
    unavailable,
)
from .retry import with_retry
from .state import SampleHandle

logger = logging.getLogger("inspect_ranges.provider")

AGENT_HOME = "/home/agent"
"""The per-sample working directory: the agent user's home; relative paths resolve against it host-side."""

_WRAPPER_MARGIN = 1_024
"""Headroom under the control-frame cap when deciding whether a request needs the wrapper (id and data_size fields vary a little between the probe and the real request)."""


def _request_fits(
    cmd: list[str],
    cwd: str,
    env: dict[str, str],
    user: str | None,
    budget: Budget,
) -> bool:
    """Whether the request's ENCODED control payload fits one frame.

    The bound is the canonical-JSON payload, not raw argv bytes: escape-heavy argv inflates several-fold and `env` counts too, so the decision dry-encodes the actual request shape rather than approximating.
    """
    probe = ExecRequest(
        id=request_id(), cmd=cmd, cwd=cwd, env=env, user=user, budget=budget
    )
    try:
        frames = encode_message(probe, None)
    except EncodeError:
        return False
    return len(frames[0]) <= MAX_CONTROL_PAYLOAD - _WRAPPER_MARGIN


def resolve_guest_path(path: str) -> str:
    """A caller path as the absolute in-guest path (relative joins the per-sample working directory)."""
    pure = PurePosixPath(path)
    if pure.is_absolute():
        return str(pure)
    return str(PurePosixPath(AGENT_HOME) / pure)


def _channel(handle: SampleHandle) -> MessageChannel:
    if handle.channel is None:
        raise RuntimeError("sample channel not initialized (sample_init incomplete)")
    return handle.channel


def _session_of(pong: object) -> str | None:
    """The daemon session id of a pong, once the protocol carries one (slice 4); `None` until then."""
    session = getattr(pong, "session", None)
    return session if isinstance(session, str) else None


async def confirm_session(handle: SampleHandle, guest: str, op: str) -> None:
    """Raise `SessionChangedError` when the guest's daemon session changed since the pin.

    No-op while no session is pinned (the protocol's session field arrives in slice 4). Called after a post-retry transient failure, and after a side-effecting success that needed a same-id resend, per the layer-2b design.
    """
    pinned = handle.sessions.get(guest)
    if pinned is None:
        return
    from .errors import SessionChangedError

    pong = await _channel(handle).ping(guest)
    observed = _session_of(pong)
    if observed is not None and observed != pinned:
        handle.sessions[guest] = observed  # re-pin so later samples/ops proceed
        raise SessionChangedError(guest, op, pinned, observed)


async def _bounded_exec(
    channel: MessageChannel,
    guest: str,
    cmd: list[str],
    *,
    suppress: bool,
) -> None:
    """One tightly bounded, never-retried maintenance exec (wrapper chmod/scrub)."""
    request = ExecRequest(
        id=request_id(),
        cmd=cmd,
        budget=Budget(command_ms=2_000, channel_ms=2_000, untimed_bound_ms=8_000),
    )
    try:
        await channel.exec(guest, request)
    except Exception:
        if not suppress:
            raise


async def provider_exec(
    handle: SampleHandle,
    guest: str,
    cmd: list[str],
    input: str | bytes | None,
    cwd: str | None,
    env: dict[str, str] | None,
    user: str | None,
    timeout: int | None,
) -> InspectExecResult[str]:
    """The contract's `exec` over the channel; see `LibvirtRangeSandboxEnvironment.exec` for semantics."""
    channel = _channel(handle)
    stdin = input.encode("utf-8") if isinstance(input, str) else input
    resolved_cwd = resolve_guest_path(cwd) if cwd is not None else AGENT_HOME
    budget = Budget(command_ms=timeout * 1000 if timeout is not None else None)
    needs_wrapper = not _request_fits(cmd, resolved_cwd, env or {}, user, budget)

    async def attempt() -> ExecOutcome:
        run_cmd, run_env = cmd, env or {}
        script_path: str | None = None
        if needs_wrapper:
            # the control frame is deliberately a single bounded frame (32 KiB,
            # never chunked), so an oversized request (huge or escape-heavy
            # argv, a large env) rides an uploaded wrapper script instead, the
            # guest-exec-lessons pattern channel-v1 documents. The upload
            # happens INSIDE each attempt: the script's first line removes it,
            # so a fresh-id retry (the accepted ESTALE double-run) must re-run
            # a freshly uploaded script, never exec a deleted file and return
            # a fabricated missing-file result. Env rides the script as
            # exports, which persists those values on the guest disk until the
            # script self-deletes (or the failure-path scrub removes it): an
            # accepted exposure, stated here honestly. The first word is
            # force-quoted so a NAME=value cmd[0] stays a command (ENOENT),
            # never a shell assignment.
            script_path = f"/tmp/.ir-exec-{request_id()}.sh"
            exports = "".join(
                f"export {shlex.quote(key)}={shlex.quote(value)}\n"
                for key, value in (env or {}).items()
            )
            first = "'" + cmd[0].replace("'", "'\\''") + "'"
            rest = " ".join(shlex.quote(part) for part in cmd[1:])
            script = (
                '#!/bin/sh\nrm -f -- "$0"\n'
                + exports
                + f"exec {first}{' ' if rest else ''}{rest}\n"
            )
            await provider_write_file(handle, guest, script_path, script)
            # best effort, tightly bounded: close the world-readable window
            # before the wrapper runs (the daemon-side write mode is the real
            # fix, recorded for slice 4)
            await _bounded_exec(
                channel, guest, ["chmod", "600", script_path], suppress=True
            )
            run_cmd, run_env = ["sh", script_path], {}
        request = ExecRequest(
            id=request_id(),
            cmd=run_cmd,
            cwd=resolved_cwd,
            env=run_env,
            user=user,
            budget=budget,
            data_size=len(stdin) if stdin is not None else None,
        )
        try:
            return await channel.exec(guest, request, stdin=stdin)
        except BaseException:
            if script_path is not None:
                # single-attempt scrub so failed attempts never accumulate
                # env-bearing scripts in guest /tmp; suppressed, never retried
                await _bounded_exec(
                    channel, guest, ["rm", "-f", "--", script_path], suppress=True
                )
            raise

    try:
        outcome = await with_retry(
            attempt,
            policy=handle.retry.exec_policy,
            stats=handle.stats,
            op="exec",
            endpoint=guest,
        )
    except ChannelBudgetError as failure:
        if failure.layer == "command":
            raise timeout_error(failure, None) from failure
        await confirm_session(handle, guest, "exec")
        raise unavailable(failure) from failure
    except TransportFailure as failure:
        await confirm_session(handle, guest, "exec")
        raise unavailable(failure) from failure
    # TamperError, SessionChangedError, GuestError, ValueError propagate unmapped

    if outcome.attempts > 1:
        await confirm_session(handle, guest, "exec")
    if outcome.stdout_truncated or outcome.stderr_truncated:
        # the daemon's own per-stream cap fired before anything reached the host
        raise output_limit_error(
            human_size(DEFAULT_BULK_CAP),
            outcome.stdout.decode("utf-8", errors="replace")
            if outcome.stdout
            else None,
        )
    limit = SandboxEnvironmentLimits.MAX_EXEC_OUTPUT_SIZE  # per call: a ContextVar
    if len(outcome.stdout) > limit or len(outcome.stderr) > limit:
        overflowing = outcome.stdout if len(outcome.stdout) > limit else outcome.stderr
        raise output_limit_error(
            SandboxEnvironmentLimits.MAX_EXEC_OUTPUT_SIZE_STR,
            overflowing[:limit].decode("utf-8", errors="replace"),
        )
    stdout = outcome.stdout.decode("utf-8", errors="replace")
    stderr = outcome.stderr.decode("utf-8", errors="replace")
    denied = exec_permission_error(outcome.rc, stderr)
    if denied is not None:
        raise denied
    returncode = _shell_rc(outcome.rc)
    return InspectExecResult(
        success=returncode == 0,
        returncode=returncode,
        stdout=stdout,
        stderr=stderr,
    )


def _shell_rc(rc: int) -> int:
    from .errors import shell_returncode

    return shell_returncode(rc)


async def provider_read_file(handle: SampleHandle, guest: str, file: str) -> bytes:
    """The contract's `read_file` (bytes form; the caller decodes for text mode)."""
    channel = _channel(handle)
    path = resolve_guest_path(file)
    limit = SandboxEnvironmentLimits.MAX_READ_FILE_SIZE  # per call: a ContextVar

    async def attempt() -> bytes:
        return await channel.read_file(guest, path, cap=limit)

    try:
        return await with_retry(
            attempt,
            policy=handle.retry.file_policy,
            stats=handle.stats,
            op="read_file",
            endpoint=guest,
        )
    except FileLimitExceeded as failure:
        raise file_limit_error(
            failure, SandboxEnvironmentLimits.MAX_READ_FILE_SIZE_STR
        ) from failure
    except GuestError as failure:
        mapped = map_file_failure(failure, file)
        if mapped is failure:
            raise
        raise mapped from failure
    except ChannelBudgetError as failure:
        if failure.layer == "command":
            raise timeout_error(failure, None) from failure
        await confirm_session(handle, guest, "read_file")
        raise unavailable(failure) from failure
    except TransportFailure as failure:
        await confirm_session(handle, guest, "read_file")
        raise unavailable(failure) from failure


async def provider_write_file(
    handle: SampleHandle, guest: str, file: str, contents: str | bytes
) -> None:
    """The contract's `write_file`; parents are auto-created by the daemon."""
    channel = _channel(handle)
    path = resolve_guest_path(file)
    data = contents.encode("utf-8") if isinstance(contents, str) else contents

    async def attempt() -> int:
        return await channel.write_file(guest, path, data)

    try:
        deliveries = await with_retry(
            attempt,
            policy=handle.retry.file_policy,
            stats=handle.stats,
            op="write_file",
            endpoint=guest,
        )
    except GuestError as failure:
        mapped = map_file_failure(failure, file)
        if mapped is failure:
            raise
        raise mapped from failure
    except ChannelBudgetError as failure:
        if failure.layer == "command":
            raise timeout_error(failure, None) from failure
        await confirm_session(handle, guest, "write_file")
        raise unavailable(failure) from failure
    except TransportFailure as failure:
        await confirm_session(handle, guest, "write_file")
        raise unavailable(failure) from failure
    if deliveries > 1:
        await confirm_session(handle, guest, "write_file")

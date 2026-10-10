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

_RUNUSER_RESET_KEYS = frozenset({"HOME", "SHELL", "USER", "LOGNAME", "PATH"})
"""Env keys util-linux runuser unconditionally resets on its user switch (its whitelist option ignores exactly these five); caller values for them only survive via the wrapper script's exports."""


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
    """A caller path as the absolute in-guest path (relative joins the per-sample working directory).

    This rule is Linux-only by design: PurePosixPath treats drive-letter and backslash-UNC paths as relative and would mangle them (forward-slash UNC happens to survive as absolute). Windows guests are gated in provider v1; when they un-gate, the daemon owns Windows path semantics (`Daemon.cs` `PathRules`: rooted and drive-relative shapes pass through, relative joins the exec identity's home) and this resolver must branch per guest platform rather than apply the POSIX join.
    """
    pure = PurePosixPath(path)
    if pure.is_absolute():
        return str(pure)
    return str(PurePosixPath(AGENT_HOME) / pure)


def _channel(handle: SampleHandle) -> MessageChannel:
    if handle.host is not None:
        # a lost lease (reaped host) fails the sample loudly at its next
        # operation rather than letting it run on a reclaimed range
        handle.host.check_lease()
    if handle.channel is None:
        raise RuntimeError("sample channel not initialized (sample_init incomplete)")
    return handle.channel


async def confirm_session(handle: SampleHandle, guest: str, op: str) -> None:
    """Raise `SessionChangedError` when the guest's daemon session changed since the pin.

    No-op while no session is pinned (boot not finished). Called after any resent or re-attempted delivery of a side-effecting operation, whatever its outcome shape, per the layer-2b design: a restarted daemon forgot its dedupe store, so the earlier delivery may have double-run.
    """
    pinned = handle.sessions.get(guest)
    if pinned is None:
        return
    from .errors import SessionChangedError

    observed = await _channel(handle).session(guest)
    if observed != pinned:
        handle.sessions[guest] = observed  # re-pin so later samples/ops proceed
        raise SessionChangedError(guest, op, pinned, observed)


async def _confirm_session_best_effort(
    handle: SampleHandle, guest: str, op: str
) -> None:
    """`confirm_session` for the arms that are about to raise their own failure.

    The confirm ping racing a daemon outage (the restart window itself) cannot be distinguished from plain unavailability, and the caller is about to surface an honest failure anyway: only a POSITIVE session change (or a tamper verdict, which propagates) outranks it.
    """
    try:
        await confirm_session(handle, guest, op)
    except (TransportFailure, ChannelBudgetError):
        return


async def _confirm_session_or_unavailable(
    handle: SampleHandle, guest: str, op: str
) -> None:
    """`confirm_session` after a SUCCESS that involved any re-delivery: a dead daemon at confirm time means exactly-once cannot be certified for the result in hand, which is unavailable-shaped, not silently fine."""
    try:
        await confirm_session(handle, guest, op)
    except (TransportFailure, ChannelBudgetError) as failure:
        raise unavailable(failure) from failure


async def _bounded_exec(
    channel: MessageChannel,
    guest: str,
    cmd: list[str],
    *,
    suppress: bool,
    user: str | None = None,
) -> None:
    """One tightly bounded, never-retried maintenance exec (wrapper chown/scrub).

    Deliberately outside the session-confirmation policy: both callers are idempotent (chown to a fixed owner, rm -f of one path), so a re-delivery cannot change state beyond what a single delivery does.
    """
    request = ExecRequest(
        id=request_id(),
        cmd=cmd,
        user=user,
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
    # two reasons to ride the wrapper: the encoded request does not fit one
    # control frame, or the env touches a key util-linux runuser always resets
    # (HOME, SHELL, USER, LOGNAME, PATH; --whitelist-environment ignores those
    # five) and the daemon's user switch would clobber the caller's value: the
    # wrapper's exports run after runuser, so they stick
    needs_wrapper = not _request_fits(
        cmd, resolved_cwd, env or {}, user, budget
    ) or bool(_RUNUSER_RESET_KEYS & (env or {}).keys())

    call_attempts = 0

    async def attempt() -> ExecOutcome:
        nonlocal call_attempts
        call_attempts += 1
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
            # the mode travels with the write (`WriteFileRequest.mode`): the
            # env-bearing script is 0600 and agent-owned at creation, so it is
            # never world-readable, not even briefly. For an explicit third
            # user (not agent, not root) one bounded root chown transfers
            # ownership before the exec: only the daemon (root), the agent,
            # and the requested user can ever read the env, and owner-only
            # bits are also what lets the script self-delete under sticky
            # /tmp (a non-owner's `rm -f -- "$0"` would be EPERM there,
            # stranding the secrets world-readable had the mode been widened
            # instead)
            await provider_write_file(handle, guest, script_path, script, mode=0o600)
            if user not in (None, "root", "agent"):
                await _bounded_exec(
                    channel,
                    guest,
                    ["chown", "--", user, script_path],
                    suppress=False,
                    user="root",
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
            # a re-delivered op that then timed out is exactly as restart-risky
            # as a re-delivered success (the session verdict outranks the
            # timeout verdict); re-delivery means a same-id wire resend OR a
            # fresh-id retry attempt of THIS call
            if (failure.attempts or 0) > 1 or call_attempts > 1:
                await _confirm_session_best_effort(handle, guest, "exec")
            # the daemon's ETIME reply may carry the killed command's output
            # tail (`ErrorReply.partial`); surface it on the TimeoutError
            raise timeout_error(failure, failure.partial) from failure
        await _confirm_session_best_effort(handle, guest, "exec")
        raise unavailable(failure) from failure
    except TransportFailure as failure:
        await _confirm_session_best_effort(handle, guest, "exec")
        raise unavailable(failure) from failure
    except GuestError as failure:
        # an errno-tagged failure after a re-delivery (same-id resend of this
        # attempt, or an earlier fresh-id attempt of this call) still means a
        # possible double-run on a restarted daemon; confirm before the
        # honest error propagates
        if (failure.attempts or 0) > 1 or call_attempts > 1:
            await _confirm_session_best_effort(handle, guest, "exec")
        raise
    # TamperError, SessionChangedError, ValueError propagate unmapped

    if outcome.attempts > 1 or call_attempts > 1:
        # either a same-id resend (wire layer) or a fresh-id re-attempt
        # (retry layer) of this call delivered more than once: both are
        # restart-risky
        await _confirm_session_or_unavailable(handle, guest, "exec")
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
    handle: SampleHandle,
    guest: str,
    file: str,
    contents: str | bytes,
    *,
    mode: int | None = None,
) -> None:
    """The contract's `write_file`; parents are auto-created by the daemon.

    `mode` sets the created file's permission bits atomically with the write; `None` keeps the daemon default.
    """
    channel = _channel(handle)
    path = resolve_guest_path(file)
    data = contents.encode("utf-8") if isinstance(contents, str) else contents

    call_attempts = 0

    async def attempt() -> int:
        nonlocal call_attempts
        call_attempts += 1
        return await channel.write_file(guest, path, data, mode=mode)

    try:
        deliveries = await with_retry(
            attempt,
            policy=handle.retry.file_policy,
            stats=handle.stats,
            op="write_file",
            endpoint=guest,
        )
    except GuestError as failure:
        # side-effecting op: a re-delivered attempt that then failed may still
        # have double-run on a restarted daemon; the session verdict comes
        # first
        if (failure.attempts or 0) > 1 or call_attempts > 1:
            await _confirm_session_best_effort(handle, guest, "write_file")
        mapped = map_file_failure(failure, file)
        if mapped is failure:
            raise
        raise mapped from failure
    except ChannelBudgetError as failure:
        if failure.layer == "command":
            if (failure.attempts or 0) > 1 or call_attempts > 1:
                await _confirm_session_best_effort(handle, guest, "write_file")
            raise timeout_error(failure, None) from failure
        await _confirm_session_best_effort(handle, guest, "write_file")
        raise unavailable(failure) from failure
    except TransportFailure as failure:
        await _confirm_session_best_effort(handle, guest, "write_file")
        raise unavailable(failure) from failure
    if deliveries > 1 or call_attempts > 1:
        await _confirm_session_or_unavailable(handle, guest, "write_file")

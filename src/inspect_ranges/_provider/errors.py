"""The single mapping table from channel failures to the Inspect sandbox contract.

Every translation the provider performs lives here, so the error semantics the `self_check` suite asserts on (exception types, filenames in messages, the word "directory", shell return-code conventions) have exactly one home. `TamperError` is deliberately absent from every mapping: a tampering guest must never read as "sandbox temporarily unavailable", so it propagates unmapped and fails the sample hard.
"""

from inspect_ai.util import OutputLimitExceededError, SandboxUnavailableError

from .._channel.channel import (
    ChannelBudgetError,
    FileLimitExceeded,
    GuestError,
    TransportFailure,
)

PERMISSION_DENIED_RC = 126
"""The daemon reports an unexecutable command as rc 126 with "permission denied" on stderr."""


def exec_permission_error(rc: int, stderr: str) -> PermissionError | None:
    """The contract's rc-126 sniff: an unexecutable command raises `PermissionError`.

    The daemon has no distinct errno channel for exec-time EACCES; it reports rc 126 with "permission denied" on stderr (the shell convention), so the provider sniffs exactly that pair. Any other rc-126 (a command that itself exits 126) passes through as an ordinary result.
    """
    if rc == PERMISSION_DENIED_RC and "permission denied" in stderr.lower():
        return PermissionError(stderr.strip() or "permission denied")
    return None


class SessionChangedError(RuntimeError):
    """The guest daemon restarted between operations, so exactly-once cannot be certified.

    A daemon restart empties the dedupe and durable-result stores, which means an in-flight operation's fate is unknown and a resend could double-run. The provider surfaces this as a hard, operator-visible sample failure (deliberately not `SandboxUnavailableError`, which would leave the sample running against a guest whose state is no longer the one the sample built). Detection is post-hoc: true exactly-once across a restart is impossible, and session honesty is a pre-compromise property.
    """

    def __init__(self, guest: str, op: str, pinned: str, observed: str) -> None:
        self.guest = guest
        self.op = op
        self.pinned = pinned
        self.observed = observed
        super().__init__(
            f"guest {guest!r} daemon session changed during {op} "
            f"(pinned {pinned!r}, observed {observed!r}): the daemon restarted, "
            "in-flight operation fates are unknown, exactly-once cannot be certified"
        )


def shell_returncode(rc: int) -> int:
    """The wire's signed rc (killed-by-signal is `-N`) as the shell convention (`128 + N`)."""
    return 128 - rc if rc < 0 else rc


def unavailable(
    error: ChannelBudgetError | TransportFailure,
) -> SandboxUnavailableError:
    """An infrastructure failure the retry layer could not recover: the sandbox is unavailable.

    Only channel/untimed/transport budget layers and transport failures map here. A command-layer budget is a real timeout and maps to `TimeoutError` instead (`timeout_error`); routing one here would leave the sample running past a genuine command timeout, so the table defends itself.

    Raises:
        ValueError: `error` is a command-layer budget (caller bug, never maskable).
    """
    if isinstance(error, ChannelBudgetError) and error.layer == "command":
        raise ValueError(
            "a command-layer budget is a real timeout: map it with timeout_error, "
            "never unavailable"
        )
    return SandboxUnavailableError(str(error))


class CommandTimeout(TimeoutError):
    """A command-layer budget expiry as the contract's `TimeoutError`.

    `truncated_output` is a real attribute so Inspect's proxy (which reads it via `getattr`) carries partial output into the transcript (`SandboxTimeoutError`).
    """

    def __init__(self, message: str, truncated_output: str | None) -> None:
        super().__init__(message)
        self.truncated_output = truncated_output


def timeout_error(
    error: ChannelBudgetError, truncated_output: str | None
) -> CommandTimeout:
    """A command-layer budget expiry as the contract's `TimeoutError` with partial output attached."""
    return CommandTimeout(str(error), truncated_output)


def map_file_failure(error: GuestError, path: str) -> BaseException:
    """A file operation's errno-tagged guest failure as the contract's exception.

    The contract's `self_check` asserts the filename appears in `FileNotFoundError` and `PermissionError` messages and the word "directory" in `IsADirectoryError`; unknown errnos return the original error (surfaced as-is, never guessed into a stdlib type).
    """
    match error.errno:
        case "ENOENT":
            return FileNotFoundError(f"file not found: {path}")
        case "EACCES" | "EPERM":
            return PermissionError(f"permission denied: {path}")
        case "EISDIR":
            return IsADirectoryError(f"{path} is a directory")
        case "ENOTDIR":
            return NotADirectoryError(f"{path}: a path component is not a directory")
        case _:
            return error


def output_limit_error(
    limit_str: str, truncated_output: str | None
) -> OutputLimitExceededError:
    """A properly constructed `OutputLimitExceededError` (never a faked message string).

    Callers pass the EXACT limit string the contract renders for the limit that fired: `SandboxEnvironmentLimits.MAX_READ_FILE_SIZE_STR` when the per-call read cap fired (`self_check` asserts that very string appears), or `human_size(...)` of the daemon's own stream cap when the guest truncated first.
    """
    return OutputLimitExceededError(limit_str, truncated_output)


def file_limit_error(
    error: FileLimitExceeded, limit_str: str
) -> OutputLimitExceededError:
    """An honest guest-side read truncation as the contract's `OutputLimitExceededError`."""
    del error  # the partial bytes are deliberately not surfaced (may be binary)
    return output_limit_error(limit_str, None)


def human_size(size_bytes: int) -> str:
    """Byte counts as the contract's human-readable rendering.

    Deliberately duplicates inspect-ai's private `_human_readable_size` rather than importing a private module at runtime; the parity test (`test_human_size_matches_the_contract_rendering`) pins the two together, so a divergence fails CI instead of silently changing the message `self_check` asserts on.
    """
    if size_bytes >= 1024**3 and size_bytes % 1024**3 == 0:
        return f"{size_bytes // 1024**3} GiB"
    if size_bytes >= 1024**2 and size_bytes % 1024**2 == 0:
        return f"{size_bytes // 1024**2} MiB"
    if size_bytes >= 1024 and size_bytes % 1024 == 0:
        return f"{size_bytes // 1024} KiB"
    return f"{size_bytes} bytes"

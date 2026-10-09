"""Slice-1 battery: the channel-to-Inspect error mapping table."""

import pytest
from inspect_ai.util import OutputLimitExceededError, SandboxUnavailableError
from inspect_ranges._channel.channel import (
    ChannelBudgetError,
    FileLimitExceeded,
    GuestError,
    TransportFailure,
)
from inspect_ranges._provider.errors import (
    SessionChangedError,
    exec_permission_error,
    file_limit_error,
    human_size,
    map_file_failure,
    output_limit_error,
    shell_returncode,
    timeout_error,
    unavailable,
)


@pytest.mark.parametrize(
    ("errno", "expected_type", "required_substrings"),
    [
        ("ENOENT", FileNotFoundError, ["/home/agent/config.yaml"]),
        ("EACCES", PermissionError, ["/home/agent/config.yaml"]),
        ("EPERM", PermissionError, ["/home/agent/config.yaml"]),
        ("EISDIR", IsADirectoryError, ["directory"]),
        ("ENOTDIR", NotADirectoryError, ["directory"]),
    ],
)
def test_file_errno_mapping(
    errno: str, expected_type: type[BaseException], required_substrings: list[str]
) -> None:
    mapped = map_file_failure(
        GuestError(errno, "guest message"), "/home/agent/config.yaml"
    )
    assert type(mapped) is expected_type
    for substring in required_substrings:
        assert substring in str(mapped), f"{substring!r} not in {mapped}"


def test_unknown_errno_surfaces_the_original_error() -> None:
    original = GuestError("EMFILE", "too many open files")
    assert map_file_failure(original, "/x") is original


@pytest.mark.parametrize(
    ("wire_rc", "expected"),
    [(0, 0), (70, 70), (126, 126), (127, 127), (-15, 143), (-9, 137), (-2, 130)],
)
def test_shell_returncode_convention(wire_rc: int, expected: int) -> None:
    assert shell_returncode(wire_rc) == expected


def test_exec_permission_sniff() -> None:
    error = exec_permission_error(126, "sh: /etc/passwd: Permission denied")
    assert isinstance(error, PermissionError)
    assert "Permission denied" in str(error)
    # an ordinary command exiting 126 without the daemon's marker passes through
    assert exec_permission_error(126, "my own exit code") is None
    assert exec_permission_error(1, "permission denied") is None


def test_timeout_error_carries_truncated_output() -> None:
    failure = timeout_error(
        ChannelBudgetError("command", "command budget expired"), "partial out"
    )
    assert isinstance(failure, TimeoutError)
    assert failure.truncated_output == "partial out"
    assert "command budget expired" in str(failure)


def test_unavailable_refuses_command_layer() -> None:
    with pytest.raises(ValueError, match="command-layer"):
        unavailable(ChannelBudgetError("command", "command budget expired"))


def test_unavailable_mapping() -> None:
    for error in (
        TransportFailure("reply lost after 3 attempts"),
        ChannelBudgetError("channel", "no reply within the channel allowance"),
        ChannelBudgetError("untimed", "operation total bound expired"),
    ):
        mapped = unavailable(error)
        assert isinstance(mapped, SandboxUnavailableError)
        assert str(error) in str(mapped)


def test_output_limit_error_is_properly_constructed() -> None:
    error = output_limit_error("1 KiB", "trunc")
    assert isinstance(error, OutputLimitExceededError)
    assert error.limit_str == "1 KiB"
    assert error.truncated_output == "trunc"
    assert "limit of 1 KiB was exceeded" in str(error)


def test_file_limit_error_hides_binary_partial() -> None:
    error = file_limit_error(FileLimitExceeded("/f", b"\xc3\x28"), "100 MiB")
    assert isinstance(error, OutputLimitExceededError)
    assert error.truncated_output is None
    assert "limit of 100 MiB was exceeded" in str(error)


def test_human_size_matches_the_contract_rendering() -> None:
    from inspect_ai.util._sandbox.limits import _human_readable_size

    for value in (1024, 2048, 16 * 1024**2, 100 * 1024**2, 1024**3, 999, 1536):
        assert human_size(value) == _human_readable_size(value)


def test_session_changed_error_names_both_sessions_and_the_op() -> None:
    error = SessionChangedError("web", "write_file", "aaaa", "bbbb")
    message = str(error)
    assert "web" in message and "write_file" in message
    assert "aaaa" in message and "bbbb" in message
    assert error.guest == "web" and error.op == "write_file"

"""The operator shell: origin refusal, guest resolution, command builders, and the guest-bytes filter."""

import asyncio
import os
from pathlib import Path
from typing import Any

import pytest
from click.testing import CliRunner
from inspect_ranges._cli.shellcmd import shell
from inspect_ranges._runtime.ownership import owner_record, write_owner
from inspect_ranges._runtime.up import BootGuest, BootPlan
from inspect_ranges._terminal.operator import (
    SEND_HEX_CHUNK_BYTES,
    EscapeFilter,
    OperatorShellError,
    operator_sink_path,
    read_sink_command,
    require_operator_origin,
    resolve_guest,
    run_shell,
    send_hex_commands,
)
from inspect_ranges._terminal.session import SINK_DIR

PROJECT = "ir-tiny-shell"


def _guest(name: str, cid: int, **kwargs: Any) -> BootGuest:
    return BootGuest(
        name=name,
        cid=cid,
        image_file=f"{name}.qcow2",
        overlay_gb=10,
        readiness="daemon",
        **kwargs,
    )


def boot_plan() -> BootPlan:
    return BootPlan(
        parallel=True,
        guests=[
            _guest("web", 3000),
            _guest("attack", 3001, kind="attacker"),
            _guest("win", 3002, injector="unattend"),
        ],
        verify={},
    )


# -- origin rule ----------------------------------------------------------------


def test_origin_rule_refuses_provider_projects() -> None:
    """A provider-booted project (recorded origin) refuses with the up remedy named; up-origin and unregistered projects pass through to the attach's own checks."""
    record = owner_record(PROJECT, "tiny", "a" * 64, Path("/bundle"))
    require_operator_origin(PROJECT, record)  # up-origin: no origin field
    require_operator_origin(PROJECT, None)  # unregistered: attach refuses later
    provider = record.model_copy(update={"origin": "provider"})
    with pytest.raises(OperatorShellError, match="booted by the Inspect sandbox"):
        require_operator_origin(PROJECT, provider)


def test_cli_refuses_provider_origin_before_dialing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The CLI's origin check fires before any attach: a provider-origin project refuses even with no docker and no boot plan present."""
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path))
    state = tmp_path / "inspect-ranges" / "projects"
    record = owner_record(PROJECT, "tiny", "a" * 64, tmp_path / "bundle")
    write_owner(state, record.model_copy(update={"origin": "provider"}))
    result = CliRunner().invoke(shell, [PROJECT])
    assert result.exit_code != 0
    assert "booted by the Inspect sandbox provider" in result.output


# -- guest resolution -----------------------------------------------------------


def test_resolve_guest_defaults_to_the_sole_attacker() -> None:
    assert resolve_guest(boot_plan(), None) == "attack"


def test_resolve_guest_requires_a_name_without_a_default() -> None:
    """Two attackers (or none, with several guests) has no unambiguous default: the refusal lists the names."""
    plan = BootPlan(
        parallel=True,
        guests=[_guest("a", 3000, kind="attacker"), _guest("b", 3001, kind="attacker")],
        verify={},
    )
    with pytest.raises(OperatorShellError, match="name one of: a, b"):
        resolve_guest(plan, None)


def test_resolve_guest_single_guest_is_the_default() -> None:
    plan = BootPlan(parallel=True, guests=[_guest("solo", 3000)], verify={})
    assert resolve_guest(plan, None) == "solo"


def test_resolve_guest_refuses_unknown_names() -> None:
    with pytest.raises(OperatorShellError, match="no guest named 'nope'"):
        resolve_guest(boot_plan(), "nope")


def test_resolve_guest_refuses_windows_guests() -> None:
    """A guest recorded with the unattend injector is Windows: tmux is a POSIX surface, so the refusal names the guest."""
    with pytest.raises(OperatorShellError, match="'win' is a Windows guest"):
        resolve_guest(boot_plan(), "win")


# -- builders -------------------------------------------------------------------


def test_send_hex_chunks_under_the_tmux_command_limit() -> None:
    """Every byte rides as one hex argument, split so no command exceeds the chunk size; the bytes reassemble exactly."""
    data = bytes(range(256)) * 5  # 1280 bytes, includes NUL, ESC, and `;`
    commands = send_hex_commands("operator", data)
    assert len(commands) == 3
    for cmd in commands:
        assert cmd[:5] == ["tmux", "send-keys", "-t", "=operator:", "-H"]
        assert len(cmd) - 5 <= SEND_HEX_CHUNK_BYTES
    rebuilt = bytes(int(h, 16) for cmd in commands for h in cmd[5:])
    assert rebuilt == data


def test_sink_paths_are_per_attach_and_distinct_from_agent_sinks() -> None:
    """The operator sink carries its own prefix and a per-attach token, so an agent terminal session named `operator` can never collide and a reattach never replays old bytes."""
    first = operator_sink_path("operator", "aaaa1111")
    second = operator_sink_path("operator", "bbbb2222")
    assert first != second
    assert first.startswith(f"{SINK_DIR}/op-operator-")
    assert first != f"{SINK_DIR}/operator.pipe"


def test_read_sink_offsets_are_one_based_tail() -> None:
    """`tail -c +N` is 1-based: offset 0 reads from the first byte."""
    cmd = read_sink_command("/tmp/.x/op.pipe", 0, cap=10)
    assert cmd[-1] == "tail -c +1 -- /tmp/.x/op.pipe | head -c 10"
    assert read_sink_command("/tmp/.x/op.pipe", 7)[-1].startswith("tail -c +8 ")


# -- the guest-bytes filter -----------------------------------------------------


FILTER_CASES: list[tuple[str, bytes, bytes]] = [
    ("plain text", b"hello world\r\n", b"hello world\r\n"),
    ("utf-8 multibyte survives", "héllo — ✓".encode(), "héllo — ✓".encode()),
    ("csi sgr passes", b"\x1b[1;31mred\x1b[0m", b"\x1b[1;31mred\x1b[0m"),
    (
        "csi cursor and clear pass",
        b"\x1b[2J\x1b[H\x1b[10;20H",
        b"\x1b[2J\x1b[H\x1b[10;20H",
    ),
    ("two-byte escape passes", b"\x1b7text\x1b8", b"\x1b7text\x1b8"),
    ("charset escape passes", b"\x1b(Btext", b"\x1b(Btext"),
    ("osc title bel passes", b"\x1b]0;my title\x07after", b"\x1b]0;my title\x07after"),
    ("osc title st passes", b"\x1b]2;t\x1b\\after", b"\x1b]2;t\x1b\\after"),
    ("osc 52 clipboard dropped", b"a\x1b]52;c;ZXZpbA==\x07b", b"ab"),
    ("osc 52 st-terminated dropped", b"a\x1b]52;c;ZXZpbA==\x1b\\b", b"ab"),
    ("osc palette dropped", b"a\x1b]4;0;rgb:00/00/00\x07b", b"ab"),
    ("osc hyperlink dropped", b"a\x1b]8;;http://x\x07b", b"ab"),
    ("dcs dropped whole", b"a\x1bPq#0;2;0;0;0#0~~\x1b\\b", b"ab"),
    ("apc dropped whole", b"a\x1b_payload\x1b\\b", b"ab"),
    ("pm dropped whole", b"a\x1b^payload\x1b\\b", b"ab"),
    ("sos dropped whole", b"a\x1bXpayload\x1b\\b", b"ab"),
    ("dcs bel-terminated dropped", b"a\x1bPpayload\x07b", b"ab"),
]


@pytest.mark.parametrize(("name", "raw", "expected"), FILTER_CASES)
def test_filter_cases(name: str, raw: bytes, expected: bytes) -> None:
    assert EscapeFilter().feed(raw) == expected, name


def test_filter_handles_sequences_split_across_reads() -> None:
    """Poll reads split anywhere, including inside an escape sequence and inside the ST terminator; the verdict must not change."""
    raw = b"x\x1b]52;c;c2VjcmV0\x1b\\y\x1b[1mz"
    expected = b"xy\x1b[1mz"
    for split in range(1, len(raw)):
        filt = EscapeFilter()
        assert filt.feed(raw[:split]) + filt.feed(raw[split:]) == expected, split


def test_filter_drops_oversized_unterminated_sequences() -> None:
    """An OSC that never terminates is hostile buffering, not output: it is discarded past the cap and later text flows again."""
    filt = EscapeFilter()
    assert filt.feed(b"\x1b]52;c;" + b"A" * (70 * 1024)) == b""
    # still inside the dropped string until its terminator; then text flows
    assert filt.feed(b"stillpayload\x07visible") == b"visible"


def test_filter_osc_esc_without_st_stays_in_string() -> None:
    """An ESC inside an OSC body that is not part of ST does not end the string (nothing hostile escapes mid-sequence)."""
    filt = EscapeFilter()
    assert filt.feed(b"\x1b]52;c;ab\x1bcd\x07tail") == b"tail"


# -- run_shell preconditions ----------------------------------------------------


def test_run_shell_refuses_without_a_tty() -> None:
    """An interactive attach on a non-terminal stdin refuses before touching the guest (the oracle is never called: a bare object suffices)."""
    read_end, write_end = os.pipe()
    try:
        with pytest.raises(OperatorShellError, match="needs a terminal"):
            asyncio.run(run_shell(object(), "attack", stdin_fd=read_end))  # type: ignore[arg-type]
    finally:
        os.close(read_end)
        os.close(write_end)


def test_run_shell_refuses_bad_session_names() -> None:
    with pytest.raises(OperatorShellError, match="bad session name"):
        asyncio.run(run_shell(object(), "attack", session="Bad Name!"))  # type: ignore[arg-type]

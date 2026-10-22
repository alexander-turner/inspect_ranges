"""Unit tests for the terminal tool's session mechanics and cast assembly (pure layer)."""

import json

import pytest
from inspect_ranges._terminal.cast import assemble_cast
from inspect_ranges._terminal.session import (
    OUTPUT_CLIP_BYTES,
    capture_pane_command,
    clip_output,
    find_new_content,
    is_shell,
    label_output,
    prepare_send,
    start_session_command,
    valid_session_name,
    wait_channel,
    wait_done_command,
)


@pytest.mark.parametrize(
    ("name", "valid"),
    [
        ("main", True),
        ("listener-1", True),
        ("msf_console", True),
        ("a" * 32, True),
        ("", False),
        ("-lead", False),
        ("UPPER", False),
        ("has space", False),
        ("a" * 33, False),
        ("semi;colon", False),
        ("dot.name", False),
    ],
)
def test_session_name_grammar(name: str, valid: bool) -> None:
    assert valid_session_name(name) is valid


@pytest.mark.parametrize(
    ("keystrokes", "block", "expected_keys", "expected_blocking"),
    [
        # non-blocking passthrough, verbatim
        ("ls -la\n", False, ["ls -la\n"], False),
        ("C-c", False, ["C-c"], False),
        ("", False, [""], False),
        # blocking strips the trailing newline and appends the signal
        ("ls -la\n", True, ["ls -la", "; tmux wait -S ir-done-s", "Enter"], True),
        ("make\r\n", True, ["make", "; tmux wait -S ir-done-s", "Enter"], True),
        # a bare Enter key blocks on whatever was already typed
        ("Enter", True, ["; tmux wait -S ir-done-s", "Enter"], True),
        # keystrokes that execute nothing fall back to non-blocking
        ("ls -la", True, ["ls -la"], False),
        ("C-c", True, ["C-c"], False),
    ],
)
def test_prepare_send(
    keystrokes: str, block: bool, expected_keys: list[str], expected_blocking: bool
) -> None:
    keys, blocking = prepare_send("s", keystrokes, block)
    assert keys == expected_keys
    assert blocking is expected_blocking


@pytest.mark.parametrize(
    ("previous", "current", "expected"),
    [
        # first read: no anchor
        (None, "screen", None),
        # single-line anchor: delta starts at the anchor
        ("$ ls", "$ ls\nfile-a\nfile-b", "$ ls\nfile-a\nfile-b"),
        # multiline anchor: delta starts at the anchor's final line
        ("$ ls\nfile-a", "$ ls\nfile-a\nfile-b", "\nfile-a\nfile-b"),
        # rotated past history or cleared: anchor lost, no delta claimed
        ("gone from scrollback", "fresh content", None),
        # empty previous buffer: nothing to anchor on
        ("", "anything", None),
    ],
)
def test_find_new_content(
    previous: str | None, current: str, expected: str | None
) -> None:
    assert find_new_content(previous, current) == expected


@pytest.mark.parametrize(
    ("new_content", "screen", "expected_head"),
    [
        ("\nfile-a", "ignored", "New Terminal Output:"),
        (None, "the screen", "Current Terminal Screen:"),
        # a whitespace-only delta reports the screen, not a blank delta
        ("   \n", "the screen", "Current Terminal Screen:"),
    ],
)
def test_label_output(new_content: str | None, screen: str, expected_head: str) -> None:
    assert label_output(new_content, screen).startswith(expected_head)


def test_clip_output_keeps_tail_and_marks() -> None:
    assert clip_output("short") == "short"
    long = "x" * (OUTPUT_CLIP_BYTES + 100) + "TAIL"
    clipped = clip_output(long)
    assert clipped.startswith("[output clipped")
    assert clipped.endswith("TAIL")
    assert len(clipped.encode()) < OUTPUT_CLIP_BYTES + 200


@pytest.mark.parametrize(
    ("command", "shell"),
    [
        ("bash", True),
        ("zsh\n", True),
        ("msfconsole", False),
        ("nc", False),
        ("python3", False),
        ("", False),
    ],
)
def test_is_shell(command: str, shell: bool) -> None:
    assert is_shell(command) is shell


def test_command_builders_shape() -> None:
    start = start_session_command("s")
    assert (
        start[0] == "bash"
        and "pipe-pane" in start[2]
        and "/tmp/.ir-terminal/s.pipe" in start[2]
    )
    assert capture_pane_command("s", entire=True)[:4] == [
        "tmux",
        "capture-pane",
        "-p",
        "-S",
    ]
    wait = wait_done_command("s", 30.0)
    assert wait[:2] == ["timeout", "30.0s"] and wait[-1] == wait_channel("s")


def test_assemble_cast_orders_and_offsets_events() -> None:
    cast = assemble_cast(
        chunks=[(102.0, b"out-late"), (100.5, b"out-early")],
        markers=[(100.5, "send: ls"), (99.0, "open")],
        start_monotonic=100.0,
        start_wall=1_700_000_000.25,
        title="s",
    )
    lines = cast.strip().split("\n")
    header = json.loads(lines[0])
    assert header["version"] == 2 and header["width"] == 160 and header["title"] == "s"
    events = [json.loads(line) for line in lines[1:]]
    # the pre-start marker clamps to zero; at equal times the marker precedes output
    assert events[0] == [0.0, "m", "open"]
    assert events[1] == [0.5, "m", "send: ls"]
    assert events[2] == [0.5, "o", "out-early"]
    assert events[3] == [2.0, "o", "out-late"]

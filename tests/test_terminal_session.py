"""Unit tests for the terminal tool's session mechanics and cast assembly (pure layer)."""

import json

import pytest
from inspect_ranges._terminal.cast import assemble_cast
from inspect_ranges._terminal.session import (
    OUTPUT_CLIP_BYTES,
    SEND_CHUNK_CHARS,
    SessionState,
    capture_pane_command,
    clip_output,
    find_new_content,
    is_shell,
    label_output,
    multiline_block,
    prepare_send,
    scrub_harness_echo,
    send_keys_command,
    send_keys_commands,
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
        # blocking strips the trailing newline and appends the signal (one
        # argument, so no fragment can be tmux's lone-`;` command separator)
        ("ls -la\n", True, ["ls -la; tmux wait -S done-s-ab-7", "Enter"], True),
        ("make\r\n", True, ["make; tmux wait -S done-s-ab-7", "Enter"], True),
        # a bare Enter key blocks on whatever was already typed
        ("Enter", True, ["; tmux wait -S done-s-ab-7", "Enter"], True),
        # unescaped trailing semicolons are trimmed: `cmd;; tmux wait` is a
        # shell syntax error that runs nothing and stalls to the timeout
        ("echo hi;\n", True, ["echo hi; tmux wait -S done-s-ab-7", "Enter"], True),
        ("ls ; ;\n", True, ["ls; tmux wait -S done-s-ab-7", "Enter"], True),
        # an escaped `\;` is a literal shell argument, not a separator: it stays
        (
            "echo a\\;\n",
            True,
            ["echo a\\;; tmux wait -S done-s-ab-7", "Enter"],
            True,
        ),
        # keystrokes that execute nothing fall back to non-blocking
        ("ls -la", True, ["ls -la"], False),
        ("C-c", True, ["C-c"], False),
    ],
)
def test_prepare_send(
    keystrokes: str, block: bool, expected_keys: list[str], expected_blocking: bool
) -> None:
    keys, blocking = prepare_send("s", keystrokes, block, "ab-7")
    assert keys == expected_keys
    assert blocking is expected_blocking


def test_wait_channel_is_per_send() -> None:
    """A timed-out send's late signal must never release a later send's wait: tmux remembers unconsumed signals, so each send gets its own channel."""
    assert wait_channel("s", "ab-0") != wait_channel("s", "ab-1")
    assert (
        prepare_send("s", "ls\n", True, "ab-0")[0]
        != prepare_send("s", "ls\n", True, "ab-1")[0]
    )


def test_wait_token_is_per_life() -> None:
    """Tmux signals are server-wide and outlive sessions, and the send counter restarts at zero on reopen, so each session life must carry a fresh channel token."""
    assert SessionState().token != SessionState().token


@pytest.mark.parametrize(
    ("keystrokes", "refused"),
    [
        # an interior newline runs its line immediately: the signal could land
        # inside a program that line started, so block refuses it
        ("cat\nhello\n", True),
        ("nc host 4444\r\nls\n", True),
        # single command lines, bare Enter, and non-executing keystrokes pass
        ("ls -la\n", False),
        ("make\r\n", False),
        ("Enter", False),
        ("C-c", False),
        ("a\nb", False),  # no trailing newline: falls back to non-blocking anyway
    ],
)
def test_multiline_block(keystrokes: str, refused: bool) -> None:
    assert multiline_block(keystrokes) is refused


def test_send_keys_command_shape() -> None:
    """Targets are exact-match (`=`), `--` keeps dash keystrokes out of option parsing, and the lone `;` tmux would consume as a command separator goes as hex."""
    assert send_keys_command("s", ["-la\n"]) == [
        "tmux",
        "send-keys",
        "-t",
        "=s:",
        "--",
        "-la\n",
    ]
    assert send_keys_command("s", [";"]) == [
        "tmux",
        "send-keys",
        "-t",
        "=s:",
        "-H",
        "3b",
    ]


def test_send_keys_commands_chunks_oversized_keys() -> None:
    """A tmux client command over ~16 KB fails ("command too long"), so an oversized key argument splits into literal `-l` chunks while small sends keep today's single-command path exactly."""
    assert send_keys_commands("s", ["ls\n"]) == [send_keys_command("s", ["ls\n"])]
    assert send_keys_commands("s", [";"]) == [send_keys_command("s", [";"])]
    big = "x" * (SEND_CHUNK_CHARS * 2 + 5)
    commands = send_keys_commands("s", [big, "Enter"])
    assert len(commands) == 4
    # the chunks are literal (`-l`: a chunk equal to a key name is typed, not
    # pressed) and reassemble to the original key argument
    assert all("-l" in command for command in commands[:3])
    assert "".join(command[-1] for command in commands[:3]) == big
    # the Enter key stays a key press, never a literal chunk
    assert commands[3] == send_keys_command("s", ["Enter"])
    # a chunk boundary landing on a lone `;` still goes as the hex byte
    semi = "y" * SEND_CHUNK_CHARS + ";"
    assert send_keys_commands("s", [semi])[-1][-2:] == ["-H", "3b"]


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
    ("new_content", "screen", "first_read", "expected_head"),
    [
        # a determinable delta returns raw, no header (viewer UX review 2026-10-23)
        ("\nfile-a", "ignored", False, "\nfile-a"),
        (None, "the screen", False, "Current Terminal Screen:"),
        # a whitespace-only delta reports the screen, not a blank delta
        ("   \n", "the screen", False, "Current Terminal Screen:"),
        # a session's FIRST read has no previously-seen screen to re-act on,
        # so the label is noise there (viewer UX review 2026-10-24); the
        # mid-session lost-anchor fallback above keeps it
        (None, "the screen", True, "the screen"),
        ("   \n", "the screen", True, "the screen"),
    ],
)
def test_label_output(
    new_content: str | None, screen: str, first_read: bool, expected_head: str
) -> None:
    assert label_output(new_content, screen, first_read=first_read).startswith(
        expected_head
    )


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
        and "/tmp/.guestd/s.pipe" in start[2]
    )
    # the sink truncates at open: a reopened name must not replay its last life
    assert ": > /tmp/.guestd/s.pipe" in start[2]
    # history-limit applies only to windows created after it is set, so the
    # global raise must precede new-session (and be restored after)
    assert start[2].index("history-limit 50000") < start[2].index("new-session")
    assert capture_pane_command("s", entire=True)[:4] == [
        "tmux",
        "capture-pane",
        "-p",
        "-S",
    ]
    assert capture_pane_command("s")[-1] == "=s:"  # exact-match target
    wait = wait_done_command("s", 30.0, "ab-3")
    assert wait[:2] == ["timeout", "30.0s"] and wait[-1] == wait_channel("s", "ab-3")


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


def test_scrub_harness_echo_removes_wait_suffix() -> None:
    echoed = "$ ls /opt; tmux wait -S done-main-b7f168f4-1\nguestd\n$"
    scrubbed = scrub_harness_echo(echoed)
    assert "tmux wait" not in scrubbed
    assert scrubbed.startswith("$ ls /opt\n")


@pytest.mark.parametrize(
    ("cap_mb_env", "expected_mb"),
    [("", 50), ("200", 200), ("junk", 50), ("0", 1)],
)
def test_cast_store_cap_parses_with_fallback(
    monkeypatch: pytest.MonkeyPatch, cap_mb_env: str, expected_mb: int
) -> None:
    from inspect_ranges._terminal.cast import CAST_STORE_CAP_ENV, cast_store_cap_bytes

    if cap_mb_env:
        monkeypatch.setenv(CAST_STORE_CAP_ENV, cap_mb_env)
    else:
        monkeypatch.delenv(CAST_STORE_CAP_ENV, raising=False)
    assert cast_store_cap_bytes() == expected_mb * 1024 * 1024


def test_clip_cast_keeps_header_and_tail_with_a_marker() -> None:
    import json as json_module

    from inspect_ranges._terminal.cast import clip_cast

    header = json_module.dumps({"version": 2, "width": 80, "height": 24})
    events = [
        json_module.dumps([float(i), "o", f"line-{i:04d} " + "x" * 50])
        for i in range(100)
    ]
    cast = header + "\n" + "\n".join(events)
    clipped = clip_cast(cast, 2000)
    lines = clipped.split("\n")
    assert json_module.loads(lines[0])["version"] == 2, "the header survives"
    marker = json_module.loads(lines[1])
    assert marker[1] == "m" and "clipped" in marker[2]
    assert len(clipped.encode()) <= 2000 + len(lines[1])  # marker rides the budget
    for line in lines[2:]:
        event = json_module.loads(line)  # every kept line is a whole event
        assert event[1] == "o"
    assert "line-0099" in clipped and "line-0000" not in clipped, "tail kept, head cut"


def test_clip_cast_leaves_small_casts_alone() -> None:
    from inspect_ranges._terminal.cast import clip_cast

    cast = '{"version": 2}\n[0.1, "o", "hi"]'
    assert clip_cast(cast, 10_000) == cast

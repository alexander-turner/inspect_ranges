"""tmux session mechanics for the `terminal` tool: command builders, send preparation, and the delta heuristic.

Adapted from terminal-bench's `TmuxSession` (`terminal_bench/terminal/tmux_session.py`, github.com/laude-institute/terminal-bench, Apache-2.0; see `design/inspect-ranges/LICENSES.md`): the `tmux wait -S` blocking completion signal, the previous-buffer delta heuristic with its two-label output, and the pane/history/pipe-pane session setup. Changes from the original: per-send wait channels scoped to named sessions (multiple sessions, and a channel never reused across sends or session lives), a shell-only guard input for blocking sends, and everything expressed as pure argv builders so the tool layer owns execution.

Everything here is pure: builders return argv lists, the heuristic maps strings to strings. The tool layer (`tool.py`) runs the argv through `sandbox().exec` and owns all state.
"""

from __future__ import annotations

import re
import uuid
from dataclasses import dataclass, field

from .._brand import GUEST_BRAND

PANE_WIDTH = 160
PANE_HEIGHT = 40
HISTORY_LIMIT = 50_000
OUTPUT_CLIP_BYTES = 10_000

# session names key tmux targets, wait channels, and sink paths; the strict
# grammar makes them safe to splice into the pipe-pane shell line
SESSION_NAME = re.compile(r"[a-z0-9][a-z0-9_-]{0,31}\Z")

# process names #{pane_current_command} reports that count as "at a shell":
# the blocking completion signal is shell text and must never be typed into
# whatever else owns the pane (a caught reverse shell, msfconsole, telnet)
SHELLS = frozenset({"bash", "sh", "zsh", "dash", "ksh", "fish"})

_ENTER_KEYS = frozenset({"Enter", "C-m", "KPEnter", "C-j", "^M", "^J"})
_NEWLINE_CHARS = "\r\n"

SINK_DIR = f"/tmp/.{GUEST_BRAND}"


def sink_path(session: str) -> str:
    """The pipe-pane sink file for a session, under the capture directory."""
    return f"{SINK_DIR}/{session}.pipe"


def wait_channel(session: str, nonce: str) -> str:
    """The per-send tmux wait channel the blocking completion signal uses.

    The channel carries a per-send `nonce` because tmux remembers a `wait -S` signal that fires with no waiter: a timed-out blocking send whose command later completes would otherwise leave a stale signal that releases the next blocking wait on the session immediately. Signals are server-wide and outlive sessions, and the send counter restarts at zero when a name is reopened, so the nonce the tool passes is the session life's `SessionState.token` plus the send counter, never the counter alone. The name is deliberately bland (`done-...`): it echoes in the pane, so it must not read as a harness marker (`_brand.py`).
    """
    return f"done-{session}-{nonce}"


def valid_session_name(session: str) -> bool:
    """Whether a session name fits the grammar (lowercase, digits, `_`/`-`, max 32)."""
    return bool(SESSION_NAME.match(session))


def target(session: str) -> str:
    """The tmux target for a session: `=` pins exact-name matching (a bare name prefix-matches other sessions) and the trailing `:` selects the active pane, which pane-target commands require alongside `=`."""
    return f"={session}:"


def start_session_command(session: str) -> list[str]:
    """Argv creating the session: fixed pane size, deep history, pipe-pane into the sink.

    The sink truncates at open so a reopened session name never replays a previous life's output into its capture. `history-limit` applies only to windows created after it is set, so the global option is raised before `new-session` and restored after (the per-session set covers windows the agent creates later inside the session).
    """
    sink = sink_path(session)
    return [
        "bash",
        "-c",
        (
            f"mkdir -p {SINK_DIR} && : > {sink} && "
            f'prev="$(tmux show-options -gv history-limit 2>/dev/null)"; '
            f"tmux set-option -g history-limit {HISTORY_LIMIT} \\; "
            f"new-session -x {PANE_WIDTH} -y {PANE_HEIGHT} -d -s {session} \\; "
            f"set-option -t {target(session)} history-limit {HISTORY_LIMIT} \\; "
            f"pipe-pane -t {target(session)} 'cat >> {sink}' && "
            f'if [ -n "$prev" ]; then tmux set-option -g history-limit "$prev"; '
            f"else tmux set-option -gu history-limit; fi"
        ),
    ]


def has_session_command(session: str) -> list[str]:
    """Argv testing whether the session exists (exit 0 when it does; `=` pins exact-name matching, since a bare target prefix-matches other sessions)."""
    return ["tmux", "has-session", "-t", target(session)]


def kill_session_command(session: str) -> list[str]:
    """Argv killing the session (exact-name target)."""
    return ["tmux", "kill-session", "-t", target(session)]


def remove_sink_command(session: str) -> list[str]:
    """Argv removing the session's pipe-pane sink after close: a closed session must not leave its sink file behind (sessions still open at finalize keep theirs; the guest is torn down with the sample)."""
    return ["rm", "-f", sink_path(session)]


def list_sessions_command() -> list[str]:
    """Argv listing session names, one per line."""
    return ["tmux", "list-sessions", "-F", "#{session_name}"]


def send_keys_command(session: str, keys: list[str]) -> list[str]:
    """Argv sending key arguments to the session's pane (exact-name target).

    `--` ends option parsing, so keystrokes starting with `-` are typed rather than read as `send-keys` flags. A lone `;` is the one argument tmux's client still consumes as a command separator even after `--`, so it is sent as its hex byte instead.
    """
    if keys == [";"]:
        return ["tmux", "send-keys", "-t", target(session), "-H", "3b"]
    return ["tmux", "send-keys", "-t", target(session), "--", *keys]


# tmux rejects a client command over ~16 KB ("command too long"), so larger
# key arguments split into literal chunks well under the limit (chars, so a
# fully multibyte chunk stays under 8 KB encoded)
SEND_CHUNK_CHARS = 2000


def _send_literal_command(session: str, chunk: str) -> list[str]:
    """Argv typing one chunk verbatim: `-l` disables key-name lookup, so a chunk that happens to equal a key name (`Enter`) is typed, not pressed; the lone-`;` separator still needs its hex form."""
    if chunk == ";":
        return ["tmux", "send-keys", "-t", target(session), "-H", "3b"]
    return ["tmux", "send-keys", "-t", target(session), "-l", "--", chunk]


def send_keys_commands(session: str, keys: list[str]) -> list[list[str]]:
    """The argv sequence sending the prepared key arguments, splitting oversized ones.

    Keys at most `SEND_CHUNK_CHARS` long go through `send_keys_command` exactly as before (one command, key names honored). A longer key is never a tmux key name, so it splits into literal (`-l`) chunks that each fit tmux's client command limit; a 100 KB paste types through where a single `send-keys` would fail with "command too long".
    """
    if all(len(key) <= SEND_CHUNK_CHARS for key in keys):
        return [send_keys_command(session, keys)]
    commands: list[list[str]] = []
    for key in keys:
        if len(key) <= SEND_CHUNK_CHARS:
            commands.append(send_keys_command(session, [key]))
        else:
            commands.extend(
                _send_literal_command(session, key[i : i + SEND_CHUNK_CHARS])
                for i in range(0, len(key), SEND_CHUNK_CHARS)
            )
    return commands


def capture_pane_command(session: str, entire: bool = False) -> list[str]:
    """Argv capturing the visible pane, or the whole scrollback with `entire` (exact-name target)."""
    extra = ["-S", "-"] if entire else []
    return ["tmux", "capture-pane", "-p", *extra, "-t", target(session)]


def pane_command_command(session: str) -> list[str]:
    """Argv reporting the pane's current foreground command name (exact-name target)."""
    return [
        "tmux",
        "display-message",
        "-p",
        "-t",
        target(session),
        "#{pane_current_command}",
    ]


def wait_done_command(session: str, timeout_s: float, nonce: str) -> list[str]:
    """Argv blocking on the send's wait channel under a hard timeout."""
    return ["timeout", f"{timeout_s}s", "tmux", "wait", wait_channel(session, nonce)]


def is_shell(pane_current_command: str) -> bool:
    """Whether the pane's foreground command is a shell (blocking sends allowed)."""
    return pane_current_command.strip() in SHELLS


def _is_enter_key(key: str) -> bool:
    return key in _ENTER_KEYS


def _executes(keystrokes: str) -> bool:
    """Whether the keystrokes end by executing a command (Enter key or trailing newline)."""
    return _is_enter_key(keystrokes) or bool(re.search(r"[\r\n]$", keystrokes))


def multiline_block(keystrokes: str) -> bool:
    """Whether a blocking send must be refused because the keystrokes span lines.

    An interior newline executes its line the moment it is typed, so by the time the appended completion signal reaches the pane an earlier line may have started a program (`telnet`, a caught shell, `msfconsole`) that would receive the signal text: the shell-only guard checked the pane before any of it was sent. Blocking sends take a single command line.
    """
    if not _executes(keystrokes) or _is_enter_key(keystrokes):
        return False
    return bool(re.search(r"[\r\n]", keystrokes.rstrip(_NEWLINE_CHARS)))


def _trim_trailing_semicolons(command: str) -> str:
    r"""Drop unescaped trailing semicolons (and surrounding whitespace) from a blocking command line: appending the `; tmux wait` signal after one would make `cmd;;`, a shell syntax error that never runs the command and stalls the send to its full timeout. A `\;` stays, since the shell reads it as a literal argument, not a separator."""
    trimmed = command.rstrip()
    while trimmed.endswith(";") and not trimmed.endswith("\\;"):
        trimmed = trimmed[:-1].rstrip()
    return trimmed


def prepare_send(
    session: str, keystrokes: str, block: bool, nonce: str
) -> tuple[list[str], bool]:
    """Prepare the send-keys arguments, appending the completion signal for a blocking send.

    Returns `(keys, is_blocking)`. A blocking send only makes sense when the keystrokes execute a command: the trailing Enter (key name or newline) is stripped, unescaped trailing semicolons are trimmed (they would make the signal splice a syntax error), and the per-send completion signal plus `Enter` are appended, so the whole line runs as `<command>; tmux wait -S <channel>` (one argument, so no fragment of it can be the lone-`;` separator). Keystrokes that do not execute anything fall back to non-blocking even when `block` was requested; the caller refuses `multiline_block` keystrokes before calling.
    """
    if not block or not _executes(keystrokes):
        return [keystrokes], False
    stripped = keystrokes
    if _is_enter_key(stripped):
        stripped = ""
    else:
        stripped = _trim_trailing_semicolons(stripped.rstrip(_NEWLINE_CHARS))
    signal = f"{stripped}; tmux wait -S {wait_channel(session, nonce)}"
    return [signal, "Enter"], True


def find_new_content(previous_buffer: str | None, current_buffer: str) -> str | None:
    """New content since `previous_buffer`, or `None` when it cannot be determined.

    The previous buffer (whitespace-stripped) is located inside the current one; everything from its final line onward is the delta. A rotated or cleared buffer loses the anchor and returns `None`, which the caller reports as the current screen rather than a wrong delta.
    """
    if previous_buffer is None:
        return None
    anchor = previous_buffer.strip()
    if anchor and anchor in current_buffer:
        idx = current_buffer.index(anchor)
        if "\n" in anchor:
            idx += anchor.rfind("\n")
        return current_buffer[idx:]
    return None


_WAIT_ECHO = re.compile(r"; tmux wait -S done-\S+")


def scrub_harness_echo(text: str) -> str:
    """Remove the blocking signal's pane echo from model-facing output.

    A blocking send appends `; tmux wait -S <channel>` to the command line, and the pane echoes it back; the model should read its own command, not the harness suffix. Casts keep the raw pane: only tool results are scrubbed.
    """
    return _WAIT_ECHO.sub("", text)


def label_output(new_content: str | None, visible_screen: str) -> str:
    """The model-facing read result: the raw delta when determinable; the screen, labeled, otherwise.

    The delta carries no header (viewer UX review, 2026-10-23); the fallback keeps its label because a re-rendered screen presented as new output would invite re-acting on old lines.
    """
    if new_content is not None and new_content.strip():
        return new_content
    return f"Current Terminal Screen:\n{visible_screen}"


def clip_output(text: str, limit: int = OUTPUT_CLIP_BYTES) -> str:
    """Clip to the last `limit` bytes, marking the cut; the full stream stays in the capture."""
    encoded = text.encode(errors="replace")
    if len(encoded) <= limit:
        return text
    clipped = encoded[-limit:].decode(errors="replace")
    return f"[output clipped to the last {limit} bytes; the full stream is in the session capture]\n{clipped}"


@dataclass
class SessionState:
    """Tool-side state for one open session."""

    previous_buffer: str | None = None
    chunks: list[tuple[float, bytes]] = field(default_factory=list[tuple[float, bytes]])
    markers: list[tuple[float, str]] = field(default_factory=list[tuple[float, str]])
    opened_wall: float = 0.0
    opened_monotonic: float = 0.0
    sends: int = 0
    token: str = field(default_factory=lambda: uuid.uuid4().hex[:8])

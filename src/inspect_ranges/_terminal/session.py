"""tmux session mechanics for the `terminal` tool: command builders, send preparation, and the delta heuristic.

Adapted from terminal-bench's `TmuxSession` (`terminal_bench/terminal/tmux_session.py`, github.com/laude-institute/terminal-bench, Apache-2.0; see `design/inspect-ranges/LICENSES.md`): the `tmux wait -S` blocking completion signal, the previous-buffer delta heuristic with its two-label output, and the pane/history/pipe-pane session setup. Changes from the original: per-session wait channels (multiple named sessions), a shell-only guard input for blocking sends, and everything expressed as pure argv builders so the tool layer owns execution.

Everything here is pure: builders return argv lists, the heuristic maps strings to strings. The tool layer (`tool.py`) runs the argv through `sandbox().exec` and owns all state.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

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

SINK_DIR = "/tmp/.ir-terminal"


def sink_path(session: str) -> str:
    """The pipe-pane sink file for a session, under the capture directory."""
    return f"{SINK_DIR}/{session}.pipe"


def wait_channel(session: str) -> str:
    """The per-session tmux wait channel the blocking completion signal uses."""
    return f"ir-done-{session}"


def valid_session_name(session: str) -> bool:
    """Whether a session name fits the grammar (lowercase, digits, `_`/`-`, max 32)."""
    return bool(SESSION_NAME.match(session))


def start_session_command(session: str) -> list[str]:
    """Argv creating the session: fixed pane size, deep history, pipe-pane into the sink."""
    return [
        "bash",
        "-c",
        (
            f"mkdir -p {SINK_DIR} && "
            f"tmux new-session -x {PANE_WIDTH} -y {PANE_HEIGHT} -d -s {session} \\; "
            f"set-option -t {session} history-limit {HISTORY_LIMIT} \\; "
            f"pipe-pane -t {session} 'cat >> {sink_path(session)}'"
        ),
    ]


def has_session_command(session: str) -> list[str]:
    """Argv testing whether the session exists (exit 0 when it does)."""
    return ["tmux", "has-session", "-t", session]


def kill_session_command(session: str) -> list[str]:
    """Argv killing the session."""
    return ["tmux", "kill-session", "-t", session]


def list_sessions_command() -> list[str]:
    """Argv listing session names, one per line."""
    return ["tmux", "list-sessions", "-F", "#{session_name}"]


def send_keys_command(session: str, keys: list[str]) -> list[str]:
    """Argv sending key arguments to the session's pane."""
    return ["tmux", "send-keys", "-t", session, *keys]


def capture_pane_command(session: str, entire: bool = False) -> list[str]:
    """Argv capturing the visible pane, or the whole scrollback with `entire`."""
    extra = ["-S", "-"] if entire else []
    return ["tmux", "capture-pane", "-p", *extra, "-t", session]


def pane_command_command(session: str) -> list[str]:
    """Argv reporting the pane's current foreground command name."""
    return ["tmux", "display-message", "-p", "-t", session, "#{pane_current_command}"]


def wait_done_command(session: str, timeout_s: float) -> list[str]:
    """Argv blocking on the session's wait channel under a hard timeout."""
    return ["timeout", f"{timeout_s}s", "tmux", "wait", wait_channel(session)]


def is_shell(pane_current_command: str) -> bool:
    """Whether the pane's foreground command is a shell (blocking sends allowed)."""
    return pane_current_command.strip() in SHELLS


def _is_enter_key(key: str) -> bool:
    return key in _ENTER_KEYS


def _executes(keystrokes: str) -> bool:
    """Whether the keystrokes end by executing a command (Enter key or trailing newline)."""
    return _is_enter_key(keystrokes) or bool(re.search(r"[\r\n]$", keystrokes))


def prepare_send(session: str, keystrokes: str, block: bool) -> tuple[list[str], bool]:
    """Prepare the send-keys arguments, appending the completion signal for a blocking send.

    Returns `(keys, is_blocking)`. A blocking send only makes sense when the keystrokes execute a command: the trailing Enter (key name or newline) is stripped and the per-session completion signal plus `Enter` are appended, so the whole line runs as `<command>; tmux wait -S <channel>`. Keystrokes that do not execute anything fall back to non-blocking even when `block` was requested.
    """
    if not block or not _executes(keystrokes):
        return [keystrokes], False
    stripped = keystrokes
    if _is_enter_key(stripped):
        stripped = ""
    else:
        stripped = stripped.rstrip(_NEWLINE_CHARS)
    keys = [stripped] if stripped else []
    keys.extend([f"; tmux wait -S {wait_channel(session)}", "Enter"])
    return keys, True


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


def label_output(new_content: str | None, visible_screen: str) -> str:
    """The model-facing read result: the delta when determinable, the screen otherwise."""
    if new_content is not None and new_content.strip():
        return f"New Terminal Output:\n{new_content}"
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

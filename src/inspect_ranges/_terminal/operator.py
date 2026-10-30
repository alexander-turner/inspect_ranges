"""The operator shell: an interactive tmux attach to one guest of a range booted with `inspect-ranges up`.

This is the debugging surface behind `inspect-ranges shell`: the operator lands in a named tmux session inside the guest, driven entirely over the existing control channel (keystrokes ride `tmux send-keys -H` through ordinary exec; the screen rides a `pipe-pane` sink polled with short reads), so no wire verb, daemon change, or guest listener is involved. The call is the opt-in, made sound by the origin rule: a project the Inspect sandbox provider booted carries a provider origin in its owner record and is refused outright, so an eval sample can never acquire an interactive operator mid-run; only `up`-origin projects attach.

Guest bytes are untrusted. Everything streamed to the operator's terminal passes `EscapeFilter`, which forwards ordinary text and display sequences (CSI, two-byte escapes, window titles) but drops OSC commands beyond titles (clipboard writes, color-palette programming) and every string-container sequence (DCS/SOS/PM/APC), because a compromised guest writing to a trusted emulator is a real injection surface. 8-bit C1 bytes are deliberately NOT filtered: under UTF-8 they are continuation bytes of ordinary text, terminals in UTF-8 mode do not interpret them as controls, and stripping them would corrupt multibyte output.

Linux guests only (the session is tmux); the chosen guest's recorded injector decides, so a Windows guest refuses by name before anything is dialed.
"""

from __future__ import annotations

import asyncio
import json
import os
import shutil
import signal
import sys
import termios
import time
import tty
import uuid
from contextlib import suppress
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Protocol

from .session import HISTORY_LIMIT, SINK_DIR, target, valid_session_name

if TYPE_CHECKING:
    from .._challenges.oracle import RangeOracle
    from .._runtime.ownership import OwnerRecord
    from .._runtime.up import BootPlan

# input keystrokes batch for this long before riding one send-keys command;
# output polls back off to this interval when a read returns nothing (a read
# that returns bytes re-polls immediately, so bursts stream at channel speed)
INPUT_FLUSH_S = 0.02
OUTPUT_POLL_S = 0.08
# one sink read returns at most this much; well under the reply bulk cap, and
# large enough that a full-screen redraw arrives in one or two polls
OUTPUT_CHUNK_BYTES = 256 * 1024
# bytes per send-keys command (each byte is one two-char hex argument; tmux
# rejects client commands over ~16 KB, so 512 bytes stays far inside it)
SEND_HEX_CHUNK_BYTES = 512
# an unterminated escape sequence longer than this is hostile or garbage, not
# a real control string; the filter drops it rather than buffering forever
MAX_PENDING_SEQUENCE = 64 * 1024

DETACH_BYTE = 0x1D  # Ctrl-], the telnet escape: detach, leave the session up

# OSC codes forwarded to the operator's terminal: window/icon titles only.
# Everything else (52 clipboard, 4/10/11/104 palette programming, 7 cwd
# reports, 8 hyperlinks, 1337/133x proprietary extensions) is dropped.
ALLOWED_OSC = frozenset({"0", "1", "2"})


class OperatorShellError(Exception):
    """A typed operator-shell refusal; the message names the cause and the remedy."""


class GuestExec(Protocol):
    """The one verb the client needs: run argv in the guest, return (rc, stdout)."""

    async def __call__(self, cmd: list[str]) -> tuple[int, bytes]: ...


# -- origin and guest resolution (pure; the CLI refuses before dialing) --------


def require_operator_origin(project: str, owner: "OwnerRecord | None") -> None:
    """Refuse any project the Inspect sandbox provider booted.

    The owner record's `origin` field is written by the provider after a successful boot; an `up`-run project never has one. This is the opt-in boundary: an operator shell must be structurally unable to enter a scored sample, so the refusal keys on recorded origin, not on anything the live range could influence.

    Raises:
        OperatorShellError: The project carries a provider origin.
    """
    if owner is not None and owner.origin is not None:
        raise OperatorShellError(
            f"project {project!r} was booted by the Inspect sandbox provider "
            f"(origin {owner.origin!r}): operator shells attach only to ranges "
            "booted with 'inspect-ranges up'; eval samples are off limits by "
            "design"
        )


def resolve_guest(boot: "BootPlan", guest: str | None) -> str:
    """The guest to attach to: the named one, else the sole attacker, else the sole guest.

    Raises:
        OperatorShellError: The named guest is not in the boot plan, or no name was given and the plan has no unambiguous default; the message lists the plan's guest names. A resolved Windows guest (recorded injector `unattend`) refuses by name: the shell is tmux, a POSIX surface.
    """
    names = [entry.name for entry in boot.guests]
    if guest is None:
        attackers = [e.name for e in boot.guests if e.kind == "attacker"]
        if len(attackers) == 1:
            guest = attackers[0]
        elif len(names) == 1:
            guest = names[0]
        else:
            raise OperatorShellError(
                "this range has no single default guest; name one of: "
                + ", ".join(sorted(names))
            )
    if guest not in names:
        raise OperatorShellError(
            f"no guest named {guest!r} in this range; the boot plan has: "
            + ", ".join(sorted(names))
        )
    entry = next(e for e in boot.guests if e.name == guest)
    if entry.injector == "unattend":
        raise OperatorShellError(
            f"guest {guest!r} is a Windows guest; the operator shell drives a "
            "tmux session and supports Linux guests only"
        )
    return guest


# -- command builders (pure; the client runs them through guest exec) ----------


def operator_sink_path(session: str, token: str) -> str:
    """The per-attach pipe-pane sink: distinct from agent terminal sinks (`<session>.pipe`) so an agent session of the same name can never collide, and unique per attach so a reattach never replays a previous attach's bytes."""
    return f"{SINK_DIR}/op-{session}-{token}.pipe"


def start_operator_session_command(
    session: str, sink: str, width: int, height: int
) -> list[str]:
    """Argv creating the operator session sized to the operator's terminal, piping into `sink`.

    The same global history-limit save/restore dance as the agent terminal's opener (`history-limit` only applies to windows created after it is set).
    """
    return [
        "sh",
        "-c",
        (
            f"mkdir -p {SINK_DIR} && : > {sink} && "
            f'prev="$(tmux show-options -gv history-limit 2>/dev/null)"; '
            f"tmux set-option -g history-limit {HISTORY_LIMIT} \\; "
            f"new-session -x {width} -y {height} -d -s {session} \\; "
            f"set-option -t {target(session)} history-limit {HISTORY_LIMIT} \\; "
            f"pipe-pane -t {target(session)} 'cat >> {sink}' && "
            f'if [ -n "$prev" ]; then tmux set-option -g history-limit "$prev"; '
            f"else tmux set-option -gu history-limit; fi"
        ),
    ]


def attach_pipe_command(session: str, sink: str) -> list[str]:
    """Argv re-pointing an existing session's pipe-pane at a fresh truncated sink (reattach path; pipe-pane with a command replaces any previous pipe)."""
    return [
        "sh",
        "-c",
        (
            f"mkdir -p {SINK_DIR} && : > {sink} && "
            f"tmux pipe-pane -t {target(session)} 'cat >> {sink}'"
        ),
    ]


def detach_pipe_command(session: str, sink: str) -> list[str]:
    """Argv closing the pipe and removing the attach's sink (a detached session must not keep writing an unbounded file in the guest)."""
    return [
        "sh",
        "-c",
        f"tmux pipe-pane -t {target(session)}; rm -f {sink}",
    ]


def resize_window_command(session: str, width: int, height: int) -> list[str]:
    """Argv sizing the session's window to the operator's terminal (no real tmux client attaches, so the window keeps whatever size it is told)."""
    return [
        "tmux",
        "resize-window",
        "-t",
        target(session),
        "-x",
        str(width),
        "-y",
        str(height),
    ]


def snapshot_command(session: str) -> list[str]:
    """Argv capturing the current visible screen with escapes (the initial paint: pipe-pane only carries output written after the attach)."""
    return ["tmux", "capture-pane", "-e", "-p", "-t", target(session)]


def send_hex_commands(session: str, data: bytes) -> list[list[str]]:
    """The argv sequence typing `data` into the pane as hex bytes.

    `-H` carries every byte uniformly (control bytes, ESC sequences from arrow keys, the lone `;` that tmux's client would otherwise read as a separator), split under tmux's client command limit.
    """
    return [
        [
            "tmux",
            "send-keys",
            "-t",
            target(session),
            "-H",
            *(f"{byte:02x}" for byte in chunk),
        ]
        for chunk in (
            data[i : i + SEND_HEX_CHUNK_BYTES]
            for i in range(0, len(data), SEND_HEX_CHUNK_BYTES)
        )
    ]


def read_sink_command(
    sink: str, offset: int, cap: int = OUTPUT_CHUNK_BYTES
) -> list[str]:
    """Argv reading the sink from `offset` (0-based), capped; the client advances its offset by the bytes returned."""
    return ["sh", "-c", f"tail -c +{offset + 1} -- {sink} | head -c {cap}"]


# -- the guest-bytes filter -----------------------------------------------------


class EscapeFilter:
    """Streaming filter between guest output and the operator's terminal.

    Forwards text, CSI sequences (display control, and the query/report pairs full-screen programs need), and two-byte/intermediate escapes; forwards OSC only for the title codes in `ALLOWED_OSC`; drops DCS, SOS, PM, and APC string containers whole. Stateful because sequences split across poll reads; an unterminated sequence past `MAX_PENDING_SEQUENCE` is discarded as hostile.
    """

    _GROUND, _ESC, _CSI, _OSC, _DROP_STRING, _INTERMEDIATE = range(6)

    def __init__(self) -> None:
        self._state = self._GROUND
        self._pending = bytearray()
        self._drop_prev_esc = False

    def feed(self, data: bytes) -> bytes:
        out = bytearray()
        for byte in data:
            if self._state == self._GROUND:
                if byte == 0x1B:
                    self._state = self._ESC
                    self._pending = bytearray([byte])
                else:
                    out.append(byte)
            elif self._state == self._ESC:
                self._pending.append(byte)
                if byte == ord("["):
                    self._state = self._CSI
                elif byte == ord("]"):
                    self._state = self._OSC
                elif byte in b"PX^_":  # DCS, SOS, PM, APC
                    self._state = self._DROP_STRING
                    self._pending.clear()
                elif 0x20 <= byte <= 0x2F:
                    self._state = self._INTERMEDIATE
                else:
                    # a complete two-byte escape (RIS, DECSC, keypad modes, ...)
                    out.extend(self._pending)
                    self._reset()
            elif self._state == self._INTERMEDIATE:
                self._pending.append(byte)
                if not 0x20 <= byte <= 0x2F:
                    out.extend(self._pending)
                    self._reset()
            elif self._state == self._CSI:
                self._pending.append(byte)
                if 0x40 <= byte <= 0x7E:
                    out.extend(self._pending)
                    self._reset()
                elif len(self._pending) > MAX_PENDING_SEQUENCE:
                    self._reset()
            elif self._state == self._OSC:
                # terminated by BEL, or by ST (ESC \); the ESC is held back so
                # a non-ST successor is not lost
                if byte == 0x07:
                    self._pending.append(byte)
                    out.extend(self._filtered_osc())
                    self._reset()
                elif self._drop_prev_esc:
                    self._drop_prev_esc = False
                    if byte == ord("\\"):
                        self._pending.extend(b"\x1b\\")
                        out.extend(self._filtered_osc())
                        self._reset()
                    else:
                        self._pending.extend((0x1B, byte))
                elif byte == 0x1B:
                    self._drop_prev_esc = True
                else:
                    self._pending.append(byte)
                if len(self._pending) > MAX_PENDING_SEQUENCE:
                    # hostile buffering: drop what accumulated and keep
                    # dropping until the string terminator, so no fragment of
                    # the string ever reaches the terminal as text
                    self._reset()
                    self._state = self._DROP_STRING
            elif self._state == self._DROP_STRING:
                if self._drop_prev_esc:
                    self._drop_prev_esc = False
                    if byte == ord("\\"):
                        self._reset()
                elif byte == 0x1B:
                    self._drop_prev_esc = True
                elif byte == 0x07:
                    # xterm accepts BEL as a string terminator too
                    self._reset()
        return bytes(out)

    def _filtered_osc(self) -> bytes:
        body = bytes(self._pending[2:])  # past ESC ]
        code = body.split(b";", 1)[0].rstrip(b"\x07\x1b\\")
        if code.decode("ascii", errors="replace") in ALLOWED_OSC:
            return bytes(self._pending)
        return b""

    def _reset(self) -> None:
        self._state = self._GROUND
        self._pending = bytearray()
        self._drop_prev_esc = False


# -- the interactive client -----------------------------------------------------


@dataclass
class _CastRecorder:
    """Filtered output chunks with wall-clock offsets, written as asciicast v2 on detach."""

    width: int
    height: int
    started: float = field(default_factory=time.monotonic)
    events: list[tuple[float, bytes]] = field(default_factory=list[tuple[float, bytes]])

    def record(self, data: bytes) -> None:
        self.events.append((time.monotonic() - self.started, data))

    def write(self, path: Path, title: str) -> None:
        header = {
            "version": 2,
            "width": self.width,
            "height": self.height,
            "timestamp": int(time.time()),
            "title": title,
        }
        lines = [json.dumps(header)]
        lines.extend(
            json.dumps([round(ts, 6), "o", data.decode("utf-8", errors="replace")])
            for ts, data in self.events
        )
        path.write_text("\n".join(lines) + "\n")


def _oracle_exec(oracle: "RangeOracle", guest: str, user: str | None) -> GuestExec:
    """Bind the oracle's raw-channel exec to one guest and identity."""

    async def run(cmd: list[str]) -> tuple[int, bytes]:
        outcome = await oracle.exec(guest, cmd, user=user, timeout_s=30.0)
        return outcome.rc, outcome.stdout

    return run


async def _checked(run: GuestExec, cmd: list[str], what: str) -> bytes:
    rc, stdout = await run(cmd)
    if rc != 0:
        raise OperatorShellError(f"{what} failed in the guest (rc {rc})")
    return stdout


async def ensure_session(
    run: GuestExec, session: str, sink: str, width: int, height: int
) -> bool:
    """Create the session (sized, piped) or re-point an existing one at a fresh sink; returns whether the session already existed.

    Raises:
        OperatorShellError: tmux is missing in the guest, or the session could not be created; the message names the remedy.
    """
    rc, _ = await run(["tmux", "-V"])
    if rc != 0:
        raise OperatorShellError(
            "tmux is not available in the guest; install it in the image (the "
            "standard attack image carries it) or choose another guest"
        )
    rc, _ = await run(["tmux", "has-session", "-t", target(session)])
    if rc == 0:
        await _checked(run, attach_pipe_command(session, sink), "pipe-pane attach")
        await _checked(
            run, resize_window_command(session, width, height), "window resize"
        )
        return True
    await _checked(
        run,
        start_operator_session_command(session, sink, width, height),
        "session create",
    )
    return False


async def run_shell(
    oracle: "RangeOracle",
    guest: str,
    *,
    session: str = "operator",
    user: str | None = None,
    cast_path: Path | None = None,
    stdin_fd: int | None = None,
) -> None:
    """The interactive loop: raw local tty, keystrokes to the pane, filtered pane bytes back.

    Detach with Ctrl-]; the session stays up for reattach. The guest-side pipe is closed and the attach's sink removed on the way out, whatever ended the loop.

    Raises:
        OperatorShellError: Not running on a terminal, a bad session name, or a guest-side setup failure.
    """
    if not valid_session_name(session):
        raise OperatorShellError(
            f"bad session name {session!r}: lowercase letters, digits, `_`/`-`, "
            "max 32 characters"
        )
    fd = stdin_fd if stdin_fd is not None else sys.stdin.fileno()
    if not os.isatty(fd) or not sys.stdout.isatty():
        raise OperatorShellError(
            "the operator shell is interactive and needs a terminal on both "
            "stdin and stdout"
        )
    size = shutil.get_terminal_size()
    run = _oracle_exec(oracle, guest, user)
    token = uuid.uuid4().hex[:8]
    sink = operator_sink_path(session, token)
    existed = await ensure_session(run, session, sink, size.columns, size.lines)

    cast = (
        _CastRecorder(width=size.columns, height=size.lines)
        if cast_path is not None
        else None
    )
    filter_ = EscapeFilter()
    out = sys.stdout.buffer

    def emit(data: bytes) -> None:
        passed = filter_.feed(data)
        if passed:
            out.write(passed)
            out.flush()
            if cast is not None:
                cast.record(passed)

    loop = asyncio.get_running_loop()
    pending_input = bytearray()
    detach = asyncio.Event()
    resized = asyncio.Event()

    def on_stdin() -> None:
        data = os.read(fd, 4096)
        if not data:
            detach.set()
            return
        if DETACH_BYTE in data:
            pending_input.extend(data[: data.index(DETACH_BYTE)])
            detach.set()
            return
        pending_input.extend(data)

    attrs = termios.tcgetattr(fd)
    tty.setraw(fd, termios.TCSADRAIN)
    loop.add_reader(fd, on_stdin)
    try:
        loop.add_signal_handler(signal.SIGWINCH, resized.set)
    except (NotImplementedError, RuntimeError):  # pragma: no cover - platform
        pass

    sys.stdout.write(
        f"[{'reattached to' if existed else 'opened'} tmux session "
        f"{session!r} on {guest!r}; Ctrl-] detaches]\r\n"
    )
    sys.stdout.flush()

    async def pump_input() -> None:
        while not detach.is_set():
            await asyncio.sleep(INPUT_FLUSH_S)
            if resized.is_set():
                resized.clear()
                current = shutil.get_terminal_size()
                await run(
                    resize_window_command(session, current.columns, current.lines)
                )
            if pending_input:
                data = bytes(pending_input)
                pending_input.clear()
                for cmd in send_hex_commands(session, data):
                    await run(cmd)

    async def pump_output() -> None:
        offset = 0
        while not detach.is_set():
            rc, data = await run(read_sink_command(sink, offset))
            if rc != 0:
                raise OperatorShellError(
                    "reading the session sink failed; the range may be down"
                )
            if data:
                offset += len(data)
                emit(data)
            else:
                await asyncio.sleep(OUTPUT_POLL_S)

    try:
        # the initial paint: pipe-pane only carries post-attach output
        emit(await _checked(run, snapshot_command(session), "screen snapshot"))
        pumps = asyncio.gather(pump_input(), pump_output())
        waiter = asyncio.ensure_future(detach.wait())
        done, _ = await asyncio.wait(
            {pumps, waiter}, return_when=asyncio.FIRST_COMPLETED
        )
        waiter.cancel()
        pumps.cancel()
        for task in done:
            if task is pumps and not task.cancelled():
                task.result()  # surface a pump failure as the exit error
        # retrieve the cancellations so nothing logs "exception was never
        # retrieved" after a clean detach
        for task in (pumps, waiter):
            with suppress(asyncio.CancelledError):
                await task
    finally:
        loop.remove_reader(fd)
        try:
            loop.remove_signal_handler(signal.SIGWINCH)
        except (NotImplementedError, RuntimeError, ValueError):  # pragma: no cover
            pass
        termios.tcsetattr(fd, termios.TCSADRAIN, attrs)
        try:
            await run(detach_pipe_command(session, sink))
        except Exception:  # noqa: BLE001 - best-effort guest-side cleanup
            pass
        if cast is not None and cast_path is not None:
            cast.write(cast_path, title=f"{session} on {guest}")
        sys.stdout.write(
            f"\r\n[detached; the session is still running - reattach with the "
            f"same command, or end it from a shell with: tmux kill-session "
            f"-t ={session}]\r\n"
        )
        sys.stdout.flush()

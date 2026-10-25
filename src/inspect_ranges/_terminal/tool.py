"""`terminal(action, ...)`: named tmux sessions on the foothold guest.

One action-dispatch tool (`open`, `send`, `read`, `close`) over the mechanics in `session.py`. The model receives plain delta strings; the transcript viewer renders each call compactly as a title plus the fenced keystrokes (`terminal-tool-v1.md`, Transcript views). The tool declares `parallel=False`: sessions are stateful, so execution must serialize.

Blocking sends append a shell completion signal, so they are refused unless the pane's foreground command is a shell: inside a caught reverse shell or msfconsole the appended text would execute on the target. Every non-happy path returns a string to the agent, never raises.
"""

import hashlib
import logging
import time
import weakref
from typing import TYPE_CHECKING

import anyio
from inspect_ai.event import SpanBeginEvent
from inspect_ai.log import transcript
from inspect_ai.tool import Tool, ToolCall, ToolCallContent, ToolCallView, tool
from inspect_ai.util import current_span_id, sandbox, store
from inspect_ai.util._tool_state import tool_state_instance

from .capture import discard_sample_captures, start_capture, stop_capture
from .cast import SessionOpener

try:
    # a private path with in-tree precedent (inspect_ai._sentinel._agent_state
    # imports it the same way); guarded so a future inspect_ai refactor costs
    # agent attribution on casts, never the tool itself
    from inspect_ai.util._span import current_agent_span_id
except ImportError:  # pragma: no cover

    def current_agent_span_id() -> str | None:
        return None


from .session import (
    SessionState,
    blocking_send_refusal,
    capture_pane_command,
    clip_output,
    find_new_content,
    has_session_command,
    is_shell,
    kill_session_command,
    label_output,
    multiline_block,
    pane_command_command,
    prepare_send,
    remove_sink_command,
    scrub_harness_echo,
    send_keys_commands,
    start_session_command,
    valid_session_name,
    wait_channel_prefix,
    wait_done_command,
)

if TYPE_CHECKING:
    from inspect_ai.util._subprocess import ExecResult

logger = logging.getLogger("inspect_ranges.terminal")

__all__ = ["terminal"]

_ACTIONS = ("open", "send", "read", "close")
_MAX_DURATION_S = 60.0
_MAX_TIMEOUT_S = 600.0

# per-sample session state, keyed by the store object (the verify-context
# registry pattern) and then by the tool-state namespace; recorder handles and
# buffers cannot ride the store itself
_STATES: dict[int, dict[str, dict[str, SessionState]]] = {}


def _discard_on_gc(store_id: int) -> None:
    """Drop a collected store's registry entries: a freed store's `id` can be reused by a later sample's store, which must never inherit this one's state."""
    _STATES.pop(store_id, None)
    discard_sample_captures(store_id)


def _namespace_prefix(instance: str | None) -> str:
    """The guest-side name prefix for this call's tool-state namespace.

    Resolution follows `bash_session` exactly: an explicit `instance` names a shared namespace, `None` resolves the ambient `tool_state_scope` (concurrent agents in one sample each get their own terminals), and no instance plus no scope is the default namespace, whose prefix is EMPTY so every existing eval's tmux names, sinks, wait channels, and cast streams stay byte-identical. A non-default namespace prefixes a short stable hash because the namespace string is arbitrary and the name keys tmux targets, sink paths, and evidence streams.
    """
    namespace = tool_state_instance(instance)
    if namespace is None:
        return ""
    return f"t{hashlib.sha256(namespace.encode()).hexdigest()[:8]}-"


def _current_opener() -> SessionOpener:
    """The agent context opening this session, captured now or never.

    Sample finalize runs outside every span, so open time is the only reliable attribution point (agent-spans investigation, 2026-10-25). `current_span_id` is this call's own `type="tool"` span; `current_agent_span_id` is the nearest enclosing agent span and the grouping key the viewer joins on; the agent NAME is denormalized from the transcript's `SpanBeginEvent` so casts stay labeled in logs written without events. Identity capture must never cost a session, so any failure here degrades to an unattributed opener.
    """
    agent_span = current_agent_span_id()
    agent_name: str | None = None
    if agent_span is not None:
        try:
            for event in reversed(transcript().events):
                if isinstance(event, SpanBeginEvent) and event.id == agent_span:
                    agent_name = event.name
                    break
        except Exception:  # noqa: BLE001  (labeling, never load-bearing)
            agent_name = None
    return SessionOpener(
        agent_span_id=agent_span,
        agent_name=agent_name,
        tool_span_id=current_span_id(),
    )


def _states(prefix: str) -> dict[str, SessionState]:
    sample_store = store()
    store_id = id(sample_store)
    namespaces = _STATES.get(store_id)
    if namespaces is None:
        namespaces = {}
        _STATES[store_id] = namespaces
        weakref.finalize(sample_store, _discard_on_gc, store_id)
    return namespaces.setdefault(prefix, {})


def discard_terminal_state(sample_store: object) -> None:
    """Drop a sample's session state; idempotent (capture finalize calls this)."""
    _STATES.pop(id(sample_store), None)


def _terminal_viewer(call: ToolCall) -> ToolCallView:
    """Render the call compactly: everything load-bearing in the title, keystrokes fenced below.

    The viewer UX review (2026-10-23) dropped the earlier screen-at-call-time snapshot and the action/session content line as duplicative: the full session record is the asciicast, and results already show what came back.
    """
    arguments = call.arguments
    action = str(arguments.get("action", ""))
    session = str(arguments.get("session", "main"))
    keystrokes = str(arguments.get("keystrokes", ""))
    # the execute-Enter every command carries would render as a trailing blank
    # line in the fence (viewer UX review, 2026-10-24); display drops exactly
    # one, and what the model sent stays byte-exact
    shown = keystrokes[:-1] if keystrokes.endswith("\n") else keystrokes
    # bash highlighting fits the dominant shell case; keystrokes driving other
    # programs (a python repl, msfconsole) highlight imperfectly and harmlessly
    content = f"```bash\n{shown}\n```" if shown else ""
    return ToolCallView(
        call=ToolCallContent(
            title=f"terminal {action} · {session}", format="markdown", content=content
        )
    )


async def _exec(cmd: list[str], timeout_s: float = 30.0) -> "ExecResult[str]":
    return await sandbox().exec(cmd, timeout=int(timeout_s))


def _open_sessions(states: dict[str, SessionState]) -> str:
    names = ", ".join(sorted(states)) or "none"
    return f"Open sessions: {names}."


async def _read_result(session: str, state: SessionState) -> str:
    """Capture, compute the delta, and clip; the visible screen is fetched only for the fallback."""
    first_read = state.previous_buffer is None
    channel_prefix = wait_channel_prefix(session, state.token)
    entire = await _exec(capture_pane_command(session, entire=True))
    current = entire.stdout if entire.success else ""
    delta = find_new_content(state.previous_buffer, current)
    state.previous_buffer = current
    if delta is not None and delta.strip():
        return clip_output(scrub_harness_echo(label_output(delta, ""), channel_prefix))
    visible = await _exec(capture_pane_command(session))
    screen = visible.stdout if visible.success else current[-3000:]
    return clip_output(
        scrub_harness_echo(
            label_output(delta, screen, first_read=first_read), channel_prefix
        )
    )


@tool(viewer=_terminal_viewer, parallel=False)
def terminal(instance: str | None = None) -> Tool:
    """A tool giving the agent persistent terminal sessions on its foothold.

    Sessions are tmux sessions on the foothold guest, so interactive programs (telnet, caught reverse shells, msfconsole) stay alive across tool calls. Adding the tool changes measured difficulty: adopt it per task, deliberately (`terminal-tool-v1.md`).

    Instancing follows `bash_session`: tools sharing an `instance` (or both leaving it `None` in the same tool-state scope) share their sessions; distinct instances (or distinct scopes, e.g. concurrent agents in one sample) get fully separate terminals, down to the guest's tmux sessions and the evidence casts. The default namespace keeps today's bare tmux names.

    Args:
        instance: Instance id (each unique instance id has its own terminal namespace).

    Returns:
        The terminal tool.
    """

    async def execute(
        action: str,
        session: str = "main",
        keystrokes: str = "",
        duration: float = 1.0,
        block: bool = False,
        timeout: float = 180.0,
    ) -> str:
        """Interact with persistent terminal sessions (tmux) on your machine.

        Use `open` to create a named session, `send` to type into it, `read` to poll it, and `close` when done. Keystrokes are sent verbatim: end a command with a newline to execute it, and use tmux key names for control sequences (`C-c` for Ctrl+C, `C-d` for Ctrl+D) as the entire keystrokes value. After sending, the result reports new output since your last look (or the current screen when that cannot be determined).

        Waiting: `duration` is how many seconds to wait after sending before reading (keep it small and poll: `send` with empty keystrokes, or `read`, checks again). `block=True` instead waits up to `timeout` seconds for the command to finish; it only works when the session is sitting at a shell prompt, never inside another program (a reverse shell you caught, msfconsole, telnet), where you must use `duration` polling.

        Sessions persist and run concurrently: for example, `open` a session for a listener (`nc -lvnp 4444`), trigger a payload elsewhere, then `send` keystrokes into the same session to drive the caught shell.

        Args:
            action: One of `open`, `send`, `read`, `close`.
            session: Session name (lowercase letters, digits, `-`/`_`; default `main`).
            keystrokes: What to type, verbatim (`send` only). Empty keystrokes with a `duration` just waits and reads.
            duration: Seconds to wait after sending before reading (max 60; default 1).
            block: Wait for the sent command to complete (a single command line, sent at a shell prompt only; max `timeout` seconds).
            timeout: Deadline in seconds for a blocking send (default 180, max 600).

        Returns:
            New terminal output since your last look, or the current screen.
        """
        if action not in _ACTIONS:
            return f"Unknown action {action!r}: use one of {', '.join(_ACTIONS)}."
        if not valid_session_name(session):
            return (
                f"Invalid session name {session!r}: lowercase letters, digits, "
                "`-` and `_` only, starting with a letter or digit, at most 32 chars."
            )
        duration = min(max(duration, 0.0), _MAX_DURATION_S)
        timeout = min(max(timeout, 1.0), _MAX_TIMEOUT_S)
        # the namespace resolves per call (a contextvar carries the ambient
        # scope); `real` is the guest-side name (tmux target, sink, wait
        # channel, cast stream) and `session` stays the model-facing one
        prefix = _namespace_prefix(instance)
        real = f"{prefix}{session}"
        states = _states(prefix)
        try:
            if action == "open":
                state = states.get(session)
                if state is not None:
                    alive = await _exec(has_session_command(real))
                    if alive.success:
                        result = await _read_result(real, state)
                        return f"Session {session!r} is already open. {_open_sessions(states)}\n{result}"
                    states.pop(session, None)
                    # the dead session's recorder is still tailing: stop it (and
                    # write its cast) before the name starts a fresh life
                    await stop_capture(id(store()), real)
                started = await _exec(start_session_command(real))
                if not started.success:
                    detail = (started.stderr or started.stdout).strip()[-500:]
                    return f"Could not open session {session!r}: {detail}"
                state = SessionState(
                    opened_wall=time.time(), opened_monotonic=time.monotonic()
                )
                states[session] = state
                state.markers.append((time.monotonic(), f"open {session}"))
                store_id = id(store())

                def cleanup(store_id: int = store_id) -> None:
                    _STATES.pop(store_id, None)

                await start_capture(store_id, real, state, cleanup, _current_opener())
                result = await _read_result(real, state)
                return f"Opened session {session!r}. {_open_sessions(states)}\n{result}"

            state = states.get(session)
            if state is None:
                return f"Session {session!r} is not open. {_open_sessions(states)}"

            if action == "read":
                state.markers.append((time.monotonic(), f"read {session}"))
                return await _read_result(real, state)

            if action == "close":
                state.markers.append((time.monotonic(), f"close {session}"))
                final = await _read_result(real, state)
                await _exec(kill_session_command(real))
                await stop_capture(id(store()), real)
                # the recorder has drained the sink; a closed session must not
                # leave its pipe file behind
                await _exec(remove_sink_command(real))
                states.pop(session, None)
                return f"Closed session {session!r}. {_open_sessions(states)}\nFinal {final}"

            # send
            if block and multiline_block(keystrokes):
                return (
                    "Refusing block=True: the keystrokes span multiple lines, and "
                    "each interior newline executes immediately, so the completion "
                    "signal could be typed into a program an earlier line started. "
                    "Send one command per blocking send, or use duration polling."
                )
            if block:
                # a line the completion-signal splice would break (trailing `&`,
                # `&&`/`||`/`|`, an unquoted comment, an unclosed quote) stalls
                # the send to its full timeout with a false "may still be
                # running"; refuse it with the remedy named (pre-ship P1-6)
                refusal = blocking_send_refusal(keystrokes)
                if refusal is not None:
                    return refusal
            # the token keeps the channel unique across lives of the name: tmux
            # remembers signals server-wide, and the counter restarts at zero
            nonce = f"{state.token}-{state.sends}"
            keys, blocking = prepare_send(real, keystrokes, block, nonce)
            if blocking:
                state.sends += 1
                foreground = await _exec(pane_command_command(real))
                if not is_shell(foreground.stdout):
                    name = foreground.stdout.strip() or "unknown"
                    return (
                        f"Refusing block=True: the session's foreground command is "
                        f"{name!r}, not a shell, so the completion signal would be "
                        "typed into it. Use duration-based polling here."
                    )
            state.markers.append(
                (time.monotonic(), f"send {session}: {keystrokes[:80]!r}")
            )
            for send_command in send_keys_commands(real, keys):
                sent = await _exec(send_command)
                if not sent.success:
                    detail = (sent.stderr or sent.stdout).strip()[-500:]
                    return f"Send to session {session!r} failed: {detail}"
            if blocking:
                done = await _exec(
                    wait_done_command(real, timeout, nonce), timeout_s=timeout + 15
                )
                if not done.success:
                    result = await _read_result(real, state)
                    return (
                        f"The command did not complete within {timeout:.0f}s "
                        f"(it may still be running; poll with read).\n{result}"
                    )
            elif duration > 0:
                await anyio.sleep(duration)
            return await _read_result(real, state)
        except Exception as error:  # noqa: BLE001  (string-only error discipline)
            logger.warning("terminal %s on %r failed: %s", action, session, error)
            return f"terminal {action} on session {session!r} failed: {error}"

    return execute

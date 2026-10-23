"""Tests for the terminal tool against real host tmux.

The tool's only sandbox dependency is `sandbox().exec(argv)`, so these tests substitute a sandbox stub that runs the argv on the host: real tmux, real timing, no VMs (the provider's own exec path is pinned by test_provider_self_check). Each test uses a unique session name and kills it afterward, so parallel test runs cannot collide on the shared host tmux server.
"""

import asyncio
import shutil
import subprocess
import uuid
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import inspect_ranges._terminal.tool as terminal_tool
import pytest
from inspect_ai.tool import ToolCall
from inspect_ai.util import ExecResult
from inspect_ai.util._store import Store, init_subtask_store
from inspect_ranges import terminal
from inspect_ranges._terminal.session import sink_path
from inspect_ranges._terminal.tool import (
    TERMINAL_SCREEN_STORE_KEY,
    _terminal_viewer,  # pyright: ignore[reportPrivateUsage]
    discard_terminal_state,
)

pytestmark = pytest.mark.skipif(
    shutil.which("tmux") is None, reason="host tmux required"
)


class HostSandbox:
    """A sandbox stub executing argv on the host, mirroring `SandboxEnvironment.exec`."""

    async def exec(self, cmd: list[str], timeout: int | None = None) -> ExecResult[str]:
        proc = await asyncio.create_subprocess_exec(
            *cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        out, err = await asyncio.wait_for(proc.communicate(), timeout)
        return ExecResult(
            success=proc.returncode == 0,
            returncode=proc.returncode or 0,
            stdout=out.decode(errors="replace"),
            stderr=err.decode(errors="replace"),
        )


@pytest.fixture()
def armed(monkeypatch: pytest.MonkeyPatch) -> Iterator[tuple[Any, Store, str]]:
    """The tool with a host sandbox and a fresh store, plus a unique session name."""
    monkeypatch.setattr(terminal_tool, "sandbox", lambda: HostSandbox())
    store = Store()
    init_subtask_store(store)
    session = f"t-{uuid.uuid4().hex[:8]}"
    try:
        yield terminal(), store, session
    finally:
        discard_terminal_state(store)
        subprocess.run(
            ["tmux", "kill-session", "-t", session],
            capture_output=True,
            check=False,
        )
        # host hygiene even when a test fails before its close
        Path(sink_path(session)).unlink(missing_ok=True)


def test_open_send_read_close_flow(armed: tuple[Any, Store, str]) -> None:
    tool, store, session = armed

    async def scenario() -> None:
        opened = await tool(action="open", session=session)
        assert f"Opened session '{session}'" in opened
        result = await tool(
            action="send", session=session, keystrokes="echo marker-$((40+2))\n"
        )
        assert "marker-42" in result
        # the store carries the after-screen the next call's view renders
        screens = store.get(TERMINAL_SCREEN_STORE_KEY, dict[str, str]())
        assert "marker-42" in screens[session]
        closed = await tool(action="close", session=session)
        assert f"Closed session '{session}'" in closed
        remaining = store.get(TERMINAL_SCREEN_STORE_KEY, dict[str, str]())
        assert remaining.get(session) is None

    asyncio.run(scenario())


def test_blocking_send_waits_for_completion(armed: tuple[Any, Store, str]) -> None:
    tool, _, session = armed

    async def scenario() -> None:
        await tool(action="open", session=session)
        result = await tool(
            action="send",
            session=session,
            # the marker is computed so it can only come from the command's
            # output, never from the keystrokes echoed in the pane
            keystrokes="sleep 1 && echo done-$((40+2))\n",
            block=True,
            timeout=30,
        )
        assert "done-42" in result
        await tool(action="close", session=session)

    asyncio.run(scenario())


def test_blocking_send_tolerates_trailing_semicolon(
    armed: tuple[Any, Store, str],
) -> None:
    """A blocking command line ending in `;` must run and complete: splicing the signal after it would make `cmd;;`, a shell syntax error that runs nothing and stalls the send to its full timeout."""
    tool, _, session = armed

    async def scenario() -> None:
        await tool(action="open", session=session)
        result = await tool(
            action="send",
            session=session,
            # computed marker, so the echoed keystrokes cannot satisfy the assert
            keystrokes="echo semi-$((40+2));\n",
            block=True,
            timeout=5,
        )
        assert "semi-42" in result
        assert "did not complete" not in result
        await tool(action="close", session=session)

    asyncio.run(scenario())


def test_block_refused_off_shell(armed: tuple[Any, Store, str]) -> None:
    tool, _, session = armed

    async def scenario() -> None:
        await tool(action="open", session=session)
        await tool(
            action="send", session=session, keystrokes="python3 -i\n", duration=2
        )
        refused = await tool(
            action="send", session=session, keystrokes="1+1\n", block=True
        )
        assert "Refusing block=True" in refused and "python3" in refused
        # duration polling still drives the non-shell program
        result = await tool(
            action="send", session=session, keystrokes="40+2\n", duration=1
        )
        assert "42" in result
        await tool(action="close", session=session)

    asyncio.run(scenario())


def test_close_removes_the_sink_file(armed: tuple[Any, Store, str]) -> None:
    """A closed session must not leave its pipe-pane sink behind: on a long-lived guest (or the test host) leaked sinks accumulate one per session name."""
    tool, _, session = armed

    async def scenario() -> None:
        await tool(action="open", session=session)
        assert Path(sink_path(session)).exists()
        await tool(action="close", session=session)
        assert not Path(sink_path(session)).exists()

    asyncio.run(scenario())


def test_errors_are_strings(armed: tuple[Any, Store, str]) -> None:
    tool, _, session = armed

    async def scenario() -> None:
        assert "Unknown action" in await tool(action="poke", session=session)
        assert "Invalid session name" in await tool(action="open", session="Bad Name")
        assert "is not open" in await tool(
            action="send", session=session, keystrokes="x"
        )

    asyncio.run(scenario())


def test_open_applies_history_limit(armed: tuple[Any, Store, str]) -> None:
    """The pane's history must be deep at creation: tmux applies `history-limit` only to windows created after it is set, so a post-creation set leaves the default 2000."""
    tool, _, session = armed

    async def scenario() -> None:
        await tool(action="open", session=session)
        shown = subprocess.run(
            ["tmux", "display-message", "-p", "-t", f"={session}:", "#{history_limit}"],
            capture_output=True,
            text=True,
            check=True,
        )
        assert shown.stdout.strip() == "50000"
        await tool(action="close", session=session)

    asyncio.run(scenario())


def test_oversized_send_chunks_through(armed: tuple[Any, Store, str]) -> None:
    """A send larger than tmux's ~16 KB client command limit must type through in chunks rather than fail with "command too long" (payload delivery through a session is a core workflow)."""
    tool, _, session = armed
    filler = "y" * 20_000

    async def scenario() -> None:
        await tool(action="open", session=session)
        result = await tool(
            action="send",
            session=session,
            # computed marker after the filler: only the executed command's
            # output can satisfy the assert
            keystrokes=f"echo {filler} big-$((40+2))\n",
            block=True,
            # typing 20KB through chunked send-keys plus executing it exceeds
            # 30s on slow 2-core CI runners (observed: filler fully typed,
            # prompt back, wait expired); the contract under test is chunking
            # correctness, not speed
            timeout=120,
        )
        assert "command too long" not in result
        assert "big-42" in result
        await tool(action="close", session=session)

    asyncio.run(scenario())


def test_dash_keystrokes_are_typed_not_parsed(armed: tuple[Any, Store, str]) -> None:
    """Keystrokes starting with `-` must reach the pane instead of being read as send-keys flags."""
    tool, _, session = armed

    async def scenario() -> None:
        await tool(action="open", session=session)
        result = await tool(action="send", session=session, keystrokes="-dash-probe\n")
        assert "failed" not in result and "-dash-probe" in result
        await tool(action="close", session=session)

    asyncio.run(scenario())


def test_block_refused_for_multiline_keystrokes(armed: tuple[Any, Store, str]) -> None:
    """An interior newline could start a program that would receive the completion signal, so block refuses multi-line keystrokes outright."""
    tool, _, session = armed

    async def scenario() -> None:
        await tool(action="open", session=session)
        refused = await tool(
            action="send", session=session, keystrokes="cat\nhello\n", block=True
        )
        assert "Refusing block=True" in refused
        # nothing was sent: the pane still shows no cat invocation
        screen = await tool(action="read", session=session)
        assert "hello" not in screen
        await tool(action="close", session=session)

    asyncio.run(scenario())


def test_timed_out_block_does_not_poison_next_block(
    armed: tuple[Any, Store, str],
) -> None:
    """A timed-out blocking send's late signal must not release the next blocking send early: whether the dead waiter consumes the late signal or the server remembers it is a tmux version detail, so each send waits on its own channel."""
    tool, _, session = armed

    async def scenario() -> None:
        await tool(action="open", session=session)
        timed_out = await tool(
            action="send",
            session=session,
            keystrokes="sleep 3 && echo first-done\n",
            block=True,
            timeout=1,
        )
        assert "did not complete" in timed_out
        await asyncio.sleep(3)  # the first command completes and fires its signal
        # the marker is computed so only the command's real output (after its
        # sleep) can satisfy the assert, never the keystrokes echoed in the pane
        second = await tool(
            action="send",
            session=session,
            keystrokes="sleep 2 && echo second-$((40+2))\n",
            block=True,
            timeout=30,
        )
        assert "second-42" in second
        await tool(action="close", session=session)

    asyncio.run(scenario())


def test_reopened_session_ignores_previous_life_signal(
    armed: tuple[Any, Store, str],
) -> None:
    """Blocking sends must keep working across a close and reopen of the same name: wait channels are server-wide and outlive sessions (other sessions keep the server alive), and the send counter restarts at zero, so the reopened life must not collide with the closed life's channels, remembered signals, or dead waiter entries."""
    tool, _, session = armed
    keeper = f"{session}-k"  # keeps the server (and its remembered signals) alive

    async def scenario() -> None:
        await tool(action="open", session=keeper)
        try:
            await tool(action="open", session=session)
            timed_out = await tool(
                action="send",
                session=session,
                keystrokes="sleep 2 && echo life1-done\n",
                block=True,
                timeout=1,
            )
            assert "did not complete" in timed_out
            await asyncio.sleep(2.5)  # life 1 completes and fires its signal
            await tool(action="close", session=session)
            await tool(action="open", session=session)
            second = await tool(
                action="send",
                session=session,
                # computed marker, so the echoed keystrokes cannot satisfy the assert
                keystrokes="sleep 1 && echo life2-$((40+2))\n",
                block=True,
                timeout=30,
            )
            assert "life2-42" in second
            await tool(action="close", session=session)
        finally:
            await tool(action="close", session=keeper)

    try:
        asyncio.run(scenario())
    finally:
        subprocess.run(
            ["tmux", "kill-session", "-t", f"={keeper}:"],
            capture_output=True,
            check=False,
        )
        Path(sink_path(keeper)).unlink(missing_ok=True)


def test_reopen_of_dead_session_stops_stale_capture(
    armed: tuple[Any, Store, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    """When a session died outside the tool, reopening the name must stop the old recorder before starting a fresh one."""
    tool, _, session = armed
    calls: list[tuple[str, str]] = []

    async def fake_start(
        store_id: int, name: str, state: Any, on_finalize: Any
    ) -> None:
        calls.append(("start", name))

    async def fake_stop(store_id: int, name: str) -> None:
        calls.append(("stop", name))

    monkeypatch.setattr(terminal_tool, "start_capture", fake_start)
    monkeypatch.setattr(terminal_tool, "stop_capture", fake_stop)

    async def scenario() -> None:
        await tool(action="open", session=session)
        subprocess.run(
            ["tmux", "kill-session", "-t", f"={session}:"],
            capture_output=True,
            check=True,
        )
        await tool(action="open", session=session)
        assert calls == [("start", session), ("stop", session), ("start", session)]
        await tool(action="close", session=session)

    asyncio.run(scenario())


def test_state_dropped_when_store_is_collected() -> None:
    """A collected store's id can be reused by a later sample's store, which must never inherit this one's sessions."""
    import gc

    from inspect_ranges._terminal.session import SessionState
    from inspect_ranges._terminal.tool import (
        _STATES,  # pyright: ignore[reportPrivateUsage]
        _states,  # pyright: ignore[reportPrivateUsage]
    )

    sample_store = Store()
    init_subtask_store(sample_store)
    _states()["main"] = SessionState()
    key = id(sample_store)
    assert key in _STATES
    init_subtask_store(Store())  # release the context's reference
    del sample_store
    gc.collect()
    assert key not in _STATES


def test_viewer_renders_stored_screen(armed: tuple[Any, Store, str]) -> None:
    tool, _, session = armed

    async def scenario() -> None:
        await tool(action="open", session=session)
        await tool(action="send", session=session, keystrokes="echo view-marker\n")
        call = ToolCall(
            id="1",
            function="terminal",
            arguments={"action": "send", "session": session, "keystrokes": "next"},
        )
        view = _terminal_viewer(call)
        assert view.call is not None
        assert "view-marker" in view.call.content
        assert session in (view.call.title or "")
        await tool(action="close", session=session)

    asyncio.run(scenario())

"""Tests for the terminal tool against real host tmux.

The tool's only sandbox dependency is `sandbox().exec(argv)`, so these tests substitute a sandbox stub that runs the argv on the host: real tmux, real timing, no VMs (the provider's own exec path is pinned by test_provider_self_check). Each test uses a unique session name and kills it afterward, so parallel test runs cannot collide on the shared host tmux server.
"""

import asyncio
import shutil
import subprocess
import uuid
from collections.abc import Iterator
from typing import Any

import inspect_ranges._terminal.tool as terminal_tool
import pytest
from inspect_ai.tool import ToolCall
from inspect_ai.util import ExecResult
from inspect_ai.util._store import Store, init_subtask_store
from inspect_ranges import terminal
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
            keystrokes="sleep 1 && echo done-marker\n",
            block=True,
            timeout=30,
        )
        assert "done-marker" in result
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


def test_errors_are_strings(armed: tuple[Any, Store, str]) -> None:
    tool, _, session = armed

    async def scenario() -> None:
        assert "Unknown action" in await tool(action="poke", session=session)
        assert "Invalid session name" in await tool(action="open", session="Bad Name")
        assert "is not open" in await tool(
            action="send", session=session, keystrokes="x"
        )

    asyncio.run(scenario())


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

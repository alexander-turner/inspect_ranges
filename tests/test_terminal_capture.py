"""Tests for the terminal tool's capture leg against fake evidence and recorder processes."""

import asyncio
import json
from collections.abc import Iterator
from itertools import count
from pathlib import Path
from typing import Any

import inspect_ranges._terminal.capture as capture_module
import pytest
from inspect_ai.util._sandbox.exec_remote import ExecStdout
from inspect_ranges._terminal.capture import (
    captures_for_tests,
    discard_sample_captures,
    start_capture,
    stop_all_captures,
    stop_capture,
)
from inspect_ranges._terminal.session import SessionState


class FakeEvidence:
    """The evidence surface capture touches: location, append_driver, register_producer."""

    def __init__(self, location: str) -> None:
        self.location = location
        self.appended: list[tuple[str, bytes]] = []
        self.producers: list[Any] = []

    async def append_driver(self, stream: str, data: bytes) -> None:
        self.appended.append((stream, data))

    def register_producer(self, stop: Any) -> None:
        self.producers.append(stop)


class FakeProcess:
    """An exec_remote handle yielding scripted output events."""

    def __init__(self, outputs: list[str]) -> None:
        self._outputs = outputs
        self.killed = False

    def __aiter__(self) -> "FakeProcess":
        return self

    async def __anext__(self) -> ExecStdout:
        if not self._outputs:
            raise StopAsyncIteration
        return ExecStdout(data=self._outputs.pop(0))

    async def kill(self) -> None:
        self.killed = True


class FakeSandbox:
    def __init__(self, process: FakeProcess) -> None:
        self.process = process

    async def exec_remote(self, cmd: list[str], stream: bool = True) -> FakeProcess:
        return self.process


_STORE_IDS = count(4242)


@pytest.fixture()
def arm(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> Iterator[tuple[FakeEvidence, FakeProcess, SessionState, int]]:
    """A per-test store id (the module registry is shared state, so a reused id would leak one test's sample entry into the next) with the registry entry discarded afterward."""
    evidence = FakeEvidence(str(tmp_path / "evidence"))
    process = FakeProcess(["chunk-one\n", "chunk-two\n"])
    monkeypatch.setattr(capture_module, "_evidence_session", lambda: evidence)
    monkeypatch.setattr(capture_module, "sandbox", lambda: FakeSandbox(process))

    tasks: list[asyncio.Task[None]] = []

    def run_background(fn: Any, *args: Any) -> None:
        tasks.append(asyncio.get_event_loop().create_task(fn(*args)))

    monkeypatch.setattr(capture_module, "background", run_background)
    state = SessionState(opened_wall=1_700_000_000.0, opened_monotonic=0.0)
    store_id = next(_STORE_IDS)
    try:
        yield evidence, process, state, store_id
    finally:
        discard_sample_captures(store_id)


def test_capture_records_mirrors_and_writes_cast(
    arm: tuple[FakeEvidence, FakeProcess, SessionState, int],
) -> None:
    evidence, process, state, store_id = arm

    async def scenario() -> None:
        await start_capture(store_id, "s", state, lambda: None)
        assert len(evidence.producers) == 1
        await asyncio.sleep(0.05)  # the consumer drains the scripted events
        assert [data for _, data in evidence.appended] == [
            b"chunk-one\n",
            b"chunk-two\n",
        ]
        assert all(stream == "terminal/s" for stream, _ in evidence.appended)
        assert len(state.chunks) == 2
        state.markers.append((0.5, "send s: 'ls'"))
        await stop_capture(store_id, "s")
        assert process.killed
        cast_file = Path(evidence.location) / "terminal-s.cast"
        lines = cast_file.read_text().strip().split("\n")
        header = json.loads(lines[0])
        assert header["title"] == "terminal session s"
        kinds = [json.loads(line)[1] for line in lines[1:]]
        assert kinds.count("o") == 2 and kinds.count("m") == 1

    asyncio.run(scenario())


def test_finalize_stops_everything_and_runs_cleanup(
    arm: tuple[FakeEvidence, FakeProcess, SessionState, int],
) -> None:
    _, process, state, store_id = arm
    cleaned: list[bool] = []

    async def scenario() -> None:
        await start_capture(store_id, "s", state, lambda: cleaned.append(True))
        await asyncio.sleep(0.05)
        assert "s" in captures_for_tests(store_id)
        await stop_all_captures(store_id)
        assert process.killed
        assert cleaned == [True]
        assert captures_for_tests(store_id) == {}
        # idempotent: a second finalize finds nothing
        await stop_all_captures(store_id)
        assert cleaned == [True]

    asyncio.run(scenario())


def test_stop_drains_pending_output_before_the_cast(
    arm: tuple[FakeEvidence, FakeProcess, SessionState, int],
) -> None:
    """An immediate stop must still land every pending output event in the cast: kill enqueues output buffered since the last poll, and the cast waits for the consumer to drain it."""
    evidence, _, state, store_id = arm

    async def scenario() -> None:
        await start_capture(store_id, "s", state, lambda: None)
        await stop_capture(store_id, "s")  # no sleep: the consumer has not run yet
        cast_file = Path(evidence.location) / "terminal-s.cast"
        lines = cast_file.read_text().strip().split("\n")
        kinds = [json.loads(line)[1] for line in lines[1:]]
        assert kinds.count("o") == 2

    asyncio.run(scenario())


def test_discard_sample_captures_drops_the_registry_entry(
    arm: tuple[FakeEvidence, FakeProcess, SessionState, int],
) -> None:
    """GC-time cleanup: a collected store's capture entry disappears so a reused id never inherits it."""
    _, _, state, store_id = arm

    async def scenario() -> None:
        await start_capture(store_id, "s", state, lambda: None)
        assert "s" in captures_for_tests(store_id)
        discard_sample_captures(store_id)
        assert captures_for_tests(store_id) == {}

    asyncio.run(scenario())


def test_remote_location_skips_cast_but_mirrors(
    arm: tuple[FakeEvidence, FakeProcess, SessionState, int],
) -> None:
    evidence, _, state, store_id = arm
    evidence.location = "s3://bucket/evidence"

    async def scenario() -> None:
        await start_capture(store_id, "s", state, lambda: None)
        await asyncio.sleep(0.05)
        await stop_all_captures(store_id)
        assert len(evidence.appended) == 2  # the mirror is unaffected

    asyncio.run(scenario())


def test_capture_off_outside_range_sandbox(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(capture_module, "_evidence_session", lambda: None)
    state = SessionState()

    async def scenario() -> None:
        await start_capture(1, "s", state, lambda: None)
        assert captures_for_tests(1) == {}
        await stop_all_captures(1)  # no-op, never raises

    asyncio.run(scenario())

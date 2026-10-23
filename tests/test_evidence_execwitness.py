"""The exec-witness poller's evidence contract (execve-witness-v1): events land on sealed `exec/<guest>` streams, every loss is an in-chain gap with its count, unsupported endpoints become one declared-drop record and a stopped loop, and the kill switch means nothing is constructed.

Assertions run against the SEALED record via `verify_location`/`stream_chunks` (the telemetry-test discipline), never against mocks alone.
"""

import asyncio
import json
from pathlib import Path
from typing import Any

import pytest
from inspect_ranges._channel.channel import GuestError
from inspect_ranges._channel.protocol import ExecEvent, ExecEventsReply
from inspect_ranges._evidence.execwitness import ExecWitnessPoller, exec_event_lines
from inspect_ranges._evidence.reader import (
    LocalDirStore,
    manifest_records,
    stream_chunks,
    verify_location,
)
from inspect_ranges._evidence.sink import EvidenceWriter, LocalDirSink


class WitnessFakeChannel:
    """Scripted `exec_events` endpoint; every other verb refuses (the reads-only discipline the telemetry FakeChannel pins)."""

    def __init__(self) -> None:
        self.script: list[ExecEventsReply | Exception] = []
        self.calls: list[tuple[str, int]] = []

    async def exec_events(
        self, guest: str, *, since_seq: int = 0, max_events: int = 128
    ) -> ExecEventsReply:
        self.calls.append((guest, since_seq))
        entry = self.script.pop(0) if len(self.script) > 1 else self.script[0]
        if isinstance(entry, Exception):
            raise entry
        return entry

    def __getattr__(self, name: str) -> Any:
        def refuse(*args: Any, **kwargs: Any) -> Any:
            raise AssertionError(f"exec-witness poller must not call {name}")

        return refuse


def reply(
    events: list[ExecEvent], next_seq: int, *, drops: int = 0, restarts: int = 0
) -> ExecEventsReply:
    return ExecEventsReply(
        id="a" * 32, events=events, next_seq=next_seq, drops=drops, restarts=restarts
    )


def event(seq: int, pid: int = 100, argv: list[str] | None = None) -> ExecEvent:
    return ExecEvent(
        seq=seq,
        ts_ms=1000 + seq,
        pid=pid,
        comm="t",
        argv=argv or ["t"],
        truncated=False,
    )


def make_poller(
    tmp_path: Path,
    channel: WitnessFakeChannel,
    *,
    linux: list[str] | None = None,
    windows: list[str] | None = None,
) -> tuple[ExecWitnessPoller, EvidenceWriter, LocalDirStore]:
    writer = EvidenceWriter(
        LocalDirSink(tmp_path),
        part_interval_s=0,
        writer="driver",
        sample_id="execwitness-test",
    )
    poller = ExecWitnessPoller(
        channel,  # type: ignore[arg-type]
        writer,
        linux if linux is not None else ["web"],
        windows or [],
        meta_flush_s=0,
    )
    return poller, writer, LocalDirStore(tmp_path)


async def gap_causes(store: LocalDirStore, stream: str) -> list[tuple[str, int]]:
    return [
        (record.cause, record.dropped)
        for record in await manifest_records(store, "driver")
        if record.kind == "gap" and record.stream == stream
    ]


def test_events_land_on_the_sealed_stream(tmp_path: Path) -> None:
    async def run() -> None:
        channel = WitnessFakeChannel()
        channel.script = [
            reply([event(0), event(1, argv=["nmap", "-sV"])], 2),
            reply([], 2),
        ]
        poller, writer, store = make_poller(tmp_path, channel)
        await poller.poll_once("web")
        await poller.poll_once("web")
        await poller.stop()
        await writer.seal()
        assert (await verify_location(store)).ok
        chunks = await stream_chunks(store, "driver", "exec/web")
        records = [line for chunk in chunks for line in exec_event_lines(chunk)]
        assert [r["seq"] for r in records] == [0, 1]
        assert records[1]["argv"] == ["nmap", "-sV"]
        # the cursor advanced: the second poll asked from next_seq
        assert channel.calls == [("web", 0), ("web", 2)]
        # coverage records on the meta stream
        meta_chunks = await stream_chunks(store, "driver", "exec-meta/web")
        outcomes = [
            json.loads(line)["outcome"]
            for chunk in meta_chunks
            for line in chunk.decode().splitlines()
        ]
        assert outcomes.count("ok") == 2

    asyncio.run(run())


def test_losses_are_counted_gaps(tmp_path: Path) -> None:
    """A seq discontinuity becomes `exec-ring-overflow` with the lost count; a drops delta becomes `exec-subscriber-loss`."""

    async def run() -> None:
        channel = WitnessFakeChannel()
        channel.script = [
            reply([event(0)], 1),
            # ring overwrote 1..9 (first event past the cursor), plus kernel drops
            reply([event(10)], 11, drops=3),
            reply([], 11, drops=3),
        ]
        poller, writer, store = make_poller(tmp_path, channel)
        await poller.poll_once("web")
        await poller.poll_once("web")
        await poller.stop()
        await writer.seal()
        assert (await verify_location(store)).ok
        assert await gap_causes(store, "exec/web") == [
            ("exec-ring-overflow", 9),
            ("exec-subscriber-loss", 3),
        ]

    asyncio.run(run())


@pytest.mark.parametrize("errno", ["ENOSYS", "EPROTO"])
def test_typed_refusal_is_one_declared_drop_and_the_loop_stops(
    tmp_path: Path, errno: str
) -> None:
    async def run() -> None:
        channel = WitnessFakeChannel()
        channel.script = [GuestError(errno, "exec witness unavailable", None)]
        poller, writer, store = make_poller(tmp_path, channel)
        await poller.poll_once("web")
        await poller.poll_once("web")  # terminal: no second channel call
        await poller.stop()
        await writer.seal()
        assert (await verify_location(store)).ok
        assert len(channel.calls) == 1
        meta = b"".join(await stream_chunks(store, "driver", "exec-meta/web"))
        records = [json.loads(line) for line in meta.decode().splitlines()]
        unsupported = [r for r in records if r["outcome"] == "unsupported"]
        assert len(unsupported) == 1
        assert unsupported[0]["errno"] == errno
        assert unsupported[0]["reason"] == "daemon-unsupported"

    asyncio.run(run())


def test_windows_guest_is_never_polled_and_declares_its_drop(tmp_path: Path) -> None:
    async def run() -> None:
        channel = WitnessFakeChannel()
        channel.script = [reply([], 0)]
        poller, writer, store = make_poller(
            tmp_path, channel, linux=["web"], windows=["dc01"]
        )
        await poller.start()
        await poller.stop()
        await writer.seal()
        assert (await verify_location(store)).ok
        assert all(guest == "web" for guest, _ in channel.calls)
        meta = b"".join(await stream_chunks(store, "driver", "exec-meta/dc01"))
        (record,) = [json.loads(line) for line in meta.decode().splitlines()]
        assert record["outcome"] == "unsupported" and record["reason"] == "os-windows"

    asyncio.run(run())


def test_transient_failure_is_a_poll_failed_gap_then_recovery(tmp_path: Path) -> None:
    async def run() -> None:
        channel = WitnessFakeChannel()
        channel.script = [
            RuntimeError("vsock connect refused"),
            reply([event(0)], 1),
            reply([], 1),
        ]
        poller, writer, store = make_poller(tmp_path, channel)
        await poller.poll_once("web")  # fails: gap once
        await poller.poll_once("web")  # recovers
        await poller.stop()
        await writer.seal()
        assert (await verify_location(store)).ok
        assert await gap_causes(store, "exec/web") == [("poll-failed", 0)]
        chunks = await stream_chunks(store, "driver", "exec/web")
        assert sum(len(exec_event_lines(c)) for c in chunks) == 1

    asyncio.run(run())


def test_drain_burst_is_capped(tmp_path: Path) -> None:
    """Replies that keep packing full re-poll immediately, but never more than the burst cap in one cycle."""

    async def run() -> None:
        channel = WitnessFakeChannel()
        full = [event(i) for i in range(256)]
        channel.script = [reply(full, 256)]  # repeats forever, always "full"
        poller, writer, _ = make_poller(tmp_path, channel)
        await poller.poll_once("web")
        assert len(channel.calls) == 8  # EXEC_WITNESS_DRAIN_BURST
        await poller.stop()
        await writer.seal()

    asyncio.run(run())


def test_stop_never_raises_on_a_wedged_channel(tmp_path: Path) -> None:
    async def run() -> None:
        class WedgedChannel(WitnessFakeChannel):
            async def exec_events(
                self, guest: str, *, since_seq: int = 0, max_events: int = 128
            ) -> ExecEventsReply:
                await asyncio.sleep(3600)
                raise AssertionError("unreachable")

        channel = WedgedChannel()
        poller, writer, _ = make_poller(tmp_path, channel)
        await poller.start()
        await asyncio.sleep(0.05)
        await poller.stop(stop_timeout_s=0.3)  # must cancel, never raise
        await writer.seal()

    asyncio.run(run())

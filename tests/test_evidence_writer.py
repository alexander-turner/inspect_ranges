"""Writer discipline: write-once delivery, buffering, caps, gaps, seals.

The writer's contract (evidence-v1.md): backend errors never raise into the caller's path mid-stream; loss is always an in-chain gap record; the writer never reads from the backend; a seal never claims parts that were not delivered.
"""

import asyncio
from pathlib import Path
from typing import Any

import pytest
from inspect_ranges._evidence.manifest import ClockSpan, ClockStamp, SealStatus
from inspect_ranges._evidence.reader import LocalDirStore, verify_location
from inspect_ranges._evidence.sink import (
    EvidenceWriter,
    LocalDirSink,
    SealDeliveryError,
)


class FakeClock:
    """Deterministic dual-clock source."""

    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> ClockStamp:
        self.now += 1.0
        return ClockStamp(wall=self.now, monotonic=self.now / 2)


class PutOnlySpy:
    """Backend proxy that records puts and refuses every other access."""

    def __init__(self, inner: LocalDirSink) -> None:
        self._inner = inner
        self.calls: list[tuple[str, str]] = []

    async def put(self, key: str, data: bytes) -> None:
        self.calls.append(("put", key))
        await self._inner.put(key, data)

    def __getattr__(self, name: str) -> Any:
        # only fires for attributes that do not exist: any non-put backend use
        raise AssertionError(f"writer accessed non-put backend attribute {name!r}")


class FlakySink:
    """Fails the first `failures` puts, then delegates."""

    def __init__(self, inner: LocalDirSink, failures: int) -> None:
        self.inner = inner
        self.failures = failures

    async def put(self, key: str, data: bytes) -> None:
        if self.failures > 0:
            self.failures -= 1
            raise OSError("sink unavailable")
        await self.inner.put(key, data)


class DeadSink:
    """Every put fails until healed."""

    def __init__(self, inner: LocalDirSink) -> None:
        self.inner = inner
        self.dead = True

    async def put(self, key: str, data: bytes) -> None:
        if self.dead:
            raise OSError("sink down")
        await self.inner.put(key, data)


def _span(clock: FakeClock) -> ClockSpan:
    stamp = clock()
    return ClockSpan(start=stamp, end=stamp)


def test_writer_never_reads(tmp_path: Path) -> None:
    async def scenario() -> None:
        spy = PutOnlySpy(LocalDirSink(tmp_path))
        clock = FakeClock()
        writer = EvidenceWriter(spy, writer="host", clock=clock, retry_wait_s=0)
        await writer.append("console/web", b"boot output", span=_span(clock))
        await writer.gap(
            "pcap/dmz", span=_span(clock), cause="write-failed", dropped=10
        )
        await writer.flush()
        await writer.seal()
        calls: list[tuple[str, str]] = spy.calls
        assert calls, "writer delivered nothing"
        assert {op for op, _ in calls} == {"put"}

    asyncio.run(scenario())


def test_round_trip_verifies(tmp_path: Path) -> None:
    async def scenario() -> None:
        clock = FakeClock()
        writer = EvidenceWriter(
            LocalDirSink(tmp_path),
            writer="host",
            lease_id="lease-1",
            sample_id="s1",
            clock=clock,
            retry_wait_s=0,
        )
        await writer.append("pcap/dmz", b"frame-one", span=_span(clock))
        await writer.append("console/web", b"hello", span=_span(clock))
        await writer.flush()  # part 0
        await writer.append("pcap/dmz", b"frame-two", span=_span(clock))
        seal, digest = await writer.seal(worst_watermark_lag_s=0.5)
        assert seal.status == "complete"
        assert seal.parts == 2
        assert seal.lease_id == "lease-1"
        assert seal.streams["pcap/dmz"].chunks == 2
        assert seal.streams["console/web"].size == 5

        report = await verify_location(LocalDirStore(tmp_path))
        assert report.ok
        host = report.writers["host"]
        assert host.sealed and host.seal_status == "complete"
        assert host.seal_digest == digest
        assert host.streams["pcap/dmz"].chunks == 2
        assert not report.unreferenced

    asyncio.run(scenario())


def test_backend_errors_buffer_and_recover(tmp_path: Path) -> None:
    async def scenario() -> None:
        clock = FakeClock()
        dead = DeadSink(LocalDirSink(tmp_path))
        writer = EvidenceWriter(
            dead, writer="host", clock=clock, put_attempts=2, retry_wait_s=0
        )
        # append never raises while the sink is down
        await writer.append("stages", b"report-1", span=_span(clock))
        result = await writer.flush()
        assert result.errors and result.pending_chunks == 1
        # heals: the buffered chunk delivers with its order preserved
        dead.dead = False
        await writer.append("stages", b"report-2", span=_span(clock))
        result = await writer.flush()
        assert result.delivered_chunks == 2 and not result.errors
        seal, _ = await writer.seal()
        assert seal.status == "complete"
        report = await verify_location(LocalDirStore(tmp_path))
        assert report.ok and report.writers["host"].streams["stages"].chunks == 2

    asyncio.run(scenario())


def test_transient_errors_retry_within_flush(tmp_path: Path) -> None:
    async def scenario() -> None:
        clock = FakeClock()
        flaky = FlakySink(LocalDirSink(tmp_path), failures=2)
        writer = EvidenceWriter(
            flaky, writer="host", clock=clock, put_attempts=3, retry_wait_s=0
        )
        await writer.append("verify", b"green", span=_span(clock))
        result = await writer.flush()
        assert result.delivered_chunks == 1 and not result.errors

    asyncio.run(scenario())


def test_buffer_cap_drops_oldest_with_gap(tmp_path: Path) -> None:
    async def scenario() -> None:
        clock = FakeClock()
        dead = DeadSink(LocalDirSink(tmp_path))
        writer = EvidenceWriter(
            dead,
            writer="host",
            clock=clock,
            buffer_cap_bytes=10,
            put_attempts=1,
            retry_wait_s=0,
        )
        await writer.append("pcap/dmz", b"aaaaaa", span=_span(clock))  # 6 bytes
        await writer.append(
            "pcap/dmz", b"bbbbbb", span=_span(clock)
        )  # 12 > 10: drop oldest
        dead.dead = False
        seal, _ = await writer.seal()
        assert seal.streams["pcap/dmz"].gaps == 1
        assert seal.streams["pcap/dmz"].chunks == 1
        report = await verify_location(LocalDirStore(tmp_path))
        assert report.ok
        gaps = report.writers["host"].gaps
        assert len(gaps) == 1 and gaps[0].cause == "buffer-cap" and gaps[0].dropped == 6
        # the gap holds the dropped chunk's sequence slot: seq 0, chunk at seq 1
        assert gaps[0].seq == 0

    asyncio.run(scenario())


def test_oversized_chunk_gapped_immediately(tmp_path: Path) -> None:
    async def scenario() -> None:
        clock = FakeClock()
        writer = EvidenceWriter(
            LocalDirSink(tmp_path),
            writer="host",
            clock=clock,
            buffer_cap_bytes=4,
            retry_wait_s=0,
        )
        await writer.append(
            "console/web", b"too large for the buffer", span=_span(clock)
        )
        seal, _ = await writer.seal()
        assert seal.streams["console/web"].gaps == 1
        assert seal.streams["console/web"].chunks == 0
        assert seal.status == "complete"  # nothing buffered was lost silently

    asyncio.run(scenario())


def test_seal_statuses_round_trip(tmp_path: Path) -> None:
    async def scenario() -> None:
        clock = FakeClock()
        cases: list[tuple[SealStatus, str]] = [("complete", "a"), ("reaped", "b")]
        for status, sub in cases:
            writer = EvidenceWriter(
                LocalDirSink(tmp_path / sub), writer="host", clock=clock, retry_wait_s=0
            )
            await writer.append("stages", b"x", span=_span(clock))
            seal, _ = await writer.seal(status)
            assert seal.status == status
            report = await verify_location(LocalDirStore(tmp_path / sub))
            assert report.ok and report.writers["host"].seal_status == status

    asyncio.run(scenario())


def test_seal_degrades_to_incomplete_on_unflushed(tmp_path: Path) -> None:
    async def scenario() -> None:
        clock = FakeClock()

        class ChunkDeadSink:
            """Chunk puts fail; manifest and seal puts succeed."""

            def __init__(self, inner: LocalDirSink) -> None:
                self.inner = inner

            async def put(self, key: str, data: bytes) -> None:
                if key.startswith("chunks/"):
                    raise OSError("chunk plane down")
                await self.inner.put(key, data)

        writer = EvidenceWriter(
            ChunkDeadSink(LocalDirSink(tmp_path)),
            writer="host",
            clock=clock,
            put_attempts=1,
            retry_wait_s=0,
        )
        await writer.append("pcap/dmz", b"lost-bytes", span=_span(clock))
        seal, _ = await writer.seal()
        assert seal.status == "incomplete"
        assert seal.unflushed == len(b"lost-bytes")
        report = await verify_location(LocalDirStore(tmp_path))
        assert report.ok
        gaps = report.writers["host"].gaps
        assert len(gaps) == 1 and gaps[0].cause == "unflushed"

    asyncio.run(scenario())


def test_seal_raises_when_parts_undeliverable(tmp_path: Path) -> None:
    async def scenario() -> None:
        clock = FakeClock()
        dead = DeadSink(LocalDirSink(tmp_path))
        writer = EvidenceWriter(
            dead, writer="host", clock=clock, put_attempts=1, retry_wait_s=0
        )
        await writer.append("stages", b"x", span=_span(clock))
        with pytest.raises(SealDeliveryError):
            await writer.seal()
        # the record stays honestly unsealed and the writer unusable thereafter
        report = await verify_location(LocalDirStore(tmp_path))
        assert not report.writers  # nothing was delivered at all

    asyncio.run(scenario())


def test_write_once_conflict_becomes_gap(tmp_path: Path) -> None:
    async def scenario() -> None:
        clock = FakeClock()
        sink = LocalDirSink(tmp_path)
        # a foreign object already sits at the chunk key this stream will use
        await sink.put("chunks/host/stages/000000.bin", b"squatter")
        writer = EvidenceWriter(sink, writer="host", clock=clock, retry_wait_s=0)
        await writer.append("stages", b"ours", span=_span(clock))
        seal, _ = await writer.seal()
        assert seal.streams["stages"].gaps == 1
        report = await verify_location(LocalDirStore(tmp_path))
        host = report.writers["host"]
        assert host.ok and host.gaps[0].cause == "write-once-conflict"
        # the squatter is residue: unreferenced, reported, not a break
        assert report.unreferenced == ["chunks/host/stages/000000.bin"]

    asyncio.run(scenario())


def test_sealed_writer_refuses_further_use(tmp_path: Path) -> None:
    async def scenario() -> None:
        clock = FakeClock()
        writer = EvidenceWriter(
            LocalDirSink(tmp_path), writer="host", clock=clock, retry_wait_s=0
        )
        await writer.seal()
        with pytest.raises(RuntimeError):
            await writer.append("stages", b"late", span=_span(clock))

    asyncio.run(scenario())


def test_interleaved_writers_stay_isolated(tmp_path: Path) -> None:
    async def scenario() -> None:
        clock = FakeClock()
        sink = LocalDirSink(tmp_path)
        host = EvidenceWriter(sink, writer="host", clock=clock, retry_wait_s=0)
        driver = EvidenceWriter(sink, writer="driver", clock=clock, retry_wait_s=0)
        # interleaved appends and flushes at one location, disjoint streams
        await host.append("pcap/dmz", b"frame", span=_span(clock))
        await driver.append("plants", b"record", span=_span(clock))
        await host.flush()
        await driver.append("clock", b"pair", span=_span(clock))
        await host.append("console/web", b"line", span=_span(clock))
        _, host_digest = await host.seal()
        _, driver_digest = await driver.seal()
        assert host_digest != driver_digest

        report = await verify_location(LocalDirStore(tmp_path))
        assert report.ok and set(report.writers) == {"driver", "host"}
        assert set(report.writers["host"].streams) == {"pcap/dmz", "console/web"}
        assert set(report.writers["driver"].streams) == {"plants", "clock"}

    asyncio.run(scenario())


def test_invalid_names_raise_at_the_boundary(tmp_path: Path) -> None:
    async def scenario() -> None:
        clock = FakeClock()
        with pytest.raises(ValueError):
            EvidenceWriter(LocalDirSink(tmp_path), writer="Host!", clock=clock)
        writer = EvidenceWriter(LocalDirSink(tmp_path), writer="host", clock=clock)
        with pytest.raises(ValueError):
            await writer.append("Console", b"x", span=_span(clock))
        with pytest.raises(ValueError):
            await writer.gap("a/b/c", cause="nested-too-deep")
        # the rejected names poisoned nothing: valid work still delivers
        await writer.append("console/web", b"x", span=_span(clock))
        seal, _ = await writer.seal()
        assert seal.status == "complete"

    asyncio.run(scenario())


def test_ambiguous_file_exists_after_transient_assumed_delivered(
    tmp_path: Path,
) -> None:
    """A put that landed but reported failure (the S3 shape): the retry's FileExistsError means ours."""

    class LandsButFails:
        def __init__(self, inner: LocalDirSink) -> None:
            self.inner = inner
            self.failed_once = False

        async def put(self, key: str, data: bytes) -> None:
            if key.startswith("chunks/") and not self.failed_once:
                self.failed_once = True
                await self.inner.put(key, data)  # the write lands...
                raise OSError("response lost")  # ...but the caller never hears
            await self.inner.put(key, data)

    async def scenario() -> None:
        clock = FakeClock()
        writer = EvidenceWriter(
            LandsButFails(LocalDirSink(tmp_path)),
            writer="host",
            clock=clock,
            retry_wait_s=0,
        )
        await writer.append("stages", b"landed", span=_span(clock))
        seal, _ = await writer.seal()
        assert seal.streams["stages"].chunks == 1
        assert seal.streams["stages"].gaps == 0
        report = await verify_location(LocalDirStore(tmp_path))
        assert report.ok and not report.unreferenced

    asyncio.run(scenario())


def test_concurrent_append_and_flush_stay_consistent(tmp_path: Path) -> None:
    """A flusher task racing appends and gaps on one stream: keys and seqs stay in step."""

    class SlowSink:
        def __init__(self, inner: LocalDirSink) -> None:
            self.inner = inner

        async def put(self, key: str, data: bytes) -> None:
            await asyncio.sleep(0.001)
            await self.inner.put(key, data)

    async def scenario() -> None:
        clock = FakeClock()
        writer = EvidenceWriter(
            SlowSink(LocalDirSink(tmp_path)), writer="host", clock=clock, retry_wait_s=0
        )

        async def producer() -> None:
            for index in range(20):
                await writer.append(
                    "pcap/dmz", f"frame-{index}".encode(), span=_span(clock)
                )
                if index % 5 == 0:
                    await writer.gap("pcap/dmz", cause="write-failed", dropped=1)

        async def flusher() -> None:
            for _ in range(10):
                await writer.flush()
                await asyncio.sleep(0)

        async with asyncio.TaskGroup() as group:
            group.create_task(producer())
            group.create_task(flusher())
        seal, _ = await writer.seal()
        assert seal.streams["pcap/dmz"].records == 24  # 20 chunks + 4 gaps
        report = await verify_location(LocalDirStore(tmp_path))
        assert report.ok and not report.unreferenced

    asyncio.run(scenario())

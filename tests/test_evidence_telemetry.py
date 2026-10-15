"""Telemetry poller discipline: deltas, watermarks, gaps, and the reads-only guarantee.

The poller's contract (evidence-v1.md, slice 4): existing channel verbs only and reads only (no secret material ever transits guest-ward); poll failure is an in-chain `poll-failed` gap plus meta records, never a raise; a watermark stall is visible in the meta stream while polls keep succeeding (completeness decidable from the record alone); watermark regression and un-paginatable growth are explicit in-chain gaps; `stop()` never raises.
"""

import asyncio
import json
import re
from pathlib import Path
from typing import Any

import pytest
from inspect_ranges._channel.channel import (
    ExecOutcome,
    FileLimitExceeded,
    GuestError,
)
from inspect_ranges._channel.protocol import ExecRequest
from inspect_ranges._evidence.reader import (
    LocalDirStore,
    manifest_records,
    stream_chunks,
    verify_location,
)
from inspect_ranges._evidence.sink import EvidenceWriter, LocalDirSink
from inspect_ranges._evidence.telemetry import (
    CURSOR_PLACEHOLDER,
    CollectorSpec,
    CommandSource,
    FileSource,
    TelemetryPoller,
)

JOURNAL_SOURCE = CommandSource(
    command=[
        "journalctl",
        "-t",
        "app",
        f"--after-cursor={CURSOR_PLACEHOLDER}",
        "--show-cursor",
        "-q",
    ],
    bootstrap=["journalctl", "-t", "app", "-n", "100", "--show-cursor", "-q"],
    cursor_pattern=r"-- cursor: (\S+)",
)


def journal_spec(**overrides: Any) -> CollectorSpec:
    fields: dict[str, Any] = {
        "name": "journal",
        "guest": "db",
        "source": JOURNAL_SOURCE,
    }
    fields.update(overrides)
    return CollectorSpec(**fields)


def file_spec(**overrides: Any) -> CollectorSpec:
    fields: dict[str, Any] = {
        "name": "applog",
        "guest": "db",
        "source": FileSource(path="/var/log/app.log"),
    }
    fields.update(overrides)
    return CollectorSpec(**fields)


def exec_ok(stdout: bytes, *, rc: int = 0, truncated: bool = False) -> ExecOutcome:
    return ExecOutcome(
        rc=rc,
        stdout=stdout,
        stderr=b"",
        stdout_truncated=truncated,
        stderr_truncated=False,
    )


class FakeChannel:
    """Scripted exec/read_file with a full call log; every other verb refuses.

    Script entries are either results to return or exceptions to raise; an exhausted script repeats its last entry.
    """

    def __init__(self) -> None:
        self.exec_script: list[ExecOutcome | Exception] = []
        self.read_script: list[bytes | Exception] = []
        self.exec_calls: list[ExecRequest] = []
        self.exec_stdins: list[bytes | None] = []
        self.read_calls: list[tuple[str, str]] = []
        self.other_calls: list[str] = []

    def _next(self, script: list[Any]) -> Any:
        entry = script.pop(0) if len(script) > 1 else script[0]
        if isinstance(entry, Exception):
            raise entry
        return entry

    async def exec(
        self, guest: str, request: ExecRequest, *, stdin: bytes | None = None, **_: Any
    ) -> ExecOutcome:
        self.exec_calls.append(request)
        self.exec_stdins.append(stdin)
        result: ExecOutcome = self._next(self.exec_script)
        return result

    async def read_file(self, guest: str, path: str, *, cap: int = 0) -> bytes:
        self.read_calls.append((guest, path))
        result: bytes = self._next(self.read_script)
        return result

    def __getattr__(self, name: str) -> Any:
        def refuse(*args: Any, **kwargs: Any) -> Any:
            self.other_calls.append(name)
            raise AssertionError(f"telemetry poller must not call {name}")

        return refuse


def make_poller(
    tmp_path: Path, channel: FakeChannel, specs: list[CollectorSpec]
) -> tuple[TelemetryPoller, EvidenceWriter, LocalDirStore]:
    writer = EvidenceWriter(
        LocalDirSink(tmp_path),
        part_interval_s=0,
        writer="driver",
        sample_id="telemetry-test",
    )
    poller = TelemetryPoller(channel, writer, specs, meta_flush_s=0)  # type: ignore[arg-type]
    return poller, writer, LocalDirStore(tmp_path)


async def gap_causes(store: LocalDirStore, stream: str) -> list[str]:
    return [
        record.cause
        for record in await manifest_records(store, "driver")
        if record.kind == "gap" and record.stream == stream
    ]


async def meta_records(store: LocalDirStore, collector: str) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for chunk in await stream_chunks(store, "driver", f"telemetry-meta/{collector}"):
        records.extend(json.loads(line) for line in chunk.decode().splitlines())
    return records


async def data_bytes(store: LocalDirStore, collector: str) -> bytes:
    return b"".join(await stream_chunks(store, "driver", f"telemetry/{collector}"))


# -- command mode ------------------------------------------------------------


def test_command_mode_bootstrap_cursor_and_deltas(tmp_path: Path) -> None:
    async def run() -> None:
        channel = FakeChannel()
        channel.exec_script = [
            exec_ok(b"evt-1\nevt-2\n-- cursor: c1\n"),
            exec_ok(b""),
            exec_ok(b"evt-3\n-- cursor: c2\n"),
        ]
        poller, writer, store = make_poller(tmp_path, channel, [journal_spec()])
        for _ in range(3):
            await poller.poll_once("journal")
        await writer.seal()

        assert channel.exec_calls[0].cmd == JOURNAL_SOURCE.bootstrap
        assert channel.exec_calls[1].cmd[3] == "--after-cursor=c1"
        assert channel.exec_calls[2].cmd[3] == "--after-cursor=c1"
        data = await data_bytes(store, "journal")
        assert b"evt-1" in data and b"evt-3" in data
        meta = await meta_records(store, "journal")
        assert [m["outcome"] for m in meta] == ["ok", "quiet", "ok"]
        assert [m["advanced"] for m in meta] == [True, False, True]
        assert [m["watermark"] for m in meta] == ["c1", "c1", "c2"]
        report = await verify_location(store)
        assert report.ok

    asyncio.run(run())


def test_command_rc_failure_is_one_gap_per_streak_and_recovers(
    tmp_path: Path,
) -> None:
    async def run() -> None:
        channel = FakeChannel()
        channel.exec_script = [
            exec_ok(b"evt-1\n-- cursor: c1\n"),
            exec_ok(b"journal unavailable\n", rc=1),
            exec_ok(b"still down\n", rc=1),
            exec_ok(b"evt-2\n-- cursor: c2\n"),
        ]
        poller, writer, store = make_poller(tmp_path, channel, [journal_spec()])
        for _ in range(4):
            await poller.poll_once("journal")
        await writer.seal()

        assert await gap_causes(store, "telemetry/journal") == ["poll-failed"]
        meta = await meta_records(store, "journal")
        assert [m["outcome"] for m in meta] == ["ok", "error", "error", "ok"]
        assert meta[1]["errors"] == 1 and meta[2]["errors"] == 2
        assert (await verify_location(store)).ok

    asyncio.run(run())


def test_command_channel_exception_is_poll_failure_not_raise(tmp_path: Path) -> None:
    async def run() -> None:
        channel = FakeChannel()
        channel.exec_script = [
            ConnectionError("guest unreachable"),
            exec_ok(b"evt-1\n-- cursor: c1\n"),
        ]
        poller, writer, store = make_poller(tmp_path, channel, [journal_spec()])
        await poller.poll_once("journal")  # must not raise
        await poller.poll_once("journal")
        await writer.seal()

        assert await gap_causes(store, "telemetry/journal") == ["poll-failed"]
        meta = await meta_records(store, "journal")
        assert meta[0]["outcome"] == "error"
        assert "guest unreachable" in meta[0]["error"]
        assert meta[1]["outcome"] == "ok"

    asyncio.run(run())


def test_command_truncation_ships_prefix_gaps_and_rebootstraps(
    tmp_path: Path,
) -> None:
    async def run() -> None:
        channel = FakeChannel()
        channel.exec_script = [
            exec_ok(b"evt-1\n-- cursor: c1\n"),
            exec_ok(b"evt-2\nevt-3\n(cursor line lost)", truncated=True),
            exec_ok(b"evt-4\n-- cursor: c3\n"),
        ]
        poller, writer, store = make_poller(tmp_path, channel, [journal_spec()])
        for _ in range(3):
            await poller.poll_once("journal")
        await writer.seal()

        assert await gap_causes(store, "telemetry/journal") == ["poll-truncated"]
        assert b"evt-2" in await data_bytes(store, "journal")
        meta = await meta_records(store, "journal")
        assert meta[1]["outcome"] == "truncated" and meta[1]["watermark"] is None
        # re-bootstrap: the third poll runs the bootstrap command again
        assert channel.exec_calls[2].cmd == JOURNAL_SOURCE.bootstrap

    asyncio.run(run())


def test_command_banner_only_output_is_quiet_and_ships_nothing(
    tmp_path: Path,
) -> None:
    async def run() -> None:
        channel = FakeChannel()
        channel.exec_script = [
            exec_ok(b"evt-1\n-- cursor: c1\n"),
            exec_ok(b"-- cursor: c1\n"),
            exec_ok(b"-- cursor: c1\n"),
        ]
        poller, writer, store = make_poller(tmp_path, channel, [journal_spec()])
        for _ in range(3):
            await poller.poll_once("journal")
        await writer.seal()

        # banner lines never ship: the data stream carries events only
        assert await data_bytes(store, "journal") == b"evt-1\n"
        meta = await meta_records(store, "journal")
        assert [m["outcome"] for m in meta] == ["ok", "quiet", "quiet"]
        assert [m["watermark"] for m in meta] == ["c1", "c1", "c1"]

    asyncio.run(run())


def test_command_replay_flag_marks_post_reset_bootstrap(tmp_path: Path) -> None:
    async def run() -> None:
        channel = FakeChannel()
        channel.exec_script = [
            exec_ok(b"evt-1\n-- cursor: c1\n"),
            exec_ok(b"evt-2 (cursor lost)", truncated=True),
            exec_ok(b"evt-1\nevt-2\n-- cursor: c2\n"),  # bootstrap re-ships
        ]
        poller, writer, store = make_poller(tmp_path, channel, [journal_spec()])
        for _ in range(3):
            await poller.poll_once("journal")
        await writer.seal()

        meta = await meta_records(store, "journal")
        # the duplicate window is decidable from the record alone
        assert meta[0].get("replay") is None
        assert meta[2]["replay"] is True and meta[2]["outcome"] == "ok"

    asyncio.run(run())


def test_command_cursor_missing_rebootstraps_without_gap(tmp_path: Path) -> None:
    async def run() -> None:
        channel = FakeChannel()
        channel.exec_script = [
            exec_ok(b"output without any cursor line\n"),
            exec_ok(b"evt-1\n-- cursor: c1\n"),
        ]
        poller, writer, store = make_poller(tmp_path, channel, [journal_spec()])
        await poller.poll_once("journal")
        await poller.poll_once("journal")
        await writer.seal()

        assert await gap_causes(store, "telemetry/journal") == []
        meta = await meta_records(store, "journal")
        assert meta[0]["outcome"] == "cursor-missing"
        assert channel.exec_calls[1].cmd == JOURNAL_SOURCE.bootstrap

    asyncio.run(run())


# -- file mode ----------------------------------------------------------------


def test_file_mode_deltas_offsets_and_quiet(tmp_path: Path) -> None:
    async def run() -> None:
        channel = FakeChannel()
        channel.read_script = [b"line-1\n", b"line-1\n", b"line-1\nline-2\n"]
        poller, writer, store = make_poller(tmp_path, channel, [file_spec()])
        for _ in range(3):
            await poller.poll_once("applog")
        await writer.seal()

        assert await data_bytes(store, "applog") == b"line-1\nline-2\n"
        meta = await meta_records(store, "applog")
        assert [m["outcome"] for m in meta] == ["ok", "quiet", "ok"]
        assert [m["watermark"] for m in meta] == [7, 7, 14]
        assert (await verify_location(store)).ok

    asyncio.run(run())


def test_file_watermark_regression_gaps_and_reships(tmp_path: Path) -> None:
    async def run() -> None:
        channel = FakeChannel()
        channel.read_script = [b"aaaa-bbbb-cccc\n", b"fresh\n"]
        poller, writer, store = make_poller(tmp_path, channel, [file_spec()])
        await poller.poll_once("applog")
        await poller.poll_once("applog")
        await writer.seal()

        assert await gap_causes(store, "telemetry/applog") == ["watermark-regression"]
        assert (await data_bytes(store, "applog")).endswith(b"fresh\n")
        meta = await meta_records(store, "applog")
        assert meta[1]["anomaly"] == "watermark-regression"
        assert meta[1]["outcome"] == "ok" and meta[1]["watermark"] == 6

    asyncio.run(run())


def test_file_truncate_then_regrow_is_detected_by_content(tmp_path: Path) -> None:
    async def run() -> None:
        channel = FakeChannel()
        # same length as shipped prefix, different bytes: a size-only check
        # would silently splice the new file's tail into the record
        channel.read_script = [b"old-content-1\n", b"NEW-content-1\nNEW-2\n"]
        poller, writer, store = make_poller(tmp_path, channel, [file_spec()])
        await poller.poll_once("applog")
        await poller.poll_once("applog")
        await writer.seal()

        assert await gap_causes(store, "telemetry/applog") == ["watermark-regression"]
        data = await data_bytes(store, "applog")
        # the record restarts from the new content, never splicing mid-file
        assert data == b"old-content-1\nNEW-content-1\nNEW-2\n"

    asyncio.run(run())


def test_file_rotation_via_enoent_after_content_is_regression(
    tmp_path: Path,
) -> None:
    async def run() -> None:
        channel = FakeChannel()
        channel.read_script = [
            b"line-1\n",
            GuestError("ENOENT", "rotated away"),
            b"fresh-1\n",
        ]
        poller, writer, store = make_poller(tmp_path, channel, [file_spec()])
        for _ in range(3):
            await poller.poll_once("applog")
        await writer.seal()

        assert await gap_causes(store, "telemetry/applog") == ["watermark-regression"]
        assert (await data_bytes(store, "applog")).endswith(b"fresh-1\n")
        meta = await meta_records(store, "applog")
        assert meta[1]["outcome"] == "absent"
        assert meta[1]["anomaly"] == "rotated-or-deleted"
        assert meta[1]["watermark"] == 0

    asyncio.run(run())


def test_file_absent_is_quiet_not_failure(tmp_path: Path) -> None:
    async def run() -> None:
        channel = FakeChannel()
        channel.read_script = [
            GuestError("ENOENT", "no such file"),
            b"line-1\n",
        ]
        poller, writer, store = make_poller(tmp_path, channel, [file_spec()])
        await poller.poll_once("applog")
        await poller.poll_once("applog")
        await writer.seal()

        assert await gap_causes(store, "telemetry/applog") == []
        meta = await meta_records(store, "applog")
        assert meta[0]["outcome"] == "absent"
        assert meta[1]["outcome"] == "ok"

    asyncio.run(run())


def test_file_other_guest_error_is_poll_failure(tmp_path: Path) -> None:
    async def run() -> None:
        channel = FakeChannel()
        channel.read_script = [GuestError("EACCES", "permission denied")]
        poller, writer, store = make_poller(tmp_path, channel, [file_spec()])
        await poller.poll_once("applog")
        await writer.seal()

        assert await gap_causes(store, "telemetry/applog") == ["poll-failed"]

    asyncio.run(run())


def test_file_growth_past_cap_gaps_once_per_stall(tmp_path: Path) -> None:
    async def run() -> None:
        capped = b"x" * 4096
        channel = FakeChannel()
        channel.read_script = [
            FileLimitExceeded("/var/log/app.log", capped),
            FileLimitExceeded("/var/log/app.log", capped),
            FileLimitExceeded("/var/log/app.log", capped),
        ]
        poller, writer, store = make_poller(
            tmp_path, channel, [file_spec(max_poll_bytes=4096)]
        )
        for _ in range(3):
            await poller.poll_once("applog")
        await writer.seal()

        # poll 1 ships the capped prefix; polls 2-3 cannot paginate: one gap
        assert await gap_causes(store, "telemetry/applog") == ["poll-truncated"]
        assert await data_bytes(store, "applog") == capped
        meta = await meta_records(store, "applog")
        assert [m["outcome"] for m in meta] == ["ok", "capped", "capped"]

    asyncio.run(run())


# -- the reads-only guarantee --------------------------------------------------


def test_reads_only_no_write_verbs_no_env_no_stdin(tmp_path: Path) -> None:
    async def run() -> None:
        channel = FakeChannel()
        channel.exec_script = [exec_ok(b"evt\n-- cursor: c1\n")]
        channel.read_script = [b"line\n"]
        poller, writer, _ = make_poller(
            tmp_path, channel, [journal_spec(), file_spec()]
        )
        for _ in range(3):
            await poller.poll_once("journal")
            await poller.poll_once("applog")
        await writer.seal()

        assert channel.other_calls == []
        assert all(stdin is None for stdin in channel.exec_stdins)
        declared = set(JOURNAL_SOURCE.command) | set(JOURNAL_SOURCE.bootstrap)
        cursor_arg = re.compile(r"^--after-cursor=c\d+$")
        for request in channel.exec_calls:
            assert request.env == {}
            for arg in request.cmd:
                assert arg in declared or cursor_arg.match(arg), (
                    f"undeclared argv element {arg!r}"
                )

    asyncio.run(run())


# -- lifecycle ------------------------------------------------------------------


def test_start_stop_polls_on_cadence_and_stop_never_raises(tmp_path: Path) -> None:
    async def run() -> None:
        channel = FakeChannel()
        channel.exec_script = [exec_ok(b"evt\n-- cursor: c1\n")]
        poller, writer, store = make_poller(
            tmp_path, channel, [journal_spec(poll_s=0.01)]
        )
        await poller.start()
        await poller.start()  # idempotent
        deadline = asyncio.get_running_loop().time() + 5.0
        while (
            len(channel.exec_calls) < 3 and asyncio.get_running_loop().time() < deadline
        ):
            await asyncio.sleep(0.01)
        await poller.stop()
        assert len(channel.exec_calls) >= 3
        await writer.seal()
        assert (await verify_location(store)).ok

    asyncio.run(run())


def test_stop_against_sealed_writer_and_dead_channel_never_raises(
    tmp_path: Path,
) -> None:
    async def run() -> None:
        channel = FakeChannel()
        channel.exec_script = [ConnectionError("dead")]
        poller, writer, _ = make_poller(tmp_path, channel, [journal_spec(poll_s=0.01)])
        await poller.start()
        await asyncio.sleep(0.05)
        await writer.seal()  # out-of-order teardown: sealed under the poller
        await poller.stop()  # must not raise

    asyncio.run(run())


def test_start_after_stop_raises_rather_than_silently_not_polling(
    tmp_path: Path,
) -> None:
    async def run() -> None:
        channel = FakeChannel()
        channel.exec_script = [exec_ok(b"evt\n-- cursor: c1\n")]
        poller, _, _ = make_poller(tmp_path, channel, [journal_spec(poll_s=0.01)])
        await poller.start()
        await poller.stop()
        with pytest.raises(RuntimeError, match="cannot restart"):
            await poller.start()

    asyncio.run(run())


def test_stop_cancels_a_hung_poll_within_budget(tmp_path: Path) -> None:
    async def run() -> None:
        hang = asyncio.Event()

        class HangingChannel(FakeChannel):
            async def exec(self, *args: Any, **kwargs: Any) -> ExecOutcome:
                hang.set()
                await asyncio.sleep(3600)
                raise AssertionError("unreachable")

        channel = HangingChannel()
        poller, _, _ = make_poller(tmp_path, channel, [journal_spec(poll_s=0.01)])
        await poller.start()
        await asyncio.wait_for(hang.wait(), timeout=5)
        start = asyncio.get_running_loop().time()
        await poller.stop(stop_timeout_s=0.2)  # must cancel, not wait an hour
        assert asyncio.get_running_loop().time() - start < 5

    asyncio.run(run())


def test_stop_never_raises_when_poll_task_cancelled_externally(
    tmp_path: Path,
) -> None:
    """Chunk-2 verification finding 1: a framework all-tasks sweep may cancel a poll task before stop(); the resulting CancelledError out of the shield must not escape stop()."""

    async def run() -> None:
        hang = asyncio.Event()

        class HangingChannel(FakeChannel):
            async def exec(self, *args: Any, **kwargs: Any) -> ExecOutcome:
                hang.set()
                await asyncio.sleep(3600)
                raise AssertionError("unreachable")

        poller, _, _ = make_poller(
            tmp_path, HangingChannel(), [journal_spec(poll_s=0.01)]
        )
        await poller.start()
        await asyncio.wait_for(hang.wait(), timeout=5)
        for task in asyncio.all_tasks():
            if task.get_name().startswith("telemetry-"):
                task.cancel()  # the outside actor
        await asyncio.sleep(0)  # let the cancellation land
        await poller.stop(stop_timeout_s=1.0)  # must not raise

    asyncio.run(run())


def test_stop_cancelled_itself_still_propagates(tmp_path: Path) -> None:
    """The dual of the external-cancellation fix: cancelling stop() is the CALLER's cancellation and must propagate, not be eaten by the task.cancelled() check."""

    async def run() -> None:
        hang = asyncio.Event()

        class HangingChannel(FakeChannel):
            async def exec(self, *args: Any, **kwargs: Any) -> ExecOutcome:
                hang.set()
                await asyncio.sleep(3600)
                raise AssertionError("unreachable")

        poller, _, _ = make_poller(
            tmp_path, HangingChannel(), [journal_spec(poll_s=0.01)]
        )
        await poller.start()
        await asyncio.wait_for(hang.wait(), timeout=5)
        stopping = asyncio.create_task(poller.stop(stop_timeout_s=30.0))
        await asyncio.sleep(0.05)  # stop() is now awaiting the hung task
        stopping.cancel()
        with pytest.raises(asyncio.CancelledError):
            await stopping
        # leave no hung poll task behind
        await poller.stop(stop_timeout_s=0.2)

    asyncio.run(run())


def test_poll_against_sealed_writer_never_raises(tmp_path: Path) -> None:
    async def run() -> None:
        channel = FakeChannel()
        channel.exec_script = [exec_ok(b"evt\n-- cursor: c1\n")]
        poller, writer, _ = make_poller(tmp_path, channel, [journal_spec()])
        await writer.seal()
        await poller.poll_once("journal")  # guarded: logged, never raised

    asyncio.run(run())


# -- spec validation --------------------------------------------------------------


def test_spec_validation_table() -> None:
    with pytest.raises(ValueError, match="exactly one argument"):
        CommandSource(
            command=["journalctl"], bootstrap=["journalctl"], cursor_pattern="(x)"
        )
    with pytest.raises(ValueError, match="exactly one argument"):
        CommandSource(
            command=[f"a{CURSOR_PLACEHOLDER}", f"b{CURSOR_PLACEHOLDER}"],
            bootstrap=["a"],
            cursor_pattern="(x)",
        )
    with pytest.raises(ValueError, match="must not reference"):
        CommandSource(
            command=[f"a{CURSOR_PLACEHOLDER}"],
            bootstrap=[f"b{CURSOR_PLACEHOLDER}"],
            cursor_pattern="(x)",
        )
    with pytest.raises(ValueError, match="capture group"):
        CommandSource(
            command=[f"a{CURSOR_PLACEHOLDER}"], bootstrap=["a"], cursor_pattern="x"
        )
    with pytest.raises(ValueError):
        CollectorSpec(name="Bad Name", guest="db", source=FileSource(path="/l"))
    with pytest.raises(ValueError, match="unique"):
        TelemetryPoller(
            FakeChannel(),  # type: ignore[arg-type]
            EvidenceWriter(LocalDirSink(Path("/tmp/unused")), writer="driver"),
            [file_spec(), file_spec()],
        )

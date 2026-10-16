"""Host-side evidence capture: the streamer that turns range-container observers into chained evidence.

The capture sidecar (`supervisor.py`) rotates per-bridge pcap chunks onto its private volume; serial consoles land in the range container's `/scratch/console/`; `up()`'s stage log mirrors through `on_stage`. This module ships all of it into an `EvidenceWriter` as the record's streams: `pcap/<segment>` (chunk files, in rotation order), `capture-stderr/<segment>` (tcpdump's own output, which carries the kernel-drop summaries), `console/<guest>` (tailed continuously, not only on failure), `stages` and `verify` (stage events with host emit clocks, one side of the clock-offset pairs), `heartbeat` (capture liveness and watermarks, the completeness machinery the `detection` goal demands of scenario collectors applied to our own), and `clock` (dual-clock readings with wall-jump anomalies).

Evidence never destabilizes the sample it observes: every cycle step is guarded, tap failures count into the heartbeat rather than raising, and loss is always explicit as in-chain gap records (`capture-cap`, `capture-restart`, `capture-dead`, `kernel-drops`, `capture-unreachable`, `console-truncated`). The transport is a `CaptureTap`: `ComposeTap` reaches the live project through `docker compose` exec/cp (the console path reuses the `compose cp` precedent from `up()`), and tests substitute a directory-backed tap.
"""

import asyncio
import base64
import json
import logging
import re
import shlex
import subprocess
import tempfile
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Protocol, cast

from .._runtime.up import run_command
from .manifest import ClockSpan, ClockStamp, clock_now
from .sink import EvidenceWriter
from .supervisor import STATUS_FILENAME, STOP_FILENAME

logger = logging.getLogger(__name__)

STDERR_NAME = "stderr.log"

_PCAP_NAME = re.compile(r"^g(\d+)\.pcap(\d*)$")

CLAIMED_SUFFIX = ".shipped"
"""Appended by `claim_file` before a chunk ships (B13): the supervisor's chunk regex anchors at `.pcap<N>$`, so a claimed file vanishes from its cap accounting and `enforce_cap` can never unlink shipped bytes and report them as `capture-cap` loss. Claimed files are the streamer's to remove; their claim window is one cycle (removal retried on failure)."""

_CLAIMED_NAME = re.compile(r"^g(\d+)\.pcap(\d*)\.shipped$")

CLAIMED_PENDING_LIMIT = 8
"""New claims pause while this many claimed files await removal in a segment (review finding on B13): claimed files sit outside the sidecar's disk cap, so a persistently failing removal must not convert the whole volume into cap-invisible files; the bound caps the excess at a few chunks while removal retries, visible as tap errors in the heartbeat."""

WALL_JUMP_THRESHOLD_S = 0.5
"""A wall-vs-monotonic delta divergence beyond this is recorded as a `wall-jump` anomaly in the `clock` stream."""


class CaptureTap(Protocol):
    """Synchronous access to one range's capture volume and console files.

    Methods raise `OSError`/`RuntimeError` on failure; the streamer guards every call and folds failures into heartbeats, never into the sample lifecycle. Paths are relative to the capture volume root. The tail reads return `(total size, bytes from offset)` so growing files ship as deltas rather than being re-fetched whole every poll.
    """

    def read_status(self) -> bytes: ...
    def list_segment_files(self, segment: str) -> list[str]: ...
    def read_file(self, relpath: str) -> bytes: ...
    def read_tail(self, relpath: str, offset: int) -> tuple[int, bytes]: ...
    def claim_file(self, relpath: str) -> None: ...
    def remove_file(self, relpath: str) -> None: ...
    def request_stop(self) -> None: ...
    def read_console(self, guest: str, offset: int) -> tuple[int, bytes]: ...


Runner = Callable[..., "subprocess.CompletedProcess[str]"]
"""`up.py`'s runner shape: `run(argv)` with captured text output."""


class ComposeTap:
    """A `CaptureTap` over the live compose project (exec and cp against the `capture` and `range` services)."""

    def __init__(
        self, project: str, bundle: Path, runner: Runner | None = None
    ) -> None:
        self._project = project
        self._bundle = bundle
        self._run = runner or run_command

    def _argv(self, *args: str) -> list[str]:
        return [
            "docker",
            "compose",
            "--project-name",
            self._project,
            "--project-directory",
            str(self._bundle),
            *args,
        ]

    def _exec(self, service: str, script: str) -> str:
        result = self._run(self._argv("exec", "-T", service, "sh", "-c", script))
        if result.returncode != 0:
            raise RuntimeError(
                f"compose exec in {service!r} failed: {result.stderr.strip()[-300:]}"
            )
        return result.stdout

    def _cp_bytes(self, source: str) -> bytes:
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "object"
            result = self._run(self._argv("cp", source, str(target)))
            if result.returncode != 0:
                raise RuntimeError(
                    f"compose cp {source} failed: {result.stderr.strip()[-300:]}"
                )
            return target.read_bytes()

    def _tail(self, service: str, path: str, offset: int) -> tuple[int, bytes]:
        quoted = shlex.quote(path)
        out = self._exec(
            service,
            f"wc -c < {quoted} && tail -c +{offset + 1} {quoted} | base64",
        )
        head, _, rest = out.partition("\n")
        return int(head.strip()), base64.b64decode(rest)

    def read_status(self) -> bytes:
        return self._cp_bytes(f"capture:/capture/{STATUS_FILENAME}")

    def list_segment_files(self, segment: str) -> list[str]:
        quoted = shlex.quote(f"/capture/{segment}")
        out = self._exec(
            "capture",
            f'find {quoted} -maxdepth 1 -type f -name "g*.pcap*" -printf "%f\\n"',
        )
        return [line for line in out.splitlines() if line.strip()]

    def read_file(self, relpath: str) -> bytes:
        return self._cp_bytes(f"capture:/capture/{relpath}")

    def read_tail(self, relpath: str, offset: int) -> tuple[int, bytes]:
        return self._tail("capture", f"/capture/{relpath}", offset)

    def claim_file(self, relpath: str) -> None:
        source = shlex.quote(f"/capture/{relpath}")
        target = shlex.quote(f"/capture/{relpath}{CLAIMED_SUFFIX}")
        self._exec("capture", f"mv -- {source} {target}")

    def remove_file(self, relpath: str) -> None:
        self._exec("capture", f"rm -f {shlex.quote(f'/capture/{relpath}')}")

    def request_stop(self) -> None:
        self._exec("capture", f"touch {shlex.quote(f'/capture/{STOP_FILENAME}')}")

    def read_console(self, guest: str, offset: int) -> tuple[int, bytes]:
        return self._tail("range", f"/scratch/console/{guest}.log", offset)


class LocalTap:
    """A directory-backed `CaptureTap` for tests: `root` plays the capture volume, `console_dir` the range's console directory."""

    def __init__(self, root: Path, console_dir: Path) -> None:
        self.root = root
        self.console_dir = console_dir

    def read_status(self) -> bytes:
        return (self.root / STATUS_FILENAME).read_bytes()

    def list_segment_files(self, segment: str) -> list[str]:
        directory = self.root / segment
        if not directory.is_dir():
            return []
        return [
            entry.name
            for entry in directory.iterdir()
            if entry.is_file()
            and (_PCAP_NAME.match(entry.name) or _CLAIMED_NAME.match(entry.name))
        ]

    def read_file(self, relpath: str) -> bytes:
        return (self.root / relpath).read_bytes()

    def read_tail(self, relpath: str, offset: int) -> tuple[int, bytes]:
        data = (self.root / relpath).read_bytes()
        return len(data), data[offset:]

    def claim_file(self, relpath: str) -> None:
        source = self.root / relpath
        source.rename(source.with_name(source.name + CLAIMED_SUFFIX))

    def remove_file(self, relpath: str) -> None:
        (self.root / relpath).unlink(missing_ok=True)

    def request_stop(self) -> None:
        (self.root / STOP_FILENAME).touch()

    def read_console(self, guest: str, offset: int) -> tuple[int, bytes]:
        data = (self.console_dir / f"{guest}.log").read_bytes()
        return len(data), data[offset:]


class StageRecorder:
    """An `on_stage` adapter: buffers stage events with host emit clocks for the streamer to drain.

    `on_stage` is called synchronously from `up()`'s thread; the deque is the thread boundary (append and popleft are atomic). Events land in the `stages` stream; `readiness` and `ready` events additionally land in `verify`. The emit clock on each event is one side of the clock-offset pairs (`evidence-v1.md`): a driver on another machine records its receive clock for the same stage report.
    """

    VERIFY_STAGES = frozenset({"readiness", "ready"})

    def __init__(self, clock: Callable[[], ClockStamp] = clock_now) -> None:
        self._clock = clock
        self._events: deque[dict[str, Any]] = deque()

    def on_stage(self, stage: str, status: str, fields: dict[str, Any]) -> None:
        """The `up(on_stage=...)` callback; never raises."""
        try:
            stamp = self._clock()
            self._events.append(
                {
                    "wall": stamp.wall,
                    "monotonic": stamp.monotonic,
                    "stage": stage,
                    "status": status,
                    "fields": fields,
                }
            )
        except Exception:  # never alter up()'s outcome
            logger.exception("stage recorder failed (event dropped)")

    def drain(self) -> tuple[bytes, bytes]:
        """All buffered events as (`stages` payload, `verify` payload) JSON lines; empty bytes mean nothing new."""
        events: list[dict[str, Any]] = []
        while self._events:
            events.append(self._events.popleft())
        if not events:
            return b"", b""
        stages = json_lines(events)
        verify = json_lines(
            [event for event in events if event["stage"] in self.VERIFY_STAGES]
        )
        return stages, verify


def json_lines(records: list[dict[str, Any]]) -> bytes:
    """Serialize records as JSONL for the in-stream record streams (`stages`, `heartbeat`, `clock`, `telemetry-meta/*`)."""
    if not records:
        return b""
    return (
        "\n".join(json.dumps(record, sort_keys=True) for record in records) + "\n"
    ).encode()


def _status_segments(status: dict[str, Any] | None) -> dict[str, dict[str, Any]]:
    """The status report's per-segment entries, shape-checked (the supervisor is trusted, but a half-written or stale file must not crash a cycle)."""
    if status is None:
        return {}
    raw: object = status.get("segments")
    if not isinstance(raw, dict):
        return {}
    entries: dict[str, dict[str, Any]] = {}
    for key, value in cast(dict[Any, Any], raw).items():
        if isinstance(key, str) and isinstance(value, dict):
            entries[key] = cast(dict[str, Any], value)
    return entries


@dataclass
class _SegmentView:
    shipped: set[str] = field(default_factory=set[str])
    shipped_chunks: int = 0
    stderr_offset: int = 0
    restarts: int = 0
    dropped_bytes: int = 0
    kernel_drops: int = 0
    dead_reported: bool = False
    unreachable_reported: bool = False
    watermark_wall: float | None = None


class CaptureStreamer:
    """Ships capture, console, stage, heartbeat, and clock evidence into one host-side `EvidenceWriter`.

    `start()` launches the poll loop; `stop()` asks the sidecar to stop, waits for its final status, runs a last harvesting cycle, and returns. The caller seals the writer afterwards (sealing is the sample lifecycle's job, not the streamer's). Nothing in the loop raises: failures are logged, counted into heartbeats, and surfaced as gap records.
    """

    def __init__(
        self,
        writer: EvidenceWriter,
        tap: CaptureTap,
        *,
        segments: list[str],
        console_guests: list[str],
        stage_recorder: StageRecorder | None = None,
        poll_s: float = 1.0,
        heartbeat_s: float = 5.0,
        clock: Callable[[], ClockStamp] = clock_now,
    ) -> None:
        self._writer = writer
        self._tap = tap
        self._segments = {name: _SegmentView() for name in segments}
        self._consoles: dict[str, int] = {guest: 0 for guest in console_guests}
        self._recorder = stage_recorder
        self._poll_s = poll_s
        self._heartbeat_s = heartbeat_s
        self._clock = clock
        self._task: asyncio.Task[None] | None = None
        self._stopping = asyncio.Event()
        self._tap_errors = 0
        self._last_cycle: ClockStamp | None = None
        self._last_heartbeat: float | None = None

    async def start(self) -> None:
        """Begin polling; idempotent."""
        if self._task is None:
            self._task = asyncio.create_task(self._run(), name="evidence-capture")

    async def stop(self, *, stop_timeout_s: float = 15.0) -> None:
        """Stop the sidecar, harvest everything still on the volume, and end the loop.

        Returns with the writer flushed as far as the sink allowed; the caller seals. A sidecar that cannot be reached leaves `capture-unreachable` gaps on its segments rather than an error.
        """
        self._stopping.set()
        if self._task is not None:
            await self._task
            self._task = None
        stopped = await self._request_and_await_stop(stop_timeout_s)
        if not stopped:
            for segment, view in self._segments.items():
                if not view.unreachable_reported:
                    view.unreachable_reported = True
                    # guarded like every other writer touch: stop() is the
                    # teardown call and must never raise, even against a
                    # writer someone already sealed
                    await self._guard(
                        "unreachable-gap",
                        self._writer.gap(
                            f"pcap/{segment}", cause="capture-unreachable"
                        ),
                    )
        await self._cycle(final=True, sidecar_stopped=stopped)
        await self._guard("flush", self._writer.flush())

    async def poll_once(self) -> None:
        """One poll pass over every source (the loop's body); for tests and embedding."""
        await self._cycle()

    async def _run(self) -> None:
        while not self._stopping.is_set():
            await self._cycle()
            try:
                await asyncio.wait_for(self._stopping.wait(), timeout=self._poll_s)
            except asyncio.TimeoutError:
                pass

    async def _request_and_await_stop(self, timeout_s: float) -> bool:
        try:
            await asyncio.to_thread(self._tap.request_stop)
        except Exception as error:
            logger.warning("capture stop request failed: %s", error)
            self._tap_errors += 1
            return False
        deadline = asyncio.get_running_loop().time() + timeout_s
        while asyncio.get_running_loop().time() < deadline:
            status = await self._read_status()
            if status is not None and status.get("stopped") is True:
                return True
            await asyncio.sleep(0.2)
        logger.warning("capture sidecar did not report stopped within %.1fs", timeout_s)
        return False

    # one cycle ---------------------------------------------------------------

    async def _cycle(self, final: bool = False, sidecar_stopped: bool = False) -> None:
        now = self._clock()
        span = ClockSpan(start=self._last_cycle or now, end=now)
        status = await self._read_status()
        if status is not None:
            await self._guard("status-deltas", self._status_deltas(status))
        await self._guard(
            "pcap", self._ship_pcap(status, span, ship_all=final and sidecar_stopped)
        )
        await self._guard("stderr", self._ship_stderr(span))
        await self._guard("consoles", self._ship_consoles(span))
        await self._guard("stages", self._ship_stages(span))
        await self._guard("clock", self._ship_clock(now))
        await self._guard("heartbeat", self._ship_heartbeat(status, now, final=final))
        await self._guard("flush", self._writer.flush())
        self._last_cycle = now

    async def _guard(self, step: str, awaitable: Any) -> None:
        try:
            await awaitable
        except Exception:
            self._tap_errors += 1
            logger.exception("evidence capture step %r failed (continuing)", step)

    async def _read_status(self) -> dict[str, Any] | None:
        try:
            raw = await asyncio.to_thread(self._tap.read_status)
            parsed: object = json.loads(raw)
            if not isinstance(parsed, dict):
                raise ValueError("status is not an object")
            return cast(dict[str, Any], parsed)
        except Exception as error:
            self._tap_errors += 1
            logger.debug("capture status unavailable: %s", error)
            return None

    async def _status_deltas(self, status: dict[str, Any]) -> None:
        """Turn supervisor-reported loss and lifecycle changes into gap records, once each."""
        segments = _status_segments(status)
        for segment, view in self._segments.items():
            entry = segments.get(segment)
            if entry is None:
                continue
            stream = f"pcap/{segment}"
            dropped = int(entry.get("dropped_bytes", 0))
            if dropped > view.dropped_bytes:
                await self._writer.gap(
                    stream, cause="capture-cap", dropped=dropped - view.dropped_bytes
                )
                view.dropped_bytes = dropped
            restarts = int(entry.get("restarts", 0))
            if restarts > view.restarts:
                await self._writer.gap(stream, cause="capture-restart")
                view.restarts = restarts
            drops = int(entry.get("kernel_drops", 0))
            if drops > view.kernel_drops:
                await self._writer.gap(stream, cause="kernel-drops")
                view.kernel_drops = drops
            if entry.get("state") == "exhausted" and not view.dead_reported:
                await self._writer.gap(stream, cause="capture-dead")
                view.dead_reported = True

    async def _ship_pcap(
        self, status: dict[str, Any] | None, span: ClockSpan, *, ship_all: bool
    ) -> None:
        """Claim, ship, and remove completed pcap chunks.

        A completed chunk is CLAIMED (renamed with `CLAIMED_SUFFIX`) before it ships, which removes it from the sidecar's cap accounting, so `enforce_cap` can never unlink shipped bytes and report them as `capture-cap` loss (B13). A claim that fails means the sidecar won the race and the loss stays honestly the sidecar's to report. Claimed files found at startup (a streamer that died between claim and removal) are shipped or removed regardless of the status claim: the claim itself froze them as completed.
        """
        segments = _status_segments(status)
        for segment, view in self._segments.items():
            entry = segments.get(segment)
            ship_bound = self._ship_bound(entry, ship_all=ship_all)
            try:
                names = await asyncio.to_thread(self._tap.list_segment_files, segment)
            except Exception as error:
                self._tap_errors += 1
                logger.debug("pcap listing failed for %s: %s", segment, error)
                continue
            ordered: list[tuple[str, int, int, bool]] = []
            for listed in names:
                match = _PCAP_NAME.match(listed)
                if match:
                    ordered.append(
                        (listed, int(match.group(1)), int(match.group(2) or 0), False)
                    )
                    continue
                match = _CLAIMED_NAME.match(listed)
                if match:
                    ordered.append(
                        (listed, int(match.group(1)), int(match.group(2) or 0), True)
                    )
            ordered.sort(key=lambda item: (item[1], item[2]))
            view.shipped &= {name for name, _, _, _ in ordered}
            claimed_pending = sum(1 for _, _, _, is_claimed in ordered if is_claimed)
            for name, generation, index, claimed in ordered:
                if not claimed:
                    if ship_bound is None or (generation, index) >= ship_bound:
                        # the declared active or newer (still being written), or
                        # no trustworthy claim about which file is being written:
                        # shipping a half-written chunk would be silent loss
                        continue
                    if claimed_pending >= CLAIMED_PENDING_LIMIT:
                        # removals are failing: pause new claims so cap-invisible
                        # files stay bounded; this cycle still retries removals
                        continue
                    try:
                        await asyncio.to_thread(
                            self._tap.claim_file, f"{segment}/{name}"
                        )
                    except Exception as error:
                        # the sidecar's enforce_cap won the race: the drop will
                        # surface honestly in its dropped counters
                        self._tap_errors += 1
                        logger.debug(
                            "pcap claim failed for %s/%s: %s", segment, name, error
                        )
                        continue
                    name = f"{name}{CLAIMED_SUFFIX}"
                    claimed_pending += 1
                relpath = f"{segment}/{name}"
                if name in view.shipped:
                    # shipped but the earlier remove failed: retry; the claim
                    # keeps these bytes out of the sidecar's cap accounting
                    try:
                        await asyncio.to_thread(self._tap.remove_file, relpath)
                        view.shipped.discard(name)
                        claimed_pending -= 1
                    except Exception:
                        self._tap_errors += 1
                    continue
                try:
                    data = await asyncio.to_thread(self._tap.read_file, relpath)
                except Exception as error:
                    self._tap_errors += 1
                    logger.debug("pcap read failed for %s: %s", relpath, error)
                    continue
                await self._writer.append(f"pcap/{segment}", data, span=span)
                view.shipped.add(name)
                view.shipped_chunks += 1
                view.watermark_wall = span.end.wall
                try:
                    await asyncio.to_thread(self._tap.remove_file, relpath)
                    view.shipped.discard(name)
                    claimed_pending -= 1
                except Exception as error:
                    # shipped but not removed: the shipped set suppresses a
                    # double-ship; the next cycle retries the removal
                    self._tap_errors += 1
                    logger.debug("pcap remove failed for %s: %s", relpath, error)

    @staticmethod
    def _ship_bound(
        entry: dict[str, Any] | None, *, ship_all: bool
    ) -> tuple[int, int] | None:
        """Which rotation ranks are safe to ship: everything strictly below the bound.

        The declared active file was being written when the supervisor last reported, so anything older is completed forever (rotation only moves forward); anything at or past it may still be open. States with no writer running (`exhausted`, `stopped`, `restarting`) and a confirmed sidecar stop ship everything. No status entry, or `running` without a declared active file, ships nothing: `None`.
        """
        unbounded = (1 << 31, 0)
        if ship_all:
            return unbounded
        if entry is None:
            return None
        state = entry.get("state")
        if state in ("exhausted", "stopped", "restarting"):
            return unbounded
        active = entry.get("active")
        if not isinstance(active, str):
            return None
        match = _PCAP_NAME.match(active.rsplit("/", 1)[-1])
        if match is None:
            return None
        return (int(match.group(1)), int(match.group(2) or 0))

    async def _ship_stderr(self, span: ClockSpan) -> None:
        for segment, view in self._segments.items():
            try:
                size, delta = await asyncio.to_thread(
                    self._tap.read_tail, f"{segment}/{STDERR_NAME}", view.stderr_offset
                )
            except Exception:
                continue  # no stderr yet is routine
            if size < view.stderr_offset:
                view.stderr_offset = 0  # rewritten: re-ship from the start
                continue
            if delta:
                await self._writer.append(f"capture-stderr/{segment}", delta, span=span)
                view.stderr_offset += len(delta)

    async def _ship_consoles(self, span: ClockSpan) -> None:
        for guest, offset in self._consoles.items():
            try:
                size, delta = await asyncio.to_thread(
                    self._tap.read_console, guest, offset
                )
            except Exception:
                continue  # console file appears once the guest defines
            if size < offset:
                await self._writer.gap(f"console/{guest}", cause="console-truncated")
                self._consoles[guest] = 0
                continue
            if delta:
                await self._writer.append(f"console/{guest}", delta, span=span)
                self._consoles[guest] = offset + len(delta)

    async def _ship_stages(self, span: ClockSpan) -> None:
        if self._recorder is None:
            return
        stages, verify = self._recorder.drain()
        if stages:
            await self._writer.append("stages", stages, span=span)
        if verify:
            await self._writer.append("verify", verify, span=span)

    async def _ship_clock(self, now: ClockStamp) -> None:
        records: list[dict[str, Any]] = []
        last = self._last_cycle
        if (
            last is not None
            and last.monotonic is not None
            and now.monotonic is not None
        ):
            drift = abs((now.wall - last.wall) - (now.monotonic - last.monotonic))
            if drift > WALL_JUMP_THRESHOLD_S:
                records.append(
                    {
                        "kind": "wall-jump",
                        "wall": now.wall,
                        "monotonic": now.monotonic,
                        "drift_s": drift,
                    }
                )
        if self._heartbeat_due(now):
            records.append(
                {"kind": "clock", "wall": now.wall, "monotonic": now.monotonic}
            )
        if records:
            await self._writer.append("clock", json_lines(records))

    def _heartbeat_due(self, now: ClockStamp) -> bool:
        # scheduled on the monotonic clock: a backwards wall jump (the very
        # anomaly the clock stream records) must not silence the liveness
        # stream until the wall catches up
        if self._last_heartbeat is None:
            return True
        basis = now.monotonic if now.monotonic is not None else now.wall
        return basis - self._last_heartbeat >= self._heartbeat_s

    async def _ship_heartbeat(
        self, status: dict[str, Any] | None, now: ClockStamp, *, final: bool
    ) -> None:
        if not final and not self._heartbeat_due(now):
            return
        self._last_heartbeat = now.monotonic if now.monotonic is not None else now.wall
        records: list[dict[str, Any]] = [
            {
                "source": "streamer",
                "wall": now.wall,
                "tap_errors": self._tap_errors,
                "status_available": status is not None,
                "final": final,
            }
        ]
        segments = _status_segments(status)
        for segment, view in self._segments.items():
            entry = segments.get(segment)
            records.append(
                {
                    "source": f"pcap/{segment}",
                    "wall": now.wall,
                    "state": None if entry is None else entry.get("state"),
                    "restarts": view.restarts,
                    "kernel_drops": view.kernel_drops,
                    "shipped_chunks": view.shipped_chunks,
                    "watermark_wall": view.watermark_wall,
                }
            )
        for guest, offset in self._consoles.items():
            records.append(
                {"source": f"console/{guest}", "wall": now.wall, "bytes": offset}
            )
        await self._writer.append("heartbeat", json_lines(records))

"""The exec-witness poller (execve-witness-v1): per-guest exec events shipped as evidence.

Polls the daemon's `exec_events` verb for every Linux guest and ships events to `exec/<guest>` (JSONL, one chunk per non-empty poll) with coverage records on `exec-meta/<guest>`, so "no events" vs "witness dead or unsupported" is decidable from the sealed record alone. The FIRST poll arms the in-guest subscriber (lazy-arm): the host-side kill switch (`INSPECT_RANGES_EXEC_WITNESS=0`, read by the provider, not here) means the poller is never constructed and the daemon never arms, no rebake involved.

Loss is never silent and maps to in-chain gaps: a reply whose first event's seq is past the cursor means the ring overwrote (`exec-ring-overflow`, with the lost count), a `drops` delta means kernel-side loss (`exec-subscriber-loss`), and a transport failure is the existing `poll-failed`. A typed refusal (`ENOSYS` from a connector-less kernel, `EPROTO` from a daemon without the verb — the Windows daemon's unknown-kind fallback) writes one terminal `unsupported` record, the DECLARED CAPABILITY DROP, and ends that guest's loop; Windows guests get theirs at `start()` without ever being polled.

Record-only for shipped scoring: no shipped goal and no `corroborate()` reads these streams; custom goal types may read them through the oracle's `exec_events()` (2026-10-25), and the stream remains forensics for reviewers. Guest-tier trust, like telemetry export: pre-compromise events are immutable once streamed, and a root attacker can starve the daemon from that moment (visible as poll failures, never silent).
"""

import asyncio
import json
import logging
import time
from typing import Callable, Coroutine

from .._channel.channel import GuestError, RangeChannel
from .capture import json_lines
from .manifest import ClockSpan, ClockStamp, clock_now
from .sink import EvidenceWriter

logger = logging.getLogger("inspect_ranges.evidence")

EXEC_WITNESS_POLL_S = 2.0
"""Per-guest poll cadence."""

EXEC_WITNESS_DRAIN_BURST = 8
"""Max immediate re-polls while replies pack full: a storm drains fast but can never starve other channel users."""

EXEC_META_FLUSH_S = 15.0
"""Meta-record batching cadence (the telemetry-meta pattern): routine per-poll coverage records batch; terminal records flush immediately."""


class _GuestState:
    def __init__(self) -> None:
        self.cursor = 0
        self.drops_seen = 0
        self.terminal = False
        self.failing = False
        self.meta: list[dict[str, object]] = []
        self.meta_last_flush = time.monotonic()


class ExecWitnessPoller:
    """Polls every Linux guest's exec-witness ring and ships events plus coverage records.

    Deliberately not a `TelemetryPoller` extension: units are guests, not declared collectors; records are coverage watermarks and declared drops, not deltas with cursor extraction; and none of the watermark/SignalWatch semantics apply. The lifecycle contract is the same: `start()` spawns one task per Linux guest, `stop()` is teardown-bound and never raises, `poll_once()` is the test and embed entry point.
    """

    def __init__(
        self,
        channel: RangeChannel,
        writer: EvidenceWriter,
        linux_guests: list[str],
        windows_guests: list[str],
        *,
        poll_s: float = EXEC_WITNESS_POLL_S,
        meta_flush_s: float = EXEC_META_FLUSH_S,
        clock: Callable[[], ClockStamp] = clock_now,
    ) -> None:
        names = [*linux_guests, *windows_guests]
        if len(set(names)) != len(names):
            raise ValueError("guest names must be unique")
        self._channel = channel
        self._writer = writer
        self._linux = list(linux_guests)
        self._windows = list(windows_guests)
        self._poll_s = poll_s
        self._meta_flush_s = meta_flush_s
        self._clock = clock
        self._states = {name: _GuestState() for name in self._linux}
        self._tasks: dict[str, asyncio.Task[None]] = {}
        self._stopping = asyncio.Event()

    def _span(self, start: ClockStamp | None = None) -> ClockSpan:
        now = self._clock()
        return ClockSpan(start=start or now, end=now)

    async def start(self) -> None:
        """Declare the Windows drops and begin polling every Linux guest; refuses restart after stop."""
        if self._stopping.is_set():
            raise RuntimeError("ExecWitnessPoller cannot restart after stop()")
        for name in self._windows:
            await self._declare_drop(name, errno=None, reason="os-windows", detail="")
        for name in self._linux:
            if name not in self._tasks:
                self._tasks[name] = asyncio.create_task(
                    self._run(name), name=f"exec-witness-{name}"
                )

    async def stop(self, *, stop_timeout_s: float = 20.0) -> None:
        """End the poll loops and flush; never raises (teardown-bound, the telemetry stop contract)."""
        self._stopping.set()
        deadline = asyncio.get_running_loop().time() + stop_timeout_s
        for task in self._tasks.values():
            remaining = max(deadline - asyncio.get_running_loop().time(), 0.1)
            try:
                await asyncio.wait_for(asyncio.shield(task), timeout=remaining)
            except asyncio.CancelledError:
                # externally-cancelled task: swallow (stop never raises);
                # stop() itself being cancelled must propagate (the telemetry
                # stop's two-cause discipline)
                if task.cancelled():
                    logger.warning(
                        "exec-witness task %s was cancelled externally before stop",
                        task.get_name(),
                    )
                    continue
                raise
            except asyncio.TimeoutError:
                logger.warning(
                    "exec-witness task %s did not stop within budget; cancelling",
                    task.get_name(),
                )
                task.cancel()
                await self._guard("cancel-task", self._await_task(task))
            except Exception:
                logger.exception("exec-witness task %s failed at stop", task.get_name())
        self._tasks.clear()
        for name in self._linux:
            await self._guard(f"meta-flush:{name}", self._flush_meta(name, force=True))
        await self._guard("flush", self._writer.flush())

    async def _await_task(self, task: "asyncio.Task[None]") -> None:
        try:
            await task
        except (asyncio.CancelledError, Exception):  # noqa: PERF203
            return

    async def _guard(self, label: str, action: "Coroutine[None, None, object]") -> None:
        try:
            await action
        except Exception:
            logger.exception("exec-witness %s failed (ignored at stop)", label)

    async def _run(self, name: str) -> None:
        while not self._stopping.is_set():
            await self.poll_once(name)
            if self._states[name].terminal:
                return
            try:
                await asyncio.wait_for(self._stopping.wait(), timeout=self._poll_s)
            except asyncio.TimeoutError:
                continue

    async def poll_once(self, name: str) -> None:
        """One guarded poll cycle for one guest (with drain bursts); never raises."""
        state = self._states[name]
        if state.terminal:
            return
        start = self._clock()
        for _ in range(EXEC_WITNESS_DRAIN_BURST):
            try:
                reply = await self._channel.exec_events(
                    name, since_seq=state.cursor, max_events=256
                )
            except GuestError as error:
                if error.errno in ("ENOSYS", "EPROTO"):
                    # the one declared-drop path: a daemon that will never
                    # serve the verb (connector-less kernel, pre-3.3 build)
                    await self._declare_drop(
                        name,
                        errno=error.errno,
                        reason="daemon-unsupported",
                        detail=str(error)[:300],
                    )
                    state.terminal = True
                    return
                await self._poll_failed(name, state, start, error)
                return
            except Exception as error:  # transport failure: observation hole
                await self._poll_failed(name, state, start, error)
                return
            if state.failing:
                state.failing = False
                self._meta(name, {"outcome": "recovered"})
            if reply.next_seq < state.cursor:
                # the daemon restarted: the seq space reset under us (the
                # packer reports its true head, never clamped up to the
                # cursor), so an unknown number of post-restart events are
                # gone and "quiet guest" must not be the record's story
                await self._writer.gap(
                    f"exec/{name}",
                    span=self._span(start),
                    cause="exec-witness-restart",
                )
                self._meta(
                    name,
                    {
                        "outcome": "restarted",
                        "host_ts": time.time(),
                        "cursor": state.cursor,
                        "next_seq": reply.next_seq,
                    },
                )
                state.cursor = reply.next_seq
                state.drops_seen = 0
                await self._flush_meta(name, force=True)
                continue
            if reply.events:
                lost = reply.events[0].seq - state.cursor
                if lost > 0:
                    await self._writer.gap(
                        f"exec/{name}",
                        span=self._span(start),
                        cause="exec-ring-overflow",
                        dropped=lost,
                    )
                lines = json_lines(
                    [
                        event.model_dump(mode="json", exclude_none=True)
                        for event in reply.events
                    ]
                )
                await self._writer.append(f"exec/{name}", lines, span=self._span(start))
            drops_delta = reply.drops - state.drops_seen
            if drops_delta > 0:
                await self._writer.gap(
                    f"exec/{name}",
                    span=self._span(start),
                    cause="exec-subscriber-loss",
                    dropped=drops_delta,
                )
            state.drops_seen = reply.drops
            # the daemon clips replies on its BYTE budget long before the
            # 256-event cap (typical argv packs ~10-160 events per page), so
            # "any events at all" is the only honest more-may-remain signal;
            # the cost is one trailing empty poll per active cycle (review
            # round 1, finding 3)
            maybe_more = len(reply.events) > 0
            state.cursor = reply.next_seq
            self._meta(
                name,
                {
                    "outcome": "ok",
                    "host_ts": time.time(),
                    "next_seq": reply.next_seq,
                    "events": len(reply.events),
                    "drops": reply.drops,
                    "restarts": reply.restarts,
                },
            )
            if not maybe_more:
                break
        await self._flush_meta(name)

    async def _poll_failed(
        self, name: str, state: _GuestState, start: ClockStamp, error: Exception
    ) -> None:
        self._meta(
            name,
            {
                "outcome": "error",
                "host_ts": time.time(),
                "error": f"{type(error).__name__}: {error}"[:300],
            },
        )
        if not state.failing:
            state.failing = True
            await self._writer.gap(
                f"exec/{name}", span=self._span(start), cause="poll-failed"
            )
            logger.warning(
                "exec-witness poll failing (gap recorded): guest=%s error=%s",
                name,
                error,
            )
        await self._flush_meta(name, force=True)

    async def _declare_drop(
        self, name: str, *, errno: str | None, reason: str, detail: str
    ) -> None:
        """The declared capability drop: one terminal record on `exec-meta/<guest>`, flushed immediately."""
        record = {
            "outcome": "unsupported",
            "errno": errno,
            "reason": reason,
            "detail": detail,
            "host_ts": time.time(),
        }
        await self._writer.append(
            f"exec-meta/{name}", json_lines([record]), span=self._span()
        )
        logger.info(
            "exec witness declared drop: guest=%s reason=%s errno=%s",
            name,
            reason,
            errno,
        )

    def _meta(self, name: str, record: dict[str, object]) -> None:
        self._states[name].meta.append(record)

    async def _flush_meta(self, name: str, *, force: bool = False) -> None:
        state = self._states.get(name)
        if state is None or not state.meta:
            return
        if not force and time.monotonic() - state.meta_last_flush < self._meta_flush_s:
            return
        batch = state.meta
        state.meta = []
        state.meta_last_flush = time.monotonic()
        await self._writer.append(
            f"exec-meta/{name}", json_lines(batch), span=self._span()
        )


def exec_event_lines(chunk: bytes) -> list[dict[str, object]]:
    """Parse one `exec/<guest>` chunk back to event records (reader-side convenience, used by tests and tooling)."""
    return [json.loads(line) for line in chunk.decode().splitlines() if line.strip()]

"""In-guest telemetry export: a driver-side poller over existing channel verbs.

Scenario telemetry (journald, application logs, EDR event files) lives inside guests because defenders are supposed to see it; this module exports it to the evidence record by polling declared collectors through the existing channel verbs (`exec`, `read_file`) on a cadence, shipping each poll's delta to `telemetry/<collector>` with a per-poll watermark record in `telemetry-meta/<collector>`. No daemon or wire-schema changes: the guest side is untouched, and the export path is the vsock control plane, which nothing in-range can observe or firewall.

The assurance claim, stated honestly: export upgrades the timeline, not the source. Pre-compromise telemetry becomes immutable once streamed; producer silencing shows as a watermark stall (polls keep succeeding while the watermark stays flat, visible in the meta stream); poll failure (daemon down, guest paused) shows as poll-gap records. The read remains T3 at origin, and the `detection` goal's completeness precondition is what consumes the watermarks (evidence-v1.md).

Reads only: poll argv is built exclusively from the declared spec literals plus the watermark extracted from the guest's own prior output; no environment, no stdin, never `write_file`, so no scoring material can transit guest-ward through this module.

Watermark semantics by source kind. A `command` source owns true deltas when the tool supports a cursor (`journalctl --after-cursor=<c> --show-cursor`): the cursor is extracted from each poll's output and substituted into the next poll's argv. Cursors are opaque, so a regression there is not detectable driver-side; tampering with the journal surfaces as command failure or duplicate output, and the timeline claim is unaffected (what was shipped before the tamper is already immutable). A `file` source has ordered watermarks (byte offsets) and detects regression (truncation or rewrite) explicitly, but pays for it: `read_file` has no offset verb, so each poll reads a capped snapshot and the delta is sliced driver-side; a file that grows past the cap cannot be paginated and is recorded as an explicit gap (use a cursor-bearing `command` source for high-volume logs).
"""

import asyncio
import logging
import re
from typing import Annotated, Callable, Coroutine, Literal

from pydantic import Field, StringConstraints, model_validator

from .._channel.channel import (
    FileLimitExceeded,
    GuestError,
    RangeChannel,
    request_id,
)
from .._channel.protocol import DEFAULT_BULK_CAP, Budget, ExecRequest
from .capture import json_lines
from .manifest import ClockSpan, ClockStamp, EvidenceModel, clock_now
from .sink import EvidenceWriter

logger = logging.getLogger(__name__)

CURSOR_PLACEHOLDER = "{cursor}"
"""The substring in a command source's argv that each poll replaces with the current watermark."""

DEFAULT_MAX_POLL_BYTES = 1 << 20
"""Default per-poll output cap; oversize polls ship their capped prefix and record the loss explicitly."""

POLL_COMMAND_MS = 10_000
"""In-guest budget for one poll command (`Budget.command_ms`)."""

POLL_UNTIMED_BOUND_MS = 30_000
"""Outer per-poll budget across attempts (`Budget.untimed_bound_ms`)."""

CollectorName = Annotated[str, StringConstraints(pattern=r"^[a-z0-9][a-z0-9._-]*$")]
"""Collector names become the second stream segment (`telemetry/<name>`), so they carry the stream grammar."""


class CommandSource(EvidenceModel):
    r"""Poll a collector by running a declared command in the guest.

    `command` runs when a watermark exists and must carry `{cursor}` in exactly one argument; `bootstrap` runs first (and after an explicit re-bootstrap) and must not reference the cursor. `cursor_pattern` is a regex with exactly one capture group, searched over the poll's decoded output; the last match's group becomes the next watermark. Example (journald): bootstrap `journalctl -t app -n 100 --show-cursor -q`, command `journalctl -t app --after-cursor={cursor} --show-cursor -q`, pattern `-- cursor: (\\S+)`.
    """

    kind: Literal["command"] = "command"
    command: list[str] = Field(min_length=1)
    bootstrap: list[str] = Field(min_length=1)
    cursor_pattern: str
    user: str | None = None

    @model_validator(mode="after")
    def _check_shape(self) -> "CommandSource":
        holders = [arg for arg in self.command if CURSOR_PLACEHOLDER in arg]
        if len(holders) != 1:
            raise ValueError(
                f"command must carry {CURSOR_PLACEHOLDER!r} in exactly one argument"
            )
        if any(CURSOR_PLACEHOLDER in arg for arg in self.bootstrap):
            raise ValueError(f"bootstrap must not reference {CURSOR_PLACEHOLDER!r}")
        if re.compile(self.cursor_pattern).groups != 1:
            raise ValueError("cursor_pattern must have exactly one capture group")
        return self


class FileSource(EvidenceModel):
    """Poll a collector by reading a guest file; the watermark is a byte offset.

    Each poll reads a capped snapshot (`read_file` has no offset verb) and ships the bytes past the previous offset. A shrink is a watermark regression (recorded, re-shipped from the new start); growth past the cap cannot be paginated and is recorded as an explicit gap.
    """

    kind: Literal["file"] = "file"
    path: str = Field(min_length=1)


class CollectorSpec(EvidenceModel):
    """One declared telemetry collector: which guest, how to poll it, how often."""

    name: CollectorName
    guest: str = Field(min_length=1)
    source: CommandSource | FileSource = Field(discriminator="kind")
    poll_s: float = Field(default=2.0, gt=0)
    max_poll_bytes: int = Field(
        default=DEFAULT_MAX_POLL_BYTES, ge=4096, le=DEFAULT_BULK_CAP
    )


class _CollectorState:
    def __init__(self) -> None:
        self.cursor: str | None = None  # command-mode watermark
        self.offset = 0  # file-mode watermark
        self.failing = False  # a poll-failed gap has been recorded for this streak
        self.capped = False  # a poll-truncated gap has been recorded for this stall
        self.polls = 0
        self.errors = 0


class TelemetryPoller:
    """Polls declared collectors and ships deltas plus per-poll watermark records.

    One asyncio task per collector; `stop()` ends the loops and flushes, and never raises (it is teardown-bound, like `CaptureStreamer.stop`). Nothing in a poll cycle raises either: channel failures become poll-gap records, watermark anomalies become in-chain gaps plus meta records, and the writer's own discipline keeps backend trouble out of this path. The caller seals the writer afterwards; sealing is the sample lifecycle's job.
    """

    def __init__(
        self,
        channel: RangeChannel,
        writer: EvidenceWriter,
        collectors: list[CollectorSpec],
        *,
        clock: Callable[[], ClockStamp] = clock_now,
    ) -> None:
        names = [spec.name for spec in collectors]
        if len(set(names)) != len(names):
            raise ValueError("collector names must be unique")
        self._channel = channel
        self._writer = writer
        self._collectors = {spec.name: spec for spec in collectors}
        self._states = {spec.name: _CollectorState() for spec in collectors}
        self._clock = clock
        self._tasks: dict[str, asyncio.Task[None]] = {}
        self._stopping = asyncio.Event()

    async def start(self) -> None:
        """Begin polling every collector; idempotent."""
        for name in self._collectors:
            if name not in self._tasks:
                self._tasks[name] = asyncio.create_task(
                    self._run(name), name=f"telemetry-{name}"
                )

    async def stop(self) -> None:
        """End the poll loops and flush; never raises."""
        self._stopping.set()
        for task in self._tasks.values():
            await self._guard("await-task", self._await_task(task))
        self._tasks.clear()
        await self._guard("flush", self._writer.flush())

    async def poll_once(self, name: str) -> None:
        """One guarded poll cycle for one collector (the loop's body); for tests and embedding."""
        await self._guard(f"poll:{name}", self._poll(name))
        await self._guard("flush", self._writer.flush())

    # internal ----------------------------------------------------------------

    @staticmethod
    async def _await_task(task: "asyncio.Task[None]") -> None:
        await task

    async def _run(self, name: str) -> None:
        spec = self._collectors[name]
        while not self._stopping.is_set():
            await self._guard(f"poll:{name}", self._poll(name))
            await self._guard("flush", self._writer.flush())
            try:
                await asyncio.wait_for(self._stopping.wait(), timeout=spec.poll_s)
            except asyncio.TimeoutError:
                pass

    async def _guard(
        self, step: str, awaitable: Coroutine[object, object, object]
    ) -> None:
        try:
            await awaitable
        except Exception:
            logger.exception("telemetry step %r failed (continuing)", step)

    def _span(self, start: ClockStamp | None = None) -> ClockSpan:
        now = self._clock()
        return ClockSpan(start=start or now, end=now)

    async def _poll(self, name: str) -> None:
        spec = self._collectors[name]
        state = self._states[name]
        state.polls += 1
        start = self._clock()
        meta: dict[str, object] = {
            "kind": "poll",
            "collector": name,
            "guest": spec.guest,
            "wall": start.wall,
            "monotonic": start.monotonic,
            "poll": state.polls,
        }
        try:
            if isinstance(spec.source, CommandSource):
                await self._poll_command(spec, spec.source, state, meta)
            else:
                await self._poll_file(spec, spec.source, state, meta)
        except Exception as error:  # channel/transport failure: observation hole
            state.errors += 1
            meta["outcome"] = "error"
            meta["error"] = f"{type(error).__name__}: {error}"[:300]
            if not state.failing:
                state.failing = True
                await self._writer.gap(
                    f"telemetry/{name}", span=self._span(start), cause="poll-failed"
                )
                logger.warning(
                    "telemetry poll failing (gap recorded): collector=%s guest=%s error=%s",
                    name,
                    spec.guest,
                    error,
                )
        else:
            if state.failing:
                state.failing = False
                logger.info("telemetry poll recovered: collector=%s", name)
        meta["errors"] = state.errors
        await self._writer.append(
            f"telemetry-meta/{name}", json_lines([meta]), span=self._span(start)
        )

    async def _poll_command(
        self,
        spec: CollectorSpec,
        source: CommandSource,
        state: _CollectorState,
        meta: dict[str, object],
    ) -> None:
        if state.cursor is None:
            argv = list(source.bootstrap)
        else:
            argv = [
                arg.replace(CURSOR_PLACEHOLDER, state.cursor) for arg in source.command
            ]
        outcome = await self._channel.exec(
            spec.guest,
            ExecRequest(
                id=request_id(),
                cmd=argv,
                user=source.user,
                budget=Budget(
                    command_ms=POLL_COMMAND_MS,
                    untimed_bound_ms=POLL_UNTIMED_BOUND_MS,
                ),
            ),
        )
        meta["rc"] = outcome.rc
        meta["attempts"] = outcome.attempts
        if outcome.rc != 0:
            # the collector command itself failed (journald stopped, tool
            # missing): an observation failure, same family as channel loss
            raise RuntimeError(
                f"poll command rc={outcome.rc}: "
                + outcome.stderr[:200].decode("utf-8", errors="replace")
            )
        # the per-poll cap is enforced driver-side (`RangeChannel.exec` has no
        # per-call output cap), on top of whatever the daemon truncated
        truncated = (
            outcome.stdout_truncated or len(outcome.stdout) > spec.max_poll_bytes
        )
        data = outcome.stdout[: spec.max_poll_bytes]
        meta["bytes"] = len(data)
        meta["truncated"] = truncated
        if not data:
            meta["outcome"] = "quiet"
            meta["watermark"] = state.cursor
            meta["advanced"] = False
            return
        await self._writer.append(f"telemetry/{spec.name}", data, span=self._span())
        if truncated:
            # the tail (which carries the cursor) is gone: the loss is
            # explicit and the watermark re-bootstraps rather than livelocking
            # on the same window
            meta["outcome"] = "truncated"
            meta["watermark"] = None
            meta["advanced"] = False
            state.cursor = None
            await self._writer.gap(
                f"telemetry/{spec.name}", cause="poll-truncated", dropped=0
            )
            logger.warning(
                "telemetry poll truncated at %d bytes (gap recorded, re-bootstrap): collector=%s",
                spec.max_poll_bytes,
                spec.name,
            )
            return
        text = data.decode("utf-8", errors="replace")
        matches = list(re.finditer(source.cursor_pattern, text))
        if not matches:
            # output without a cursor: the declared pattern does not match the
            # tool's output; re-bootstrap so the poller never silently spins
            # on a stale cursor (duplicates stay visible as advanced=false)
            meta["outcome"] = "cursor-missing"
            meta["watermark"] = None
            meta["advanced"] = False
            state.cursor = None
            logger.warning(
                "telemetry cursor pattern matched nothing (re-bootstrap): collector=%s",
                spec.name,
            )
            return
        cursor = matches[-1].group(1)
        meta["outcome"] = "ok"
        meta["watermark"] = cursor
        meta["advanced"] = cursor != state.cursor
        state.cursor = cursor

    async def _poll_file(
        self,
        spec: CollectorSpec,
        source: FileSource,
        state: _CollectorState,
        meta: dict[str, object],
    ) -> None:
        truncated = False
        try:
            data = await self._channel.read_file(
                spec.guest, source.path, cap=spec.max_poll_bytes
            )
        except FileLimitExceeded as error:
            data = error.partial
            truncated = True
        except GuestError as error:
            if error.errno == "ENOENT":
                # the log appears once the producer starts; absence is quiet,
                # not an observation failure
                meta["outcome"] = "absent"
                meta["watermark"] = state.offset
                meta["advanced"] = False
                return
            raise
        meta["truncated"] = truncated
        size = len(data)
        if size < state.offset:
            # the file shrank: truncated or rewritten on the guest. The
            # watermark regression is recorded in-chain and shipping restarts
            # from the new content.
            await self._writer.gap(
                f"telemetry/{spec.name}", cause="watermark-regression", dropped=0
            )
            logger.warning(
                "telemetry watermark regression (gap recorded): collector=%s path=%s %d -> %d",
                spec.name,
                source.path,
                state.offset,
                size,
            )
            state.offset = 0
            state.capped = False
            meta["anomaly"] = "watermark-regression"
        delta = data[state.offset :]
        if delta:
            await self._writer.append(
                f"telemetry/{spec.name}", delta, span=self._span()
            )
            state.offset += len(delta)
            state.capped = False
            meta["outcome"] = "ok"
            meta["advanced"] = True
        elif truncated and state.offset >= size:
            # the file grew past the cap and read_file cannot paginate: the
            # unreachable tail is an explicit gap, recorded once per stall
            meta["outcome"] = "capped"
            meta["advanced"] = False
            if not state.capped:
                state.capped = True
                await self._writer.gap(
                    f"telemetry/{spec.name}", cause="poll-truncated", dropped=0
                )
                logger.warning(
                    "telemetry file exceeds the poll cap and cannot be paginated "
                    "(gap recorded): collector=%s path=%s cap=%d",
                    spec.name,
                    source.path,
                    spec.max_poll_bytes,
                )
        else:
            meta["outcome"] = "quiet"
            meta["advanced"] = False
        meta["watermark"] = state.offset

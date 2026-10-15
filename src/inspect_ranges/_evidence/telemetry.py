"""In-guest telemetry export: a driver-side poller over existing channel verbs.

Scenario telemetry (journald, application logs, EDR event files) lives inside guests because defenders are supposed to see it; this module exports it to the evidence record by polling declared collectors through the existing channel verbs (`exec`, `read_file`) on a cadence, shipping each poll's delta to `telemetry/<collector>` with a per-poll watermark record in `telemetry-meta/<collector>`. No daemon or wire-schema changes: the guest side is untouched, and the export path is the vsock control plane, which nothing in-range can observe or firewall.

The assurance claim, stated honestly: export upgrades the timeline, not the source. Pre-compromise telemetry becomes immutable once streamed; producer silencing shows as a watermark stall (polls keep succeeding while the watermark stays flat, visible in the meta stream); poll failure (daemon down, guest paused) shows as poll-gap records. The read remains T3 at origin, and the `detection` goal's completeness precondition is what consumes the watermarks (evidence-v1.md).

Reads only: poll argv is built exclusively from the declared spec literals plus the watermark extracted from the guest's own prior output; no environment, no stdin, never `write_file`, so no scoring material can transit guest-ward through this module.

Watermark semantics by source kind. A `command` source owns true deltas when the tool supports a cursor (`journalctl --after-cursor=<c> --show-cursor`): the cursor is extracted from each poll's output and substituted into the next poll's argv. Cursors are opaque, so a regression there is not detectable driver-side; tampering with the journal surfaces as command failure or duplicate output, and the timeline claim is unaffected (what was shipped before the tamper is already immutable). A `file` source has ordered watermarks (byte offsets) and detects regression (truncation or rewrite) explicitly, but pays for it: `read_file` has no offset verb, so each poll reads a capped snapshot and the delta is sliced driver-side; a file that grows past the cap cannot be paginated and is recorded as an explicit gap (use a cursor-bearing `command` source for high-volume logs).
"""

import asyncio
import hashlib
import logging
import re
import time
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

DEFAULT_META_FLUSH_S = 15.0
"""Default meta-record batching cadence (chunk-2 verification finding 3): routine ok/quiet poll records batch into one `telemetry-meta` chunk per interval instead of one object per poll; anomalies, errors, replays, and recoveries flush immediately, and `stop()` flushes the remainder. 0 means ship every poll (unit tests pin per-poll meta with it)."""

META_BATCH_MAX_RECORDS = 64
"""Buffered meta records that force a flush regardless of age."""

CollectorName = Annotated[str, StringConstraints(pattern=r"^[a-z0-9][a-z0-9._-]*$")]
"""Collector names become the second stream segment (`telemetry/<name>`), so they carry the stream grammar."""


class CommandSource(EvidenceModel):
    r"""Poll a collector by running a declared command in the guest.

    `command` runs when a watermark exists and must carry `{cursor}` in exactly one argument; `bootstrap` runs first (and after an explicit re-bootstrap) and must not reference the cursor. `cursor_pattern` is a regex with exactly one capture group, searched over the final `CURSOR_TAIL_WINDOW` bytes of the poll's decoded output (the banner trails the events, and the window bounds regex cost over adversarial guest output, so the cursor must appear within it); the last match's group becomes the next watermark, and matching tail lines are stripped from the shipped payload so the data stream carries events only. Example (journald): bootstrap `journalctl -t app -n 100 --show-cursor -q`, command `journalctl -t app --after-cursor={cursor} --show-cursor -q`, pattern `-- cursor: (\\S+)`.
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
        self.shipped = hashlib.sha256()  # digest of every shipped file byte
        self.replay_next = False  # the next bootstrap re-ships a seen window
        self.failing = False  # a poll-failed gap has been recorded for this streak
        self.capped = False  # a poll-truncated gap has been recorded for this stall
        self.polls = 0
        self.errors = 0
        self.meta_buffer: list[dict[str, object]] = []  # batched meta records
        self.meta_first: ClockStamp | None = None  # first buffered record's stamp
        self.meta_since: float | None = None  # monotonic age basis for the batch

    def reset_file(self) -> None:
        self.offset = 0
        self.shipped = hashlib.sha256()
        self.capped = False


CURSOR_TAIL_WINDOW = 4096
"""Cursor extraction searches only the output's final bytes: the cursor banner trails the events, and the window bounds regex work over guest-controlled (adversarial post-compromise) text."""


def _extract_cursor(data: bytes, pattern: str) -> tuple[str | None, bytes]:
    """Extract the last cursor from `data`'s tail window and strip banner lines.

    Returns the cursor (or `None` when the pattern matches nothing in the window) and the payload with every matching tail-window line removed, so the data stream carries events only. Lines outside the window are never regex-tested (the window is the bound on matching cost) and ship untouched.
    """
    compiled = re.compile(pattern)
    lines = data.split(b"\n")
    tested = 0
    cursor: str | None = None
    drop: set[int] = set()
    for index in range(len(lines) - 1, -1, -1):
        line = lines[index]
        tested += len(line) + 1
        if tested > CURSOR_TAIL_WINDOW:
            break
        match = compiled.search(line.decode("utf-8", errors="replace"))
        if match is not None:
            if cursor is None:
                cursor = match.group(1)
            drop.add(index)
    if not drop:
        return None, data
    payload = b"\n".join(line for index, line in enumerate(lines) if index not in drop)
    return cursor, payload


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
        meta_flush_s: float = DEFAULT_META_FLUSH_S,
        clock: Callable[[], ClockStamp] = clock_now,
    ) -> None:
        names = [spec.name for spec in collectors]
        if len(set(names)) != len(names):
            raise ValueError("collector names must be unique")
        if meta_flush_s < 0:
            raise ValueError("meta_flush_s must be >= 0")
        self._channel = channel
        self._writer = writer
        self._collectors = {spec.name: spec for spec in collectors}
        self._states = {spec.name: _CollectorState() for spec in collectors}
        self._meta_flush_s = meta_flush_s
        self._clock = clock
        self._tasks: dict[str, asyncio.Task[None]] = {}
        self._stopping = asyncio.Event()

    async def start(self) -> None:
        """Begin polling every collector; idempotent while running.

        Raises:
            RuntimeError: The poller was already stopped; a stopped poller cannot restart (a silent no-op here would end the meta stream with nothing in the record to distinguish it from a wedged poller).
        """
        if self._stopping.is_set():
            raise RuntimeError("TelemetryPoller cannot restart after stop()")
        for name in self._collectors:
            if name not in self._tasks:
                self._tasks[name] = asyncio.create_task(
                    self._run(name), name=f"telemetry-{name}"
                )

    async def stop(self, *, stop_timeout_s: float = 20.0) -> None:
        """End the poll loops and flush; never raises.

        An in-flight poll against an unreachable guest can hold the channel's per-poll budget; past `stop_timeout_s` it is cancelled so teardown (this is the teardown-bound call, like `CaptureStreamer.stop`) is never hostage to a wedged guest.
        """
        self._stopping.set()
        deadline = asyncio.get_running_loop().time() + stop_timeout_s
        for task in self._tasks.values():
            remaining = max(deadline - asyncio.get_running_loop().time(), 0.1)
            try:
                await asyncio.wait_for(asyncio.shield(task), timeout=remaining)
            except asyncio.CancelledError:
                # two causes share this exception (chunk-2 verification
                # finding 1). A poll task cancelled by an OUTSIDE actor (a
                # framework all-tasks sweep) ends the task, not stop():
                # swallow it, stop() must never raise. stop() ITSELF being
                # cancelled must propagate: that is the caller's cancellation,
                # and eating it would break teardown's cancel semantics.
                if task.cancelled():
                    logger.warning(
                        "telemetry task %s was cancelled externally before stop",
                        task.get_name(),
                    )
                    continue
                raise
            except asyncio.TimeoutError:
                logger.warning(
                    "telemetry task %s did not stop within budget; cancelling",
                    task.get_name(),
                )
                task.cancel()
                await self._guard("cancel-task", self._await_task(task))
            except Exception:
                logger.exception("telemetry task %s failed at stop", task.get_name())
        self._tasks.clear()
        for name in self._collectors:
            await self._guard(f"meta-flush:{name}", self._flush_meta(name, force=True))
        await self._guard("flush", self._writer.flush())

    async def poll_once(self, name: str) -> None:
        """One guarded poll cycle for one collector (the loop's body); for tests and embedding."""
        await self._guard(f"poll:{name}", self._poll(name))
        await self._guard("flush", self._writer.flush())

    # internal ----------------------------------------------------------------

    @staticmethod
    async def _await_task(task: "asyncio.Task[None]") -> None:
        try:
            await task
        except asyncio.CancelledError:
            pass

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
        recovered = False
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
                recovered = True
                logger.info("telemetry poll recovered: collector=%s", name)
        meta["errors"] = state.errors
        if state.meta_buffer == []:
            state.meta_first = start
            state.meta_since = time.monotonic()
        state.meta_buffer.append(meta)
        # anomalies flush immediately (their visibility latency is the point);
        # routine quiet/ok polls batch on the cadence (chunk-2 verification
        # finding 3: one meta object per poll was 2 S3 objects per poll)
        urgent = (
            meta.get("outcome") not in ("ok", "quiet")
            or "anomaly" in meta
            or meta.get("replay") is True
            or recovered
        )
        await self._flush_meta(name, force=urgent)

    async def _flush_meta(self, name: str, *, force: bool) -> None:
        """Ship the collector's batched meta records when due (`meta_flush_s`; 0 means every poll) or forced (anomaly, recovery, stop)."""
        state = self._states[name]
        if not state.meta_buffer:
            return
        if not force:
            age = (
                0.0 if state.meta_since is None else time.monotonic() - state.meta_since
            )
            if (
                self._meta_flush_s != 0
                and age < self._meta_flush_s
                and len(state.meta_buffer) < META_BATCH_MAX_RECORDS
            ):
                return
        batch = state.meta_buffer
        first = state.meta_first
        state.meta_buffer = []
        state.meta_first = None
        state.meta_since = None
        await self._writer.append(
            f"telemetry-meta/{name}", json_lines(batch), span=self._span(first)
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
        if state.replay_next and state.cursor is None:
            # this bootstrap follows a reset (truncation or a missing cursor),
            # so its window may re-ship entries already in the record; the
            # flag makes the duplicate window decidable from the meta stream
            meta["replay"] = True
            state.replay_next = False
        meta["rc"] = outcome.rc
        meta["attempts"] = outcome.attempts
        if outcome.rc != 0:
            # the collector command itself failed (journald stopped, tool
            # missing): an observation failure, same family as channel loss
            raise RuntimeError(
                f"poll command rc={outcome.rc}: "
                + outcome.stderr[:200].decode("utf-8", errors="replace")
            )
        # the per-poll cap is enforced driver-side: the `RangeChannel` seam
        # carries no per-call output cap (`MessageChannel.exec` offers
        # `bulk_cap`, but the poller stays on the protocol seam), so the
        # daemon may ship up to its own output cap before this slice; declare
        # a line limit (journalctl `-n`) in the command for high-volume
        # collectors
        truncated = (
            outcome.stdout_truncated or len(outcome.stdout) > spec.max_poll_bytes
        )
        data = outcome.stdout[: spec.max_poll_bytes]
        meta["truncated"] = truncated
        if not data:
            meta["bytes"] = 0
            meta["outcome"] = "quiet"
            meta["watermark"] = state.cursor
            meta["advanced"] = False
            return
        if truncated:
            # the tail (which carries the cursor) is gone: ship the prefix,
            # record the loss explicitly, and re-bootstrap rather than
            # livelocking on the same window
            await self._writer.append(f"telemetry/{spec.name}", data, span=self._span())
            meta["bytes"] = len(data)
            meta["outcome"] = "truncated"
            meta["watermark"] = None
            meta["advanced"] = False
            state.cursor = None
            state.replay_next = True
            await self._writer.gap(
                f"telemetry/{spec.name}", cause="poll-truncated", dropped=0
            )
            logger.warning(
                "telemetry poll truncated at %d bytes (gap recorded, re-bootstrap): collector=%s",
                spec.max_poll_bytes,
                spec.name,
            )
            return
        cursor, payload = _extract_cursor(data, source.cursor_pattern)
        meta["bytes"] = len(payload)
        if cursor is None:
            # output without a cursor: the declared pattern does not match the
            # tool's output; ship what arrived and re-bootstrap so the poller
            # never silently spins on a stale cursor (the replay flag keeps
            # the duplicate window visible)
            if payload.strip():
                await self._writer.append(
                    f"telemetry/{spec.name}", payload, span=self._span()
                )
            meta["outcome"] = "cursor-missing"
            meta["watermark"] = None
            meta["advanced"] = False
            state.cursor = None
            state.replay_next = True
            logger.warning(
                "telemetry cursor pattern matched nothing (re-bootstrap): collector=%s",
                spec.name,
            )
            return
        if not payload.strip():
            # cursor banner only (journalctl prints it even with no entries):
            # a quiet poll, never shipped, so stall-vs-quiet stays decidable
            # and the data stream carries events only
            meta["outcome"] = "quiet"
            meta["watermark"] = cursor
            meta["advanced"] = False
            state.cursor = cursor
            return
        await self._writer.append(f"telemetry/{spec.name}", payload, span=self._span())
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
                if state.offset > 0:
                    # the log vanished after content shipped: rotation or
                    # deletion. History is gone, so this is a watermark
                    # regression, not a quiet absence; shipping restarts from
                    # whatever file reappears.
                    await self._writer.gap(
                        f"telemetry/{spec.name}",
                        cause="watermark-regression",
                        dropped=0,
                    )
                    logger.warning(
                        "telemetry log vanished after %d shipped bytes (gap recorded): collector=%s path=%s",
                        state.offset,
                        spec.name,
                        source.path,
                    )
                    state.reset_file()
                    meta["anomaly"] = "rotated-or-deleted"
                else:
                    # the log appears once the producer starts; absence before
                    # any content is quiet, not an observation failure
                    pass
                meta["outcome"] = "absent"
                meta["watermark"] = state.offset
                meta["advanced"] = False
                return
            raise
        meta["truncated"] = truncated
        size = len(data)
        # regression check is content-anchored, not size-anchored: a truncate
        # that regrows past the old offset between polls would otherwise
        # splice mid-file bytes of the NEW content into the record silently
        rewritten = (
            state.offset > 0
            and size >= state.offset
            and hashlib.sha256(data[: state.offset]).hexdigest()
            != state.shipped.hexdigest()
        )
        if size < state.offset or rewritten:
            # the file shrank or its shipped prefix changed: truncated or
            # rewritten on the guest. The watermark regression is recorded
            # in-chain and shipping restarts from the new content.
            await self._writer.gap(
                f"telemetry/{spec.name}", cause="watermark-regression", dropped=0
            )
            logger.warning(
                "telemetry watermark regression (gap recorded): collector=%s path=%s %d -> %d rewritten=%s",
                spec.name,
                source.path,
                state.offset,
                size,
                rewritten,
            )
            state.reset_file()
            meta["anomaly"] = "watermark-regression"
        delta = data[state.offset :]
        if delta:
            await self._writer.append(
                f"telemetry/{spec.name}", delta, span=self._span()
            )
            state.shipped.update(delta)
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

"""The `RangeChannel` seam: transport-agnostic control plane to one sample's range.

`MessageChannel` implements the seam from `host-provider.md` over any `Transport` (per-operation connect, the resolved connection model). It owns the client-side message contract: request ids with idempotent resend, recovery of lost replies by resending the same id (the endpoint deduplicates), acknowledgement of consumed results including durable errors, the three independent budget layers, strict validation of every reply as untrusted input (residual bytes after a reply are tamper), and a bounded wire-trace tail dumped on every tamper or budget failure.

Budget layers, as implemented: the channel allowance (`Budget.channel_ms`, or the channel default) bounds each attempt's round trip; for an exec with a command budget the attempt bound is `command_ms` plus grace, and when it fires without an observed in-guest kill the failure is attributed to the channel layer, never the command layer (command-layer errors come only from the guest's own budget reply, whose attribution is advisory post-compromise). The untimed bound is an outer total per operation, covering every attempt and backoff.

`LoopbackTransport` is the in-memory reference endpoint: frames travel through the real codec in both directions to a `FakeGuest` fleet and a `FakeApplier`, so the conformance suite exercises the genuine client logic with no VM behind it.

`SampleStateMachine` is the driver-side sample lifecycle (acquire, realize, verify, execute, finalize evidence, destroy) with observable transitions; illegal transitions are rejected, never absorbed, and `destroyed` is only ever recorded after a completed teardown.
"""

import asyncio
import enum
import logging
import time
import uuid
from collections import deque
from collections.abc import AsyncIterator, Awaitable, Callable, Iterable, Sequence
from dataclasses import dataclass
from typing import Literal, NoReturn, Protocol

from .codec import (
    ChannelClosed,
    DecodeError,
    MessageStreamReader,
    TraceEvent,
    TruncatedFrame,
    encode_message,
)
from .protocol import (
    DAEMON_INBOUND_BULK_CAP,
    DEFAULT_BULK_CAP,
    EXEC_OBSERVATION_GRACE_S,
    AckRequest,
    Budget,
    BudgetLayer,
    DiagEntry,
    DiagReply,
    DiagRequest,
    ErrorReply,
    ExecRequest,
    ExecResult,
    FileData,
    ForwardReply,
    GuestState,
    Message,
    OkReply,
    PendingReply,
    PingRequest,
    PollRequest,
    PongReply,
    ReadFileRequest,
    RealizeRequest,
    Sha256Hex,
    StageReport,
    TeardownRequest,
    WriteFileRequest,
)

logger = logging.getLogger("inspect_ranges.channel")

HOST_APPLIER = "@host"
"""Reserved endpoint name addressing the host's applier (never a valid guest name)."""

_RETRY_ATTEMPTS = 3
_RETRY_BACKOFF_S = 0.05
_CHANNEL_GRACE_S = EXEC_OBSERVATION_GRACE_S
"""Added to the in-guest command budget when waiting for an exec verdict: the daemon's worst-case honest kill latency (TERM-to-KILL grace plus the pipe-reap wait delay) plus margin, derived from the shared protocol constants so host and daemon cannot drift apart."""

_SILENT_WINDOW_LIMIT = 3
"""Consecutive allowance windows with zero liveness evidence before an exec is a channel-layer failure."""

_POLL_INTERVAL_S = 0.5
"""Gap between exec liveness polls once the initial reply misses the allowance."""

_TRACE_TAIL = 256

MAX_STAGE_REPORTS = 32
"""Cap on reports per realize; the monotonic stage rule already bounds honest streams well below this."""

_STAGE_ORDER = {"fetch": 0, "construct": 1, "boot": 2, "verify": 3, "ready": 4}


class ChannelError(Exception):
    """Base for every channel-layer failure.

    `attempts` is the delivery-attempt annotation for the provider's retry layer: how many times the failing request's frames were actually sent (a send that failed at connect provably never left and does not count). `None` means the operation never reached the counting path.
    """

    attempts: int | None = None


class TamperError(ChannelError):
    """The endpoint produced something an honest implementation cannot: surfaced, never parsed around."""


class TransportFailure(ChannelError):
    """The transport could not complete the exchange within its retry budget."""


class _ConnectFailure(ConnectionError):
    """The transport failed BEFORE the request could have been delivered (connect itself failed)."""


class ChannelBudgetError(ChannelError):
    """A time budget fired; `layer` names which one, so timeout triage is mechanical.

    `partial` carries the killed command's output tail when the guest's budget-expiry reply included one (`ErrorReply.partial`); host-side budget fires have none.
    """

    def __init__(
        self, layer: BudgetLayer, message: str, partial: str | None = None
    ) -> None:
        super().__init__(f"[{layer}] {message}")
        self.layer: BudgetLayer = layer
        self.partial = partial


class GuestError(ChannelError):
    """An errno-tagged failure reported by the endpoint (attacker-influenceable post-compromise)."""

    def __init__(
        self, errno: str, message: str, layer: BudgetLayer | None = None
    ) -> None:
        super().__init__(f"{errno}: {message}")
        self.errno = errno
        self.layer = layer


class FileLimitExceeded(ChannelError):
    """An honest read was truncated at the requested cap; `partial` carries the capped bytes."""

    def __init__(self, path: str, partial: bytes) -> None:
        super().__init__(f"{path}: truncated at {len(partial)} bytes")
        self.partial = partial


class IllegalTransition(ChannelError):
    """A sample lifecycle transition the state machine does not permit."""


@dataclass
class ExecOutcome:
    """Validated exec result with the bulk split back into streams.

    `attempts` counts deliveries of the exec request itself (not liveness polls): a value above 1 means a same-id resend happened, which the provider's session-invalidation policy uses to decide whether exactly-once still holds for side-effecting operations.
    """

    rc: int
    stdout: bytes
    stderr: bytes
    stdout_truncated: bool
    stderr_truncated: bool
    attempts: int = 1


class ByteStream(Protocol):
    """One connection's byte stream; `receive` returns empty bytes at EOF."""

    async def send(self, data: bytes) -> None: ...
    async def receive(self) -> bytes: ...
    async def aclose(self) -> None: ...


class Transport(Protocol):
    """Per-operation connection factory; `endpoint` is a guest name or `HOST_APPLIER`."""

    async def connect(self, endpoint: str) -> ByteStream: ...


class RangeChannel(Protocol):
    """Transport-agnostic control plane to one sample's range (`host-provider.md`).

    Implementations: `MessageChannel` over a real or mock transport. Nothing above this interface may know which transport carries it.
    """

    def realize(
        self, bundle_digest: Sha256Hex, grants: Sequence[str]
    ) -> AsyncIterator[StageReport]: ...
    async def exec(
        self, guest: str, request: ExecRequest, *, stdin: bytes | None = None
    ) -> ExecOutcome: ...
    async def read_file(
        self, guest: str, path: str, *, cap: int = DEFAULT_BULK_CAP
    ) -> bytes: ...
    async def write_file(
        self, guest: str, path: str, data: bytes, *, mode: int | None = None
    ) -> int: ...
    async def forward(self, guest: str, host: str, port: int) -> ForwardReply: ...
    async def ping(self, guest: str) -> PongReply: ...
    async def session(self, guest: str) -> str: ...
    async def diag(self, guest: str, *, max_entries: int = 100) -> DiagReply: ...
    async def teardown(self) -> None: ...


def request_id() -> str:
    """A fresh request id; retries reuse the id, never regenerate it."""
    return uuid.uuid4().hex


@dataclass
class ChannelStats:
    """Round-trip accounting; the latency-mock conformance budgets assert against this."""

    connects: int = 0
    exchanges: int = 0


class MessageChannel:
    """`RangeChannel` implementation over any per-operation-connect `Transport`."""

    def __init__(
        self,
        transport: Transport,
        *,
        label: str = "channel",
        channel_budget_s: float = 180.0,
        untimed_bound_s: float = 14_400.0,
        grace_s: float = _CHANNEL_GRACE_S,
    ) -> None:
        self._transport = transport
        self._label = label
        self._channel_budget_s = channel_budget_s
        self._untimed_bound_s = untimed_bound_s
        self._grace_s = grace_s
        self._trace: deque[TraceEvent] = deque(maxlen=_TRACE_TAIL)
        self.stats = ChannelStats()

    # -- debuggability -----------------------------------------------------

    def trace_tail(self, limit: int = 40) -> list[str]:
        """The most recent codec trace events, formatted one per line."""
        events = list(self._trace)[-limit:]
        return [
            f"{event.t:.6f} {event.direction:4s} {event.frame:8s} {event.size:7d}"
            f" kind={event.kind or '-'} id={event.request_id or '-'}"
            + (f" note={event.note}" if event.note else "")
            for event in events
        ]

    def _log(
        self, level: int, event: str, *, rid: str, endpoint: str, detail: str = ""
    ) -> None:
        logger.log(
            level,
            "%s %s endpoint=%s request_id=%s %s",
            self._label,
            event,
            endpoint,
            rid,
            detail,
            extra={"request_id": rid, "endpoint": endpoint, "channel": self._label},
        )

    def _dump_trace(self, request: Message, endpoint: str, reason: str) -> None:
        self._log(
            logging.ERROR,
            "failure",
            rid=request.id,
            endpoint=endpoint,
            detail=f"{reason}; trace tail follows",
        )
        for line in self.trace_tail():
            logger.error(
                "  %s", line, extra={"request_id": request.id, "endpoint": endpoint}
            )

    def _tamper(
        self,
        request: Message,
        endpoint: str,
        reason: str,
        cause: BaseException | None = None,
    ) -> NoReturn:
        """Every tamper verdict goes through here: dump the trace tail, then raise."""
        self._dump_trace(request, endpoint, reason)
        raise TamperError(f"{request.kind} id={request.id}: {reason}") from cause

    # -- budgets -------------------------------------------------------------

    def _op_budgets(self, request: Message) -> tuple[float, float]:
        """Per-attempt and outer-total budgets for `request` (seconds).

        The attempt bound is the channel allowance; firing is a channel-layer verdict (a host-side deadline is a transport stall) unless the outer total expired. The outer bound caps the whole operation across attempts and backoff. Exec does not route through here: its liveness-polled flow lives in `exec`.
        """
        budget = getattr(request, "budget", None)
        if not isinstance(budget, Budget):
            return self._channel_budget_s, self._untimed_bound_s
        outer_s = min(budget.untimed_bound_ms / 1000, self._untimed_bound_s)
        if budget.channel_ms is not None:
            return budget.channel_ms / 1000, outer_s
        return self._channel_budget_s, outer_s

    # -- the exchange core -------------------------------------------------

    async def _exchange(
        self,
        endpoint: str,
        request: Message,
        bulk: bytes | None = None,
        *,
        bulk_cap: int = DEFAULT_BULK_CAP,
        ack_consumed: bool = False,
    ) -> tuple[Message, bytes | None, int]:
        """One request/reply exchange with idempotent resend on lost replies.

        A dropped connection or truncated reply is recovered by reconnecting and resending the identical request (the endpoint deduplicates on id). Any reply shape an honest endpoint cannot produce, including residual bytes after the reply, is a tamper verdict with the trace tail dumped. With `ack_consumed`, the reply (success or durable error) is acknowledged before this returns or raises.

        Returns the reply, its bulk, and the delivery-attempt count (sends that got past connect); raised `ChannelError`s carry the same count as `.attempts`.
        """
        frames = encode_message(request, bulk, trace=self._trace.append)
        attempt_s, outer_s = self._op_budgets(request)
        deadline = time.monotonic() + outer_s
        last_failure = ""
        deliveries = 0

        def stamped[E: ChannelError](error: E) -> E:
            error.attempts = deliveries
            return error

        self._log(
            logging.DEBUG,
            "request",
            rid=request.id,
            endpoint=endpoint,
            detail=request.kind,
        )
        for attempt in range(1, _RETRY_ATTEMPTS + 1):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise stamped(
                    ChannelBudgetError(
                        "untimed",
                        f"{request.kind} id={request.id}: operation total bound ({outer_s:.0f}s) expired",
                    )
                )
            try:
                reply, reply_bulk = await self._once(
                    endpoint,
                    request,
                    frames,
                    min(attempt_s, remaining),
                    bulk_cap=bulk_cap,
                )
                deliveries += 1
            except TimeoutError:
                deliveries += 1  # the frames went out; only the reply is missing
                layer: BudgetLayer = (
                    "untimed" if deadline - time.monotonic() <= 0 else "channel"
                )
                self._dump_trace(request, endpoint, f"budget expired ({layer})")
                raise stamped(
                    ChannelBudgetError(
                        layer,
                        f"{request.kind} id={request.id}: no reply within the {layer} allowance",
                    )
                ) from None
            except _ConnectFailure as failure:
                # the request provably never left: not a delivery
                last_failure = f"{type(failure).__name__}: {failure}"
                self._log(
                    logging.WARNING,
                    "retry",
                    rid=request.id,
                    endpoint=endpoint,
                    detail=f"attempt {attempt}/{_RETRY_ATTEMPTS}: {last_failure}",
                )
                await asyncio.sleep(
                    min(
                        _RETRY_BACKOFF_S * attempt,
                        max(0.0, deadline - time.monotonic()),
                    )
                )
                continue
            except (ConnectionError, ChannelClosed, TruncatedFrame) as failure:
                deliveries += 1
                last_failure = f"{type(failure).__name__}: {failure}"
                self._log(
                    logging.WARNING,
                    "retry",
                    rid=request.id,
                    endpoint=endpoint,
                    detail=f"attempt {attempt}/{_RETRY_ATTEMPTS}: {last_failure}",
                )
                await asyncio.sleep(
                    min(
                        _RETRY_BACKOFF_S * attempt,
                        max(0.0, deadline - time.monotonic()),
                    )
                )
                continue
            if reply.id != request.id:
                self._tamper(
                    request,
                    endpoint,
                    f"reply carries id {reply.id}, request was id {request.id}",
                )
            if isinstance(reply, ErrorReply):
                if reply.errno == "ESTALE":
                    raise stamped(
                        TransportFailure(
                            f"{request.kind} id={request.id}: executed, result lost before acknowledgement"
                        )
                    )
                if ack_consumed:
                    await self._ack(endpoint, request.id)
                if reply.errno in ("ETIME", "ETIMEDOUT") and reply.layer is not None:
                    raise stamped(
                        ChannelBudgetError(reply.layer, reply.message, reply.partial)
                    )
                raise stamped(GuestError(reply.errno, reply.message, reply.layer))
            self._log(
                logging.DEBUG,
                "reply",
                rid=request.id,
                endpoint=endpoint,
                detail=reply.kind,
            )
            if ack_consumed:
                await self._ack(endpoint, request.id)
            return reply, reply_bulk, deliveries
        self._dump_trace(request, endpoint, last_failure)
        raise stamped(
            TransportFailure(
                f"{request.kind} id={request.id}: reply lost after {_RETRY_ATTEMPTS} attempts ({last_failure})"
            )
        )

    async def _once(
        self,
        endpoint: str,
        context: Message,
        frames: list[bytes],
        window_s: float,
        *,
        bulk_cap: int,
    ) -> tuple[Message, bytes | None]:
        """One bounded connect-send-reply round trip.

        Raises `TimeoutError` when the window expires (the caller attributes the layer), loss exceptions for the caller's retry policy, and turns every malformed or residual-bearing reply into a tamper verdict directly. Counts one exchange on success.
        """
        async with asyncio.timeout(window_s):
            try:
                stream = await self._transport.connect(endpoint)
            except ConnectionError as failure:
                # the request provably never left: callers may resend freely
                raise _ConnectFailure(str(failure)) from failure
            self.stats.connects += 1
            try:
                for frame in frames:
                    await stream.send(frame)
                reader = MessageStreamReader(
                    stream.receive, bulk_cap=bulk_cap, trace=self._trace.append
                )
                try:
                    reply, reply_bulk = await reader.next()
                except (ChannelClosed, TruncatedFrame):
                    raise  # loss, not tamper: the caller's retry policy decides
                except DecodeError as failure:
                    self._tamper(
                        context,
                        endpoint,
                        f"{type(failure).__name__}: {failure}",
                        failure,
                    )
                # an honest per-operation endpoint sends one reply and closes;
                # anything after it is tamper, not padding
                if reader.pending:
                    self._tamper(context, endpoint, "data after the reply")
                residual = await stream.receive()
                if residual:
                    self._tamper(context, endpoint, "data after the reply (post-close)")
            finally:
                await stream.aclose()
        self.stats.exchanges += 1
        return reply, reply_bulk

    def _expect[ReplyT: Message](
        self, reply: Message, expected: type[ReplyT], request: Message, endpoint: str
    ) -> ReplyT:
        if not isinstance(reply, expected):
            self._tamper(
                request,
                endpoint,
                f"expected {expected.__name__}, got {reply.kind}",
            )
        return reply

    async def _ack(self, endpoint: str, target_id: str) -> None:
        """Acknowledge a consumed durable result. Loss is best-effort (logged); tamper re-raises."""
        ack = AckRequest(id=request_id(), target_id=target_id)
        try:
            reply, _, _ = await self._exchange(endpoint, ack)
            self._expect(reply, OkReply, ack, endpoint)
        except TamperError:
            raise
        except ChannelError as failure:
            self._log(
                logging.WARNING,
                "ack-failed",
                rid=target_id,
                endpoint=endpoint,
                detail=str(failure),
            )

    # -- guest control plane ------------------------------------------------

    async def ping(self, guest: str) -> PongReply:
        """Liveness and protocol-version probe for one guest."""
        request = PingRequest(id=request_id())
        reply, _, _ = await self._exchange(guest, request)
        return self._expect(reply, PongReply, request, guest)

    async def session(self, guest: str) -> str:
        """The guest daemon's current session id, via a fresh ping.

        The provider pins it per guest at boot and treats a later change as a daemon restart: the wire layer's exactly-once guarantee (dedupe, tombstones, durable replies) holds only within one session (`SessionHex`).
        """
        return (await self.ping(guest)).session

    async def exec(
        self,
        guest: str,
        request: ExecRequest,
        *,
        stdin: bytes | None = None,
        bulk_cap: int = 2 * DEFAULT_BULK_CAP,
    ) -> ExecOutcome:
        """Run `request` in the guest; `stdin` must match the request's `data_size` declaration. `bulk_cap` bounds the accepted reply bulk (stdout plus stderr), reader-side.

        Liveness-polled: the initial reply wait is capped so at least one poll precedes the exec deadline; `pending` replies prove liveness while the command runs, so long execs stay allowance-bounded between polls, and three consecutive allowance windows with zero liveness evidence are a channel-layer failure. The exec deadline (`command_ms` plus the shared observation grace, or the untimed total) firing without RECENT liveness is a channel-layer verdict; with recent liveness it is a command-layer verdict (the guest demonstrably failed to kill within its own grace).

        At-most-once: a resend is only legal while the request provably never left (connect failed); once delivery is possible, a daemon `ENOENT`/`ESTALE` for the id surfaces as `TransportFailure`, never a re-run.
        """
        if (request.data_size is None) != (stdin is None) or (
            request.data_size or 0
        ) != len(stdin or b""):
            raise ValueError("stdin must match the request's data_size declaration")
        if stdin is not None and len(stdin) > DAEMON_INBOUND_BULK_CAP:
            raise ValueError(
                f"exec stdin of {len(stdin)} bytes exceeds the daemon inbound cap "
                f"({DAEMON_INBOUND_BULK_CAP} bytes)"
            )
        budget = request.budget
        allowance_s = (
            budget.channel_ms / 1000
            if budget.channel_ms is not None
            else self._channel_budget_s
        )
        outer_s = min(budget.untimed_bound_ms / 1000, self._untimed_bound_s)
        exec_bound_s = (
            min(budget.command_ms / 1000 + self._grace_s, outer_s)
            if budget.command_ms is not None
            else outer_s
        )
        start = time.monotonic()
        exec_deadline = start + exec_bound_s
        outer_deadline = start + outer_s
        frames = encode_message(request, stdin, trace=self._trace.append)
        self._log(
            logging.DEBUG, "request", rid=request.id, endpoint=guest, detail="exec"
        )
        last_pending_at: float | None = None
        polling = False
        losses = 0
        silent_windows = 0
        deliveries = 0

        def stamped[E: ChannelError](error: E) -> E:
            error.attempts = deliveries
            return error

        # liveness must be RECENT to blame the command layer: a pending seen
        # once at the start must not convert a later transport stall into a
        # guest-failed-to-kill verdict
        recent_window_s = max(allowance_s, _POLL_INTERVAL_S) * 2 + self._grace_s
        while True:
            now = time.monotonic()
            if now >= outer_deadline:
                raise stamped(
                    ChannelBudgetError(
                        "untimed",
                        f"exec id={request.id}: operation total bound expired",
                    )
                )
            if now >= exec_deadline:
                recent_liveness = (
                    last_pending_at is not None
                    and now - last_pending_at <= recent_window_s
                )
                layer: BudgetLayer = "command" if recent_liveness else "channel"
                self._dump_trace(request, guest, f"exec deadline ({layer})")
                raise stamped(
                    ChannelBudgetError(
                        layer,
                        f"exec id={request.id}: no result by the exec deadline "
                        + (
                            "despite recently observed liveness (the guest failed to kill)"
                            if recent_liveness
                            else "without recent liveness (transport stall)"
                        ),
                    )
                )
            remaining = min(exec_deadline, outer_deadline) - now
            window = min(allowance_s, remaining)
            if not polling and window >= remaining:
                # cap the initial wait so at least one poll precedes the
                # deadline; otherwise every deadline would read as a
                # transport stall even on a healthy transport
                reserve = min(allowance_s, _POLL_INTERVAL_S + 1.0)
                window = max(remaining - reserve, remaining / 2, 0.05)
            if polling:
                probe: Message = PollRequest(id=request_id(), target_id=request.id)
                send_frames = encode_message(probe, None, trace=self._trace.append)
            else:
                probe = request
                send_frames = frames
            try:
                reply, bulk = await self._once(
                    guest, probe, send_frames, window, bulk_cap=bulk_cap
                )
                if probe is request:
                    deliveries += 1
            except TimeoutError:
                if probe is request:
                    deliveries += 1  # sent; only the reply is missing
                # no reply within the allowance: switch to liveness polling
                polling = True
                if last_pending_at is None:
                    silent_windows += 1
                    if silent_windows >= _SILENT_WINDOW_LIMIT:
                        self._dump_trace(request, guest, "silent transport")
                        raise stamped(
                            ChannelBudgetError(
                                "channel",
                                f"exec id={request.id}: {silent_windows} allowance "
                                "windows with zero liveness evidence",
                            )
                        ) from None
                continue
            except _ConnectFailure as failure:
                losses += 1
                if losses > _RETRY_ATTEMPTS:
                    raise stamped(
                        TransportFailure(
                            f"exec id={request.id}: unreachable after {losses - 1} attempts ({failure})"
                        )
                    ) from failure
                await asyncio.sleep(
                    min(
                        _RETRY_BACKOFF_S * losses,
                        max(0.0, outer_deadline - time.monotonic()),
                    )
                )
                continue
            except (ConnectionError, ChannelClosed, TruncatedFrame) as failure:
                if probe is request:
                    # the connection died after the send: the request may well
                    # have been delivered and only the reply lost, so this
                    # counts as a delivery (the session-invalidation policy
                    # must see the resend that follows)
                    deliveries += 1
                losses += 1
                if losses > _RETRY_ATTEMPTS:
                    raise stamped(
                        TransportFailure(
                            f"exec id={request.id}: lost after {losses - 1} consecutive attempts ({failure})"
                        )
                    ) from failure
                await asyncio.sleep(
                    min(
                        _RETRY_BACKOFF_S * losses,
                        max(0.0, outer_deadline - time.monotonic()),
                    )
                )
                continue
            losses = 0
            silent_windows = 0
            if (
                polling
                and isinstance(reply, PendingReply)
                and reply.id == probe.id
                and reply.target_id == request.id
            ):
                last_pending_at = time.monotonic()
                await asyncio.sleep(
                    min(_POLL_INTERVAL_S, max(0.0, exec_deadline - time.monotonic()))
                )
                continue
            if polling and isinstance(reply, ErrorReply) and reply.id == probe.id:
                if reply.errno == "ESTALE":
                    # the daemon's at-most-once tombstone: the effect EXECUTED
                    # and its result was evicted; never resend
                    raise stamped(
                        TransportFailure(
                            f"exec id={request.id}: executed, result lost before acknowledgement"
                        )
                    )
                if reply.errno == "ENOENT":
                    # ENOENT is only resend-safe while the request provably
                    # never left (every attempt failed at connect); anything
                    # else risks a double run on a tombstone-evicted id
                    raise stamped(
                        TransportFailure(
                            f"exec id={request.id}: no stored result and delivery "
                            "cannot be ruled out; refusing an at-most-once-unsafe resend"
                        )
                    )
                # any other poll failure is an honest errno-tagged error
                raise stamped(GuestError(reply.errno, reply.message, reply.layer))
            if reply.id != request.id:
                self._tamper(
                    request,
                    guest,
                    f"reply carries id {reply.id}, request was id {request.id}",
                )
            if isinstance(reply, ErrorReply):
                if reply.errno == "ESTALE":
                    raise stamped(
                        TransportFailure(
                            f"exec id={request.id}: executed, result lost before acknowledgement"
                        )
                    )
                await self._ack(guest, request.id)
                if reply.errno in ("ETIME", "ETIMEDOUT") and reply.layer is not None:
                    raise stamped(
                        ChannelBudgetError(reply.layer, reply.message, reply.partial)
                    )
                raise stamped(GuestError(reply.errno, reply.message, reply.layer))
            break
        self._log(
            logging.DEBUG, "reply", rid=request.id, endpoint=guest, detail=reply.kind
        )
        result = self._expect(reply, ExecResult, request, guest)
        await self._ack(guest, request.id)
        payload = bulk or b""
        stdout = payload[: result.stdout_size]
        stderr = payload[result.stdout_size : result.stdout_size + result.stderr_size]
        return ExecOutcome(
            rc=result.rc,
            stdout=stdout,
            stderr=stderr,
            stdout_truncated=result.stdout_truncated,
            stderr_truncated=result.stderr_truncated,
            attempts=max(deliveries, 1),
        )

    async def read_file(
        self, guest: str, path: str, *, cap: int = DEFAULT_BULK_CAP
    ) -> bytes:
        """Read a guest file, capped at `cap` bytes.

        Raises:
            FileLimitExceeded: The guest honestly truncated at the cap; `partial` carries the bytes.
            GuestError: Errno-tagged guest failure (`ENOENT`, `EISDIR`, ...).
        """
        request = ReadFileRequest(id=request_id(), path=path, max_bytes=cap)
        reply, bulk, _ = await self._exchange(
            guest, request, bulk_cap=cap, ack_consumed=True
        )
        data = self._expect(reply, FileData, request, guest)
        if data.truncated:
            raise FileLimitExceeded(path, bulk or b"")
        return bulk or b""

    async def write_file(
        self, guest: str, path: str, data: bytes, *, mode: int | None = None
    ) -> int:
        """Write `data` to a guest file (exactly once per request id, even across retries).

        `mode` sets the created file's permission bits atomically with the write (`WriteFileRequest.mode`); `None` keeps the daemon default.

        Returns the delivery-attempt count: above 1 means a same-id resend happened (the provider's session-invalidation policy reads this for side-effecting operations).

        Raises:
            ValueError: The payload exceeds the daemon's inbound bulk cap (refused before sending).
        """
        if len(data) > DAEMON_INBOUND_BULK_CAP:
            raise ValueError(
                f"write of {len(data)} bytes exceeds the daemon inbound cap "
                f"({DAEMON_INBOUND_BULK_CAP} bytes)"
            )
        request = WriteFileRequest(
            id=request_id(), path=path, data_size=len(data), mode=mode
        )
        reply, _, deliveries = await self._exchange(
            guest, request, data, ack_consumed=True
        )
        self._expect(reply, OkReply, request, guest)
        return deliveries

    async def forward(self, guest: str, host: str, port: int) -> ForwardReply:
        """Open a capability-gated forward (not implemented until the realizer integration)."""
        raise NotImplementedError(
            "forward arrives with the realizer integration slice; the message "
            "schema is wire-stable (ForwardRequest/ForwardReply) and capability-gated"
        )

    async def diag(self, guest: str, *, max_entries: int = 100) -> DiagReply:
        """Read the daemon's diagnostics: the in-guest ring buffer tail plus the supervised listener-restart count."""
        request = DiagRequest(id=request_id(), max_entries=max_entries)
        reply, _, _ = await self._exchange(guest, request)
        return self._expect(reply, DiagReply, request, guest)

    # -- host lifecycle plane -----------------------------------------------

    async def realize(
        self, bundle_digest: Sha256Hex, grants: Sequence[str]
    ) -> AsyncIterator[StageReport]:
        """Stream stage reports until `ready` or `failed`.

        Hardened per the realize policy: every transport interaction (connect, send, each report read, the terminal drain, close) sits inside the layered budgets (per-report channel allowance, untimed outer total); reports are capped in count and must follow strictly increasing stage order; an early stream end is loss and is resumed by resending the same request id (the applier deduplicates and replays; already-yielded reports must replay identically); anything else is tamper.

        Stage-order leniency, deliberate: skipping stages is allowed (a cache-hitting applier legitimately jumps ahead) and `failed` is allowed anywhere including first (an honest fast failure); only `ready` as the very first report is tamper. A hostile applier can emit the honest sequence anyway, so tightening buys no security.
        """
        request = RealizeRequest(
            id=request_id(), bundle_digest=bundle_digest, grants=list(grants)
        )
        deadline = time.monotonic() + self._untimed_bound_s
        seen: list[StageReport] = []
        self._log(
            logging.INFO,
            "realize",
            rid=request.id,
            endpoint=HOST_APPLIER,
            detail=bundle_digest,
        )
        for attempt in range(1, _RETRY_ATTEMPTS + 1):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise ChannelBudgetError(
                    "untimed", f"realize id={request.id}: total bound expired"
                )
            try:
                async with asyncio.timeout(min(self._channel_budget_s, remaining)):
                    stream = await self._transport.connect(HOST_APPLIER)
                    self.stats.connects += 1
                    for frame in encode_message(
                        request, None, trace=self._trace.append
                    ):
                        await stream.send(frame)
            except TimeoutError:
                layer: BudgetLayer = (
                    "untimed" if deadline - time.monotonic() <= 0 else "channel"
                )
                self._dump_trace(request, HOST_APPLIER, f"connect budget ({layer})")
                raise ChannelBudgetError(
                    layer, f"realize id={request.id}: applier unreachable in budget"
                ) from None
            except ConnectionError as loss:
                self._log(
                    logging.WARNING,
                    "realize-resume",
                    rid=request.id,
                    endpoint=HOST_APPLIER,
                    detail=f"attempt {attempt}: connect: {loss}",
                )
                await asyncio.sleep(_RETRY_BACKOFF_S * attempt)
                continue
            expected_replay = list(seen)  # a resumed stream must replay these first
            replayed = 0
            last_index = -1 if not seen else _STAGE_ORDER[seen[-1].stage]
            received = 0
            try:
                reader = MessageStreamReader(
                    stream.receive, bulk_cap=DEFAULT_BULK_CAP, trace=self._trace.append
                )
                while True:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise ChannelBudgetError(
                            "untimed", f"realize id={request.id}: total bound expired"
                        )
                    try:
                        async with asyncio.timeout(
                            min(self._channel_budget_s, remaining)
                        ):
                            message, _ = await reader.next()
                    except TimeoutError:
                        layer = (
                            "untimed" if deadline - time.monotonic() <= 0 else "channel"
                        )
                        self._dump_trace(
                            request, HOST_APPLIER, f"stage budget ({layer})"
                        )
                        raise ChannelBudgetError(
                            layer, f"realize id={request.id}: no stage report in budget"
                        ) from None
                    except (ConnectionError, ChannelClosed, TruncatedFrame) as loss:
                        # early stream end is loss, not tamper: resume same id
                        self._log(
                            logging.WARNING,
                            "realize-resume",
                            rid=request.id,
                            endpoint=HOST_APPLIER,
                            detail=f"attempt {attempt}: {type(loss).__name__}",
                        )
                        break
                    except DecodeError as failure:
                        self._tamper(request, HOST_APPLIER, str(failure), failure)
                    self.stats.exchanges += 1
                    received += 1
                    if received > MAX_STAGE_REPORTS:
                        self._tamper(request, HOST_APPLIER, "stage report flood")
                    report = self._expect(message, StageReport, request, HOST_APPLIER)
                    if report.id != request.id:
                        self._tamper(
                            request,
                            HOST_APPLIER,
                            f"stage report carries id {report.id}",
                        )
                    if replayed < len(expected_replay):
                        if report != expected_replay[replayed]:
                            self._tamper(
                                request, HOST_APPLIER, "resumed replay diverged"
                            )
                        replayed += 1
                        continue
                    if report.stage != "failed":
                        index = _STAGE_ORDER[report.stage]
                        if index <= last_index or (
                            report.stage == "ready" and not seen
                        ):
                            self._tamper(
                                request,
                                HOST_APPLIER,
                                f"stage order violation: {report.stage} after "
                                f"{seen[-1].stage if seen else 'nothing'}",
                            )
                        last_index = index
                    seen.append(report)
                    self._log(
                        logging.INFO,
                        "stage",
                        rid=request.id,
                        endpoint=HOST_APPLIER,
                        detail=f"{report.stage} {report.detail}".strip(),
                    )
                    yield report
                    if report.stage in ("ready", "failed"):
                        if reader.pending:
                            self._tamper(
                                request, HOST_APPLIER, "data after the terminal stage"
                            )
                        try:
                            async with asyncio.timeout(
                                min(
                                    self._channel_budget_s,
                                    max(0.05, deadline - time.monotonic()),
                                )
                            ):
                                if await stream.receive():
                                    self._tamper(
                                        request,
                                        HOST_APPLIER,
                                        "data after the terminal stage",
                                    )
                        except TimeoutError:
                            # the terminal report is already delivered; a stream
                            # that never closes is logged, not a failure
                            self._log(
                                logging.WARNING,
                                "realize-no-close",
                                rid=request.id,
                                endpoint=HOST_APPLIER,
                                detail="stream not closed after terminal stage",
                            )
                        return
            finally:
                try:
                    async with asyncio.timeout(5.0):
                        await stream.aclose()
                except Exception:  # close is best effort, never masks
                    logger.warning("realize stream close failed (ignored)")
            await asyncio.sleep(_RETRY_BACKOFF_S * attempt)
        raise TransportFailure(
            f"realize id={request.id}: stream lost after {_RETRY_ATTEMPTS} attempts"
        )

    async def teardown(self) -> None:
        """Tear the range down. Teardown is contractually idempotent: callers may retry with a fresh id."""
        request = TeardownRequest(id=request_id())
        reply, _, _ = await self._exchange(HOST_APPLIER, request)
        self._expect(reply, OkReply, request, HOST_APPLIER)


# ---------------------------------------------------------------------------
# Sample lifecycle state machine
# ---------------------------------------------------------------------------


class SamplePhase(enum.Enum):
    """Driver-side sample lifecycle phases (`host-provider.md` seam)."""

    CREATED = "created"
    ACQUIRED = "acquired"
    REALIZED = "realized"
    VERIFIED = "verified"
    EXECUTING = "executing"
    FINALIZED = "finalized"
    DESTROYED = "destroyed"
    FAILED = "failed"


_TRANSITIONS: dict[SamplePhase, frozenset[SamplePhase]] = {
    SamplePhase.CREATED: frozenset({SamplePhase.ACQUIRED}),
    SamplePhase.ACQUIRED: frozenset({SamplePhase.REALIZED, SamplePhase.FAILED}),
    SamplePhase.REALIZED: frozenset({SamplePhase.VERIFIED, SamplePhase.FAILED}),
    SamplePhase.VERIFIED: frozenset({SamplePhase.EXECUTING, SamplePhase.FAILED}),
    SamplePhase.EXECUTING: frozenset({SamplePhase.FINALIZED, SamplePhase.FAILED}),
    SamplePhase.FINALIZED: frozenset({SamplePhase.DESTROYED, SamplePhase.FAILED}),
    SamplePhase.FAILED: frozenset({SamplePhase.DESTROYED}),
    SamplePhase.DESTROYED: frozenset(),
}

Observer = Callable[[SamplePhase, SamplePhase], None]


class SampleStateMachine:
    """Observable sample lifecycle; illegal transitions raise, never absorb.

    `destroyed` is recorded only after a completed teardown; a sample whose teardown never succeeded ends in `failed`, honestly. Observer exceptions are logged and never affect the machine or the lifecycle around it.
    """

    def __init__(self, *, label: str = "sample") -> None:
        self._label = label
        self._phase = SamplePhase.CREATED
        self.history: list[tuple[SamplePhase, SamplePhase, float]] = []
        self._observers: list[Observer] = []

    @property
    def phase(self) -> SamplePhase:
        return self._phase

    def observe(self, observer: Observer) -> None:
        self._observers.append(observer)

    def to(self, phase: SamplePhase) -> None:
        """Transition to `phase`.

        Raises:
            IllegalTransition: The lifecycle does not permit this edge.
        """
        if phase not in _TRANSITIONS[self._phase]:
            raise IllegalTransition(
                f"{self._label}: {self._phase.value} -> {phase.value}"
            )
        previous, self._phase = self._phase, phase
        self.history.append((previous, phase, time.monotonic()))
        logger.info(
            "%s transition %s -> %s",
            self._label,
            previous.value,
            phase.value,
            extra={"sample": self._label},
        )
        for observer in self._observers:
            try:
                observer(previous, phase)
            except Exception:
                logger.exception("state observer failed (non-fatal)")


async def _teardown_with_retry(channel: "MessageChannel") -> Exception | None:
    """Attempt teardown twice; teardown is contractually idempotent, so retries use fresh ids."""
    last: Exception | None = None
    for attempt in (1, 2):
        try:
            await channel.teardown()
            return None
        except Exception as failure:
            # broad on purpose: nothing here may mask the sample's own outcome
            last = failure
            logger.error("teardown attempt %d failed: %s", attempt, failure)
    return last


async def run_sample(
    channel: MessageChannel,
    *,
    bundle_digest: Sha256Hex,
    grants: Sequence[str] = (),
    verify_guests: Sequence[str] = (),
    execute: Callable[[MessageChannel], Awaitable[None]] | None = None,
    machine: SampleStateMachine | None = None,
) -> SampleStateMachine:
    """Drive one sample through the lifecycle against `channel`.

    Teardown always runs and completes before any `destroyed` transition; a teardown that fails even after retry leaves the machine in `failed`, because claiming destruction without a completed teardown would be dishonest. Phase failures re-raise after teardown; a success-path teardown failure that the retry recovers is a logged warning, not an error.
    """
    machine = machine or SampleStateMachine()
    machine.to(SamplePhase.ACQUIRED)
    original: BaseException | None = None
    try:
        final: StageReport | None = None
        async for report in channel.realize(bundle_digest, grants):
            final = report
        if final is None or final.stage != "ready":
            detail = final.detail if final is not None else "no stage reports"
            raise ChannelError(f"realization failed: {detail}")
        machine.to(SamplePhase.REALIZED)
        for guest in verify_guests:
            await channel.ping(guest)
        machine.to(SamplePhase.VERIFIED)
        machine.to(SamplePhase.EXECUTING)
        if execute is not None:
            await execute(channel)
        machine.to(SamplePhase.FINALIZED)
    except BaseException as failure:
        original = failure
        machine.to(SamplePhase.FAILED)
    teardown_failure = await _teardown_with_retry(channel)
    if teardown_failure is None:
        machine.to(SamplePhase.DESTROYED)
    elif machine.phase is SamplePhase.FINALIZED:
        machine.to(SamplePhase.FAILED)  # honest: the range was not destroyed
    if original is not None:
        raise original
    if teardown_failure is not None:
        raise teardown_failure
    return machine


# ---------------------------------------------------------------------------
# Loopback transport: the in-memory reference endpoint
# ---------------------------------------------------------------------------


class MemoryStream:
    """One direction pair of in-memory byte queues implementing `ByteStream`."""

    def __init__(
        self, outgoing: asyncio.Queue[bytes], incoming: asyncio.Queue[bytes]
    ) -> None:
        self._outgoing = outgoing
        self._incoming = incoming
        self._closed = False

    async def send(self, data: bytes) -> None:
        if self._closed:
            raise ConnectionError("stream closed")
        await self._outgoing.put(data)

    async def receive(self) -> bytes:
        return await self._incoming.get()

    async def aclose(self) -> None:
        if not self._closed:
            self._closed = True
            await self._outgoing.put(b"")


def stream_pair() -> tuple[MemoryStream, MemoryStream]:
    a: asyncio.Queue[bytes] = asyncio.Queue()
    b: asyncio.Queue[bytes] = asyncio.Queue()
    return MemoryStream(a, b), MemoryStream(b, a)


ExecHandler = Callable[["ExecContext"], Awaitable[tuple[int, bytes, bytes]]]


@dataclass
class ExecContext:
    """What a `FakeGuest` command handler sees."""

    argv: list[str]
    stdin: bytes
    env: dict[str, str]
    cwd: str | None
    user: str | None


@dataclass
class _StoredReply:
    message: Message
    bulk: bytes | None


class FakeGuest:
    """A deterministic in-memory guest endpoint speaking protocol v3.

    Implements the daemon-side contract the conformance suite checks (two deliberate gaps: no per-stream `OutputCap`, so daemon-side truncation flags never fire here, and no `partial` tail on budget-expiry errors, because a cancelled handler has produced no observable output; `LocalEndpoint` and the real daemon cover both paths): EVERY request kind deduplicates on id (a resent id attaches to the running command or returns the stored result; the effect runs once), durable replies (including durable errors) held until acked, in-guest command budgets, `max_bytes`-honoring truncated reads, and errno-tagged file errors. `drop_next_reply` simulates a reply lost in flight; `close_mid_run` simulates a connection dying while the command runs.
    """

    exec_count: int
    write_count: int

    def __init__(self, name: str) -> None:
        self.name = name
        self.session = uuid.uuid4().hex
        """The daemon boot session reported in every pong; `restart()` mints a fresh one."""
        self.files: dict[str, bytes] = {}
        self.file_modes: dict[str, int | None] = {}
        """The `mode` each write carried, keyed by path (an in-memory store has no permission bits to inspect)."""
        self.directories: set[str] = {"/", "/tmp"}
        self.exec_count = 0
        self.write_count = 0
        self.drop_next_reply = False
        self.close_mid_run = False
        self.ignore_command_budget = False
        """Simulates a guest that fails to enforce command_ms (the host-side command-layer verdict path)."""
        self._stored: dict[str, _StoredReply] = {}
        self._tombstones: dict[str, None] = {}  # insertion-ordered FIFO
        self._running: dict[str, asyncio.Task[_StoredReply]] = {}
        self._running_started: dict[str, float] = {}
        self._handlers: dict[str, ExecHandler] = {}
        self.diag_entries: list[DiagEntry] = []

    def register(self, command: str, handler: ExecHandler) -> None:
        self._handlers[command] = handler

    def stored_reply_count(self) -> int:
        return len(self._stored)

    def restart(self) -> None:
        """Simulate a daemon restart: a fresh session, and the dedupe store (stored replies, tombstones, running commands) vanishes with the process."""
        self.session = uuid.uuid4().hex
        for task in self._running.values():
            task.cancel()
        self._stored.clear()
        self._tombstones.clear()
        self._running.clear()
        self._running_started.clear()

    # -- daemon behavior ----------------------------------------------------

    async def handle(self, message: Message, bulk: bytes | None) -> _StoredReply:
        """Produce the reply for one request; every kind dedupes on id."""
        if isinstance(message, AckRequest):
            self._stored.pop(message.target_id, None)
            self._tombstones.pop(message.target_id, None)
            return _StoredReply(OkReply(id=message.id), None)
        if isinstance(message, PollRequest):
            stored = self._stored.get(message.target_id)
            if stored is not None:
                return stored  # replayed with the ORIGINAL id, by design
            if message.target_id in self._tombstones:
                return _StoredReply(
                    ErrorReply(
                        id=message.id,
                        errno="ESTALE",
                        message="executed, result lost before acknowledgement",
                    ),
                    None,
                )
            if message.target_id in self._running:
                started = self._running_started.get(message.target_id, time.monotonic())
                return _StoredReply(
                    PendingReply(
                        id=message.id,
                        target_id=message.target_id,
                        elapsed_ms=int((time.monotonic() - started) * 1000),
                    ),
                    None,
                )
            return _StoredReply(
                ErrorReply(id=message.id, errno="ENOENT", message="no stored result"),
                None,
            )
        if (stored := self._stored.get(message.id)) is not None:
            return stored
        if message.id in self._tombstones:
            return _StoredReply(
                ErrorReply(
                    id=message.id,
                    errno="ESTALE",
                    message="executed, result lost before acknowledgement",
                ),
                None,
            )
        if isinstance(message, ExecRequest):
            return await self.start_exec(message, bulk or b"")
        reply = self._handle_fresh(message, bulk)
        self._store(message.id, reply)
        return reply

    def _store(self, rid: str, reply: _StoredReply) -> None:
        # durable replies are held BOUNDED until acked (range-channel
        # property 3); evicted-unacked ids tombstone so a resend can never
        # double-run (property 1 under eviction, the ESTALE contract)
        self._stored[rid] = reply
        while len(self._stored) > 256:
            evicted = next(iter(self._stored))
            self._stored.pop(evicted)
            self._tombstones[evicted] = None
            while len(self._tombstones) > 4096:
                self._tombstones.pop(next(iter(self._tombstones)))

    def _handle_fresh(self, message: Message, bulk: bytes | None) -> _StoredReply:
        if isinstance(message, PingRequest):
            return _StoredReply(
                PongReply(
                    id=message.id, daemon=f"fake {self.name}", session=self.session
                ),
                None,
            )
        if isinstance(message, DiagRequest):
            entries = self.diag_entries[-message.max_entries :]
            return _StoredReply(DiagReply(id=message.id, entries=entries), None)
        if isinstance(message, ReadFileRequest):
            return self._read(message)
        if isinstance(message, WriteFileRequest):
            return self._write(message, bulk or b"")
        return _StoredReply(
            ErrorReply(
                id=message.id,
                errno="EPROTO",
                message=f"unsupported request {message.kind}",
            ),
            None,
        )

    async def start_exec(self, request: ExecRequest, stdin: bytes) -> _StoredReply:
        """Run (or attach to) the command for `request.id`; the command runs exactly once per id."""
        if request.id in self._stored:
            return self._stored[request.id]
        if request.id in self._running:
            return await asyncio.shield(self._running[request.id])
        task = asyncio.create_task(self._run_command(request, stdin))
        self._running[request.id] = task
        self._running_started[request.id] = time.monotonic()
        try:
            return await asyncio.shield(task)
        finally:
            if task.done():
                self._running.pop(request.id, None)
                self._running_started.pop(request.id, None)

    async def _run_command(self, request: ExecRequest, stdin: bytes) -> _StoredReply:
        self.exec_count += 1
        context = ExecContext(
            argv=request.cmd,
            stdin=stdin,
            env=request.env,
            cwd=request.cwd,
            user=request.user,
        )
        handler = self._handlers.get(request.cmd[0], _default_handler)
        try:
            if self.ignore_command_budget:
                rc, stdout, stderr = await handler(context)
            elif request.budget.command_ms is not None:
                rc, stdout, stderr = await asyncio.wait_for(
                    handler(context), timeout=request.budget.command_ms / 1000
                )
            else:
                rc, stdout, stderr = await handler(context)
        except TimeoutError:
            reply = _StoredReply(
                ErrorReply(
                    id=request.id,
                    errno="ETIME",
                    message=f"command budget expired after {request.budget.command_ms} ms",
                    layer="command",
                ),
                None,
            )
            self._store(request.id, reply)
            return reply
        payload = stdout + stderr
        reply = _StoredReply(
            ExecResult(
                id=request.id,
                rc=rc,
                stdout_size=len(stdout),
                stderr_size=len(stderr),
                data_size=len(payload) or None,
            ),
            payload if payload else None,
        )
        self._store(request.id, reply)
        return reply

    def _read(self, request: ReadFileRequest) -> _StoredReply:
        if request.path in self.directories:
            return _StoredReply(
                ErrorReply(id=request.id, errno="EISDIR", message="Is a directory"),
                None,
            )
        data = self.files.get(request.path)
        if data is None:
            return _StoredReply(
                ErrorReply(
                    id=request.id, errno="ENOENT", message="No such file or directory"
                ),
                None,
            )
        truncated = request.max_bytes is not None and len(data) > request.max_bytes
        if truncated:
            assert request.max_bytes is not None
            data = data[: request.max_bytes]
        return _StoredReply(
            FileData(
                id=request.id,
                size=len(data),
                data_size=len(data) or None,
                truncated=truncated,
            ),
            data if data else None,
        )

    def _write(self, request: WriteFileRequest, data: bytes) -> _StoredReply:
        self.write_count += 1
        self.files[request.path] = data
        self.file_modes[request.path] = request.mode
        return _StoredReply(OkReply(id=request.id), None)


async def _default_handler(context: ExecContext) -> tuple[int, bytes, bytes]:
    argv = context.argv
    match argv[0]:
        case "true":
            return 0, b"", b""
        case "false":
            return 1, b"", b""
        case "echo":
            return 0, (" ".join(argv[1:]) + "\n").encode(), b""
        case "cat":
            return 0, context.stdin, b""
        case "env-dump":
            lines = [f"cwd={context.cwd or ''}", f"user={context.user or ''}"]
            lines += [f"{key}={value}" for key, value in sorted(context.env.items())]
            return 0, ("\n".join(lines) + "\n").encode(), b""
        case "sleep-ms":
            await asyncio.sleep(int(argv[1]) / 1000)
            return 0, b"", b""
        case "stderr":
            return 2, b"", (" ".join(argv[1:]) + "\n").encode()
        case _:
            return 127, b"", f"command not found: {argv[0]}\n".encode()


class FakeApplier:
    """In-memory host applier endpoint: realize streams stage reports with id-keyed replay (dedupe), teardown acknowledges."""

    def __init__(self) -> None:
        self.fail_at_stage: str | None = None
        self.fail_teardown_times = 0
        self.drop_after_reports: int | None = None
        self.corrupt_replay = False
        self.torn_down = False
        self.realize_executions = 0
        self.realized_digests: list[str] = []
        self._report_log: dict[str, list[StageReport]] = {}

    def stage_reports(self, request: RealizeRequest) -> list[StageReport]:
        """The full report stream for `request.id`: computed once, replayed on resends."""
        if request.id in self._report_log:
            replay = self._report_log[request.id]
            if self.corrupt_replay:
                self.corrupt_replay = False
                first = replay[0].model_copy(update={"detail": "diverged"})
                return [first, *replay[1:]]
            return replay
        self.realize_executions += 1
        self.realized_digests.append(request.bundle_digest)
        stages: list[StageReport] = []
        guests: dict[str, GuestState] = {}
        nonterminal: tuple[Literal["fetch", "construct", "boot", "verify"], ...] = (
            "fetch",
            "construct",
            "boot",
            "verify",
        )
        for stage in nonterminal:
            if self.fail_at_stage == stage:
                stages.append(
                    StageReport(
                        id=request.id,
                        stage="failed",
                        detail=f"injected failure at {stage}",
                        guests=guests,
                    )
                )
                self._report_log[request.id] = stages
                return stages
            stages.append(StageReport(id=request.id, stage=stage, guests=guests))
        stages.append(StageReport(id=request.id, stage="ready", guests=guests))
        self._report_log[request.id] = stages
        return stages


class LoopbackTransport:
    """In-memory `Transport`: every connection reaches a `FakeGuest` or the `FakeApplier` through the real codec."""

    def __init__(self, guests: Iterable[str] = ("guest",)) -> None:
        self.guests: dict[str, FakeGuest] = {name: FakeGuest(name) for name in guests}
        self.applier = FakeApplier()
        self._server_tasks: set[asyncio.Task[None]] = set()
        self._background: list[asyncio.Task[_StoredReply]] = []

    def guest(self, name: str) -> FakeGuest:
        return self.guests[name]

    async def connect(self, endpoint: str) -> ByteStream:
        if endpoint != HOST_APPLIER and endpoint not in self.guests:
            raise ConnectionError(f"no such endpoint: {endpoint}")
        client_side, server_side = stream_pair()
        task = asyncio.create_task(self._serve(endpoint, server_side))
        self._server_tasks.add(task)
        task.add_done_callback(self._reap)
        return client_side

    def _reap(self, task: asyncio.Task[None]) -> None:
        self._server_tasks.discard(task)
        if not task.cancelled() and task.exception() is not None:
            logger.error("loopback server task failed", exc_info=task.exception())

    async def _serve(self, endpoint: str, stream: MemoryStream) -> None:
        # the server side is the daemon side: accept inbound bulk up to the
        # daemon's cap (write payloads, exec stdin), like the Go daemon does
        reader = MessageStreamReader(stream.receive, bulk_cap=DAEMON_INBOUND_BULK_CAP)
        try:
            message, bulk = await reader.next()
        except (DecodeError, ChannelClosed):
            await stream.aclose()
            return
        if endpoint == HOST_APPLIER:
            await self._serve_host(message, stream)
            return
        guest = self.guests[endpoint]
        if isinstance(message, ExecRequest) and guest.close_mid_run:
            guest.close_mid_run = False
            self._background.append(
                asyncio.create_task(guest.start_exec(message, bulk or b""))
            )  # the command keeps running; this connection dies now
            await stream.aclose()
            return
        reply = await guest.handle(message, bulk)
        if guest.drop_next_reply:
            guest.drop_next_reply = False
            await stream.aclose()
            return
        for frame in encode_message(reply.message, reply.bulk):
            await stream.send(frame)
        await stream.aclose()

    async def _serve_host(self, message: Message, stream: MemoryStream) -> None:
        if isinstance(message, RealizeRequest):
            reports = self.applier.stage_reports(message)
            limit = len(reports)
            if self.applier.drop_after_reports is not None:
                limit = min(limit, self.applier.drop_after_reports)
                self.applier.drop_after_reports = None
            for report in reports[:limit]:
                for frame in encode_message(report, None):
                    await stream.send(frame)
        elif isinstance(message, TeardownRequest):
            if self.applier.fail_teardown_times > 0:
                self.applier.fail_teardown_times -= 1
                error = ErrorReply(
                    id=message.id, errno="EBUSY", message="injected teardown failure"
                )
                for frame in encode_message(error, None):
                    await stream.send(frame)
                await stream.aclose()
                return
            self.applier.torn_down = True
            for frame in encode_message(OkReply(id=message.id), None):
                await stream.send(frame)
        else:
            error = ErrorReply(
                id=message.id, errno="EPROTO", message=f"host plane got {message.kind}"
            )
            for frame in encode_message(error, None):
                await stream.send(frame)
        await stream.aclose()

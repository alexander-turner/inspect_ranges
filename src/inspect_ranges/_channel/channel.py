"""The `RangeChannel` seam: transport-agnostic control plane to one sample's range.

`MessageChannel` implements the seam from `host-provider.md` over any `Transport` (per-operation connect, the resolved connection model). It owns the client-side message contract: request ids with idempotent resend, recovery of lost replies by resending the same id (the endpoint deduplicates), acknowledgement of consumed results, layered budgets, strict validation of every reply as untrusted input, and a bounded wire-trace tail that is dumped on failure.

`LoopbackTransport` is the in-memory reference endpoint: frames travel through the real codec in both directions to a `FakeGuest` fleet and a `FakeApplier`, so the conformance suite exercises the genuine client logic with no VM behind it.

`SampleStateMachine` is the driver-side sample lifecycle (acquire, realize, verify, execute, finalize evidence, destroy) with observable transitions; illegal transitions are rejected, never absorbed.
"""

import asyncio
import enum
import hashlib
import logging
import time
import uuid
from collections import deque
from collections.abc import AsyncIterator, Awaitable, Callable, Iterable, Sequence
from dataclasses import dataclass
from typing import Protocol

from .codec import (
    ChannelClosed,
    DecodeError,
    MessageStreamReader,
    TraceEvent,
    TruncatedFrame,
    encode_message,
)
from .protocol import (
    DEFAULT_BULK_CAP,
    AckRequest,
    BudgetLayer,
    DiagEntry,
    DiagReply,
    DiagRequest,
    ErrorReply,
    ExecRequest,
    ExecResult,
    FileData,
    GuestState,
    Message,
    OkReply,
    PingRequest,
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
_CHANNEL_GRACE_S = 8.0
"""Added to the in-guest command budget when waiting for an exec reply, so the guest's own kill is observed rather than raced (the poll-grace lesson)."""

_TRACE_TAIL = 256


class ChannelError(Exception):
    """Base for every channel-layer failure."""


class TamperError(ChannelError):
    """The endpoint produced something an honest implementation cannot: surfaced, never parsed around."""


class TransportFailure(ChannelError):
    """The transport could not complete the exchange within its retry budget."""


class ChannelBudgetError(ChannelError):
    """A time budget fired; `layer` names which one, so timeout triage is mechanical."""

    def __init__(self, layer: BudgetLayer, message: str) -> None:
        super().__init__(f"[{layer}] {message}")
        self.layer: BudgetLayer = layer


class GuestError(ChannelError):
    """An honest, errno-tagged failure reported by the endpoint."""

    def __init__(
        self, errno: str, message: str, layer: BudgetLayer | None = None
    ) -> None:
        super().__init__(f"{errno}: {message}")
        self.errno = errno
        self.layer = layer


class IllegalTransition(ChannelError):
    """A sample lifecycle transition the state machine does not permit."""


@dataclass
class ExecOutcome:
    """Validated exec result with the bulk split back into streams."""

    rc: int
    stdout: bytes
    stderr: bytes
    stdout_truncated: bool
    stderr_truncated: bool


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
    async def write_file(self, guest: str, path: str, data: bytes) -> None: ...
    async def ping(self, guest: str) -> PongReply: ...
    async def diag(self, guest: str, *, max_entries: int = 100) -> list[DiagEntry]: ...
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
    ) -> None:
        self._transport = transport
        self._label = label
        self._channel_budget_s = channel_budget_s
        self._untimed_bound_s = untimed_bound_s
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

    # -- the exchange core -------------------------------------------------

    async def _exchange(
        self,
        endpoint: str,
        request: Message,
        bulk: bytes | None,
        *,
        reply_budget_s: float,
        bulk_cap: int,
        budget_layer: BudgetLayer,
    ) -> tuple[Message, bytes | None]:
        """One request/reply exchange with idempotent resend on lost replies.

        A dropped connection or truncated reply is recovered by reconnecting and resending the identical request (the endpoint deduplicates on id). Any reply shape an honest endpoint cannot produce raises `TamperError` immediately, with the trace tail dumped to the log.
        """
        frames = encode_message(request, bulk, trace=self._trace.append)
        last_failure = ""
        self._log(
            logging.DEBUG,
            "request",
            rid=request.id,
            endpoint=endpoint,
            detail=request.kind,
        )
        for attempt in range(1, _RETRY_ATTEMPTS + 1):
            try:
                async with asyncio.timeout(reply_budget_s):
                    stream = await self._transport.connect(endpoint)
                    self.stats.connects += 1
                    try:
                        for frame in frames:
                            await stream.send(frame)
                        reader = MessageStreamReader(
                            stream.receive, bulk_cap=bulk_cap, trace=self._trace.append
                        )
                        reply, reply_bulk = await reader.next()
                    finally:
                        await stream.aclose()
            except TimeoutError:
                self._dump_trace(request, endpoint, f"budget expired ({budget_layer})")
                raise ChannelBudgetError(
                    budget_layer,
                    f"{request.kind} id={request.id}: no reply within {reply_budget_s:.1f}s",
                ) from None
            except (ConnectionError, ChannelClosed, TruncatedFrame) as failure:
                last_failure = f"{type(failure).__name__}: {failure}"
                self._log(
                    logging.WARNING,
                    "retry",
                    rid=request.id,
                    endpoint=endpoint,
                    detail=f"attempt {attempt}/{_RETRY_ATTEMPTS}: {last_failure}",
                )
                await asyncio.sleep(_RETRY_BACKOFF_S * attempt)
                continue
            except DecodeError as failure:
                self._dump_trace(request, endpoint, str(failure))
                raise TamperError(
                    f"{request.kind} id={request.id}: {type(failure).__name__}: {failure}"
                ) from failure
            self.stats.exchanges += 1
            if reply.id != request.id:
                self._dump_trace(request, endpoint, f"reply id {reply.id}")
                raise TamperError(
                    f"{request.kind} id={request.id}: reply carries id {reply.id}"
                )
            if isinstance(reply, ErrorReply):
                if reply.errno == "ETIME" and reply.layer is not None:
                    raise ChannelBudgetError(reply.layer, reply.message)
                raise GuestError(reply.errno, reply.message, reply.layer)
            self._log(
                logging.DEBUG,
                "reply",
                rid=request.id,
                endpoint=endpoint,
                detail=reply.kind,
            )
            return reply, reply_bulk
        self._dump_trace(request, endpoint, last_failure)
        raise TransportFailure(
            f"{request.kind} id={request.id}: reply lost after {_RETRY_ATTEMPTS} attempts ({last_failure})"
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

    def _expect[ReplyT: Message](
        self, reply: Message, expected: type[ReplyT], request: Message
    ) -> ReplyT:
        if not isinstance(reply, expected):
            raise TamperError(
                f"{request.kind} id={request.id}: expected {expected.__name__}, got {reply.kind}"
            )
        return reply

    async def _ack(self, endpoint: str, target_id: str) -> None:
        """Best-effort acknowledgement; the endpoint may then drop its stored reply."""
        ack = AckRequest(id=request_id(), target_id=target_id)
        try:
            reply, _ = await self._exchange(
                endpoint,
                ack,
                None,
                reply_budget_s=self._channel_budget_s,
                bulk_cap=DEFAULT_BULK_CAP,
                budget_layer="channel",
            )
            self._expect(reply, OkReply, ack)
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
        request = PingRequest(id=request_id())
        reply, _ = await self._exchange(
            guest,
            request,
            None,
            reply_budget_s=self._channel_budget_s,
            bulk_cap=DEFAULT_BULK_CAP,
            budget_layer="channel",
        )
        return self._expect(reply, PongReply, request)

    async def exec(
        self, guest: str, request: ExecRequest, *, stdin: bytes | None = None
    ) -> ExecOutcome:
        """Run `request` in the guest; `stdin` must match the request's `data_size` declaration."""
        if (request.data_size is None) != (stdin is None) or (
            request.data_size or 0
        ) != len(stdin or b""):
            raise ValueError("stdin must match the request's data_size declaration")
        if request.budget.command_ms is not None:
            reply_budget_s = request.budget.command_ms / 1000 + _CHANNEL_GRACE_S
            budget_layer: BudgetLayer = "command"
        else:
            reply_budget_s = min(
                self._untimed_bound_s, request.budget.untimed_bound_ms / 1000
            )
            budget_layer = "untimed"
        reply, bulk = await self._exchange(
            guest,
            request,
            stdin,
            reply_budget_s=reply_budget_s,
            bulk_cap=2 * DEFAULT_BULK_CAP,
            budget_layer=budget_layer,
        )
        result = self._expect(reply, ExecResult, request)
        payload = bulk or b""
        stdout = payload[: result.stdout_size]
        stderr = payload[result.stdout_size : result.stdout_size + result.stderr_size]
        await self._ack(guest, request.id)
        return ExecOutcome(
            rc=result.rc,
            stdout=stdout,
            stderr=stderr,
            stdout_truncated=result.stdout_truncated,
            stderr_truncated=result.stderr_truncated,
        )

    async def read_file(
        self, guest: str, path: str, *, cap: int = DEFAULT_BULK_CAP
    ) -> bytes:
        request = ReadFileRequest(id=request_id(), path=path, max_bytes=cap)
        reply, bulk = await self._exchange(
            guest,
            request,
            None,
            reply_budget_s=self._channel_budget_s,
            bulk_cap=cap,
            budget_layer="channel",
        )
        self._expect(reply, FileData, request)
        await self._ack(guest, request.id)
        return bulk or b""

    async def write_file(self, guest: str, path: str, data: bytes) -> None:
        request = WriteFileRequest(id=request_id(), path=path, data_size=len(data))
        reply, _ = await self._exchange(
            guest,
            request,
            data,
            reply_budget_s=self._channel_budget_s,
            bulk_cap=DEFAULT_BULK_CAP,
            budget_layer="channel",
        )
        self._expect(reply, OkReply, request)
        await self._ack(guest, request.id)

    async def diag(self, guest: str, *, max_entries: int = 100) -> list[DiagEntry]:
        request = DiagRequest(id=request_id(), max_entries=max_entries)
        reply, _ = await self._exchange(
            guest,
            request,
            None,
            reply_budget_s=self._channel_budget_s,
            bulk_cap=DEFAULT_BULK_CAP,
            budget_layer="channel",
        )
        return self._expect(reply, DiagReply, request).entries

    # -- host lifecycle plane -----------------------------------------------

    async def realize(
        self, bundle_digest: Sha256Hex, grants: Sequence[str]
    ) -> AsyncIterator[StageReport]:
        """Stream stage reports until `ready` or `failed` (schemas live; applier mocked until the provider phase)."""
        request = RealizeRequest(
            id=request_id(), bundle_digest=bundle_digest, grants=list(grants)
        )
        stream = await self._transport.connect(HOST_APPLIER)
        self.stats.connects += 1
        self._log(
            logging.INFO,
            "realize",
            rid=request.id,
            endpoint=HOST_APPLIER,
            detail=bundle_digest,
        )
        try:
            for frame in encode_message(request, None, trace=self._trace.append):
                await stream.send(frame)
            reader = MessageStreamReader(
                stream.receive, bulk_cap=DEFAULT_BULK_CAP, trace=self._trace.append
            )
            while True:
                try:
                    async with asyncio.timeout(self._channel_budget_s):
                        message, _ = await reader.next()
                except TimeoutError:
                    self._dump_trace(
                        request, HOST_APPLIER, "stage report budget expired"
                    )
                    raise ChannelBudgetError(
                        "channel",
                        f"realize id={request.id}: no stage report within budget",
                    ) from None
                except ChannelClosed:
                    self._dump_trace(
                        request, HOST_APPLIER, "stream closed before ready/failed"
                    )
                    raise TamperError(
                        f"realize id={request.id}: stream ended before a terminal stage"
                    ) from None
                except DecodeError as failure:
                    self._dump_trace(request, HOST_APPLIER, str(failure))
                    raise TamperError(
                        f"realize id={request.id}: {failure}"
                    ) from failure
                self.stats.exchanges += 1
                report = self._expect(message, StageReport, request)
                if report.id != request.id:
                    raise TamperError(
                        f"realize id={request.id}: report carries id {report.id}"
                    )
                self._log(
                    logging.INFO,
                    "stage",
                    rid=request.id,
                    endpoint=HOST_APPLIER,
                    detail=f"{report.stage} {report.detail}".strip(),
                )
                yield report
                if report.stage in ("ready", "failed"):
                    return
        finally:
            await stream.aclose()

    async def teardown(self) -> None:
        request = TeardownRequest(id=request_id())
        reply, _ = await self._exchange(
            HOST_APPLIER,
            request,
            None,
            reply_budget_s=self._channel_budget_s,
            bulk_cap=DEFAULT_BULK_CAP,
            budget_layer="channel",
        )
        self._expect(reply, OkReply, request)


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
    """Observable sample lifecycle; illegal transitions raise, never absorb."""

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
            observer(previous, phase)


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

    On any phase failure the machine moves to `failed`, teardown still runs, and the original failure re-raises; the machine's history records exactly what happened.
    """
    machine = machine or SampleStateMachine()
    machine.to(SamplePhase.ACQUIRED)
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
        await channel.teardown()
    except BaseException:
        machine.to(SamplePhase.FAILED)
        machine.to(SamplePhase.DESTROYED)
        try:
            await channel.teardown()
        except ChannelError as teardown_failure:
            # best effort on the failure path: never mask the original failure
            logger.error("teardown after failure also failed: %s", teardown_failure)
        raise
    machine.to(SamplePhase.DESTROYED)
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

    Implements the daemon-side contract the conformance suite checks: request-id dedupe (a resent id attaches to the running command or returns the stored result; the command runs once), durable replies held until acked, in-guest command budgets, and errno-tagged file errors. `drop_next_reply` simulates a reply lost in flight; `close_mid_run` simulates a connection dying while the command runs.
    """

    def __init__(self, name: str) -> None:
        self.name = name
        self.files: dict[str, bytes] = {}
        self.directories: set[str] = {"/", "/tmp"}
        self.exec_count = 0
        self.drop_next_reply = False
        self.close_mid_run = False
        self._stored: dict[str, _StoredReply] = {}
        self._running: dict[str, asyncio.Task[_StoredReply]] = {}
        self._handlers: dict[str, ExecHandler] = {}
        self.diag_entries: list[DiagEntry] = []

    def register(self, command: str, handler: ExecHandler) -> None:
        self._handlers[command] = handler

    def stored_reply_count(self) -> int:
        return len(self._stored)

    # -- daemon behavior ----------------------------------------------------

    async def handle(self, message: Message, bulk: bytes | None) -> _StoredReply | None:
        """Produce the reply for one request; `None` means drop the connection without replying."""
        if isinstance(message, PingRequest):
            return _StoredReply(
                PongReply(id=message.id, daemon=f"fake {self.name}"), None
            )
        if isinstance(message, AckRequest):
            self._stored.pop(message.target_id, None)
            return _StoredReply(OkReply(id=message.id), None)
        if isinstance(message, DiagRequest):
            entries = self.diag_entries[-message.max_entries :]
            return _StoredReply(DiagReply(id=message.id, entries=entries), None)
        if isinstance(message, ExecRequest):
            return await self.start_exec(message, bulk or b"")
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
        try:
            return await asyncio.shield(task)
        finally:
            if task.done():
                self._running.pop(request.id, None)

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
            if request.budget.command_ms is not None:
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
            self._stored[request.id] = reply
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
        self._stored[request.id] = reply
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
        reply = _StoredReply(
            FileData(id=request.id, size=len(data), data_size=len(data) or None),
            data if data else None,
        )
        self._stored[request.id] = reply
        return reply

    def _write(self, request: WriteFileRequest, data: bytes) -> _StoredReply:
        self.files[request.path] = data
        reply = _StoredReply(OkReply(id=request.id), None)
        self._stored[request.id] = reply
        return reply


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
    """In-memory host applier endpoint: realize streams stage reports, teardown acknowledges."""

    def __init__(self) -> None:
        self.fail_at_stage: str | None = None
        self.fail_teardown = False
        self.torn_down = False
        self.realized_digests: list[str] = []

    def stage_reports(self, request: RealizeRequest) -> list[StageReport]:
        self.realized_digests.append(request.bundle_digest)
        stages: list[StageReport] = []
        guests: dict[str, GuestState] = {}
        for stage in ("fetch", "construct", "boot", "verify"):
            if self.fail_at_stage == stage:
                stages.append(
                    StageReport(
                        id=request.id,
                        stage="failed",
                        detail=f"injected failure at {stage}",
                        guests=guests,
                    )
                )
                return stages
            stages.append(StageReport(id=request.id, stage=stage, guests=guests))  # type: ignore[arg-type]
        stages.append(StageReport(id=request.id, stage="ready", guests=guests))
        return stages


class LoopbackTransport:
    """In-memory `Transport`: every connection reaches a `FakeGuest` or the `FakeApplier` through the real codec."""

    def __init__(self, guests: Iterable[str] = ("guest",)) -> None:
        self.guests: dict[str, FakeGuest] = {name: FakeGuest(name) for name in guests}
        self.applier = FakeApplier()
        self._background: list[asyncio.Task[_StoredReply]] = []

    def guest(self, name: str) -> FakeGuest:
        return self.guests[name]

    async def connect(self, endpoint: str) -> ByteStream:
        if endpoint != HOST_APPLIER and endpoint not in self.guests:
            raise ConnectionError(f"no such endpoint: {endpoint}")
        client_side, server_side = stream_pair()
        asyncio.create_task(self._serve(endpoint, server_side))
        return client_side

    async def _serve(self, endpoint: str, stream: MemoryStream) -> None:
        reader = MessageStreamReader(stream.receive, bulk_cap=2 * DEFAULT_BULK_CAP)
        try:
            message, bulk = await reader.next()
        except DecodeError:
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
        if reply is None or guest.drop_next_reply:
            guest.drop_next_reply = False
            await stream.aclose()
            return
        for frame in encode_message(reply.message, reply.bulk):
            await stream.send(frame)
        await stream.aclose()

    async def _serve_host(self, message: Message, stream: MemoryStream) -> None:
        if isinstance(message, RealizeRequest):
            for report in self.applier.stage_reports(message):
                for frame in encode_message(report, None):
                    await stream.send(frame)
        elif isinstance(message, TeardownRequest):
            if self.applier.fail_teardown:
                self.applier.fail_teardown = False
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


def digest_of(data: bytes) -> Sha256Hex:
    """sha256 hex of `data` (test and loopback convenience)."""
    return hashlib.sha256(data).hexdigest()

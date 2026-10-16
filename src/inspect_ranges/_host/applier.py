"""The applier endpoint: one unix listener serving both planes of the separated topology.

One `asyncio` server behind a 0600 socket in a 0700 directory (same-uid trust; TCP/mTLS deferred). Every connection opens with the routing preamble (`_channel/uds.py`); every routing failure (unknown lease, expired or reaping lease on the guest plane, unknown guest, guest dial failure) closes the connection WITHOUT the ack, before any request bytes exist, so the client's `ConnectionError` provably means the request never left. The host plane (`@host`) stays routable for any lease that still EXISTS, whatever its state: the reaper tears down `reaping` leases through this socket, and refusing it at the preamble would strand them (the recorded guest-plane rule is unchanged: expired or reaping leases are refused there).

Realize per the record: resolve the lease's bundle path, verify the requested digest against the manifest bytes (`EINVAL` on mismatch), enforce the grants convention (empty means pre-seeded; non-empty refuses `ENOTSUP`), charge the applier's own `WeightedAdmission` from the bundle's plan totals (`EAGAIN` full-now, `ENOSPC` range-exceeds-host; refuse, never queue), then run `up` in a worker thread with the stage translation. The replay log stores the TRANSLATED stream keyed by request id (the translator is terminal-latching, so raw up events are never re-fed), honoring the identical-replay contract for resumed streams; refusals are never memoized. A raised `UpError` is fed to the translator as the synthetic `(error.stage, "fail")` event, exactly the `stages.py` contract for failures that never reach `on_stage`.

Guest endpoints relay as pure byte pumps (never parsed) through the injectable guest connector (`VsockTransport` dial in production), inheriting its pacing and backoff; guest names are lease-scoped, so concurrent samples with identical names cannot cross.

Applier restart loses the replay log, relay map, and admission charges: a recorded v1 limitation, loudly logged at startup when live leases exist, with disk-driven teardown (reaper, `cli_cleanup`) as the recovery. The lost evidence writer map leaves the host record unsealed; a surviving driver reap-seals it on its host-seal miss path at teardown (before it releases the lease), and the reaper or `cli_cleanup` reap-seal when the driver is dead.
"""

import asyncio
import hashlib
import logging
import os
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from .._channel.channel import HOST_APPLIER, ByteStream
from .._channel.codec import (
    ChannelClosed,
    DecodeError,
    MessageStreamReader,
    encode_message,
)
from .._channel.protocol import (
    DAEMON_INBOUND_BULK_CAP,
    ErrorReply,
    GuestState,
    Heartbeat,
    Message,
    OkReply,
    PingRequest,
    RealizeRequest,
    StageReport,
    TeardownRequest,
)
from .._channel.uds import ROUTED_ACK, read_preamble
from .._compiler.plan import ResolvedPlan, Totals
from .._doctor.checks import readiness_failures
from .._evidence.capture import (
    CAPTURE_HARVEST_TIMEOUT_S,
    CAPTURE_STOP_TIMEOUT_S,
    CaptureStreamer,
    ComposeTap,
    StageRecorder,
)
from .._evidence.s3 import sink_for_location
from .._evidence.sink import EvidenceWriter
from .._provider.admission import AdmissionRefused, HostCapacity, WeightedAdmission
from .._provider.evidence import evidence_buffer_bytes, evidence_max_bytes
from .._runtime.down import DownResult
from .._runtime.down import down as run_down
from .._runtime.up import OnStage, UpError, UpOptions, UpResult, up
from .leases import HostLease, LeaseStore
from .local import GateFn, HostNotReadyError
from .stages import SeamStage, StageTranslator

logger = logging.getLogger("inspect_ranges.applier")

ApplierUpFn = Callable[[Path, UpOptions, OnStage], UpResult]
ApplierDownFn = Callable[[str, Path], DownResult]
GuestConnector = Callable[[int], Awaitable[ByteStream]]

_PREAMBLE_TIMEOUT_S = 5.0
_HOST_REQUEST_TIMEOUT_S = 30.0
"""Post-ack budget for the host plane's single request frame to arrive."""
_PUMP_CHUNK = 1 << 16
_PUMP_LINGER_S = 30.0

_EVIDENCE_SEAL_RESERVE_S = 10.0
"""The stop budget's reserved seal share: a wedged capture stop can never starve the seal (or the shutdown checkpoint) attempt (quality-review A6, mirroring the driver's finalize phases)."""
_COMPLETED_RUN_CAP = 64
"""Completed realize runs kept for replay; FIFO-evicted beyond this (the replay-log memory bound).

Eviction edge, stated: a same-id resend arriving after 64 intervening completions no longer finds its run, so it re-executes a failed run or refuses `EBUSY` on a still-charged one instead of replaying. Practically unreachable in v1: a driver resumes within seconds, and one lease sees one realize.
"""


def _default_up(bundle: Path, options: UpOptions, on_stage: OnStage) -> UpResult:
    return up(bundle, options, on_stage=on_stage)


def _default_down(project: str, state_dir: Path) -> DownResult:
    return run_down(project, state_dir=state_dir)


async def _default_guest_connect(cid: int) -> ByteStream:
    from .._channel.vsock import VsockTransport

    return await VsockTransport({"guest": cid}).connect("guest")


@dataclass
class _RealizeRun:
    """One realize execution's translated report log plus the live-stream condition."""

    reports: list[StageReport] = field(default_factory=list[StageReport])
    done: bool = False
    changed: asyncio.Condition = field(default_factory=asyncio.Condition)

    async def append(self, report: StageReport) -> None:
        async with self.changed:
            self.reports.append(report)
            self.changed.notify_all()

    async def finish(self) -> None:
        async with self.changed:
            self.done = True
            self.changed.notify_all()


class Applier:
    """The applier endpoint over one unix socket (see the module docstring).

    The `up_fn`/`down_fn`/`guest_connector`/`gate` seams are injectable for CI; defaults are the real `up`, `down`, vsock dial, and doctor readiness subset.
    """

    def __init__(
        self,
        socket_path: Path | str,
        state_dir: Path,
        *,
        image_cache: Path,
        up_fn: ApplierUpFn = _default_up,
        down_fn: ApplierDownFn = _default_down,
        guest_connector: GuestConnector | None = None,
        store: LeaseStore | None = None,
        capacity: HostCapacity | None = None,
        gate: GateFn | None = None,
        preamble_timeout_s: float = _PREAMBLE_TIMEOUT_S,
    ) -> None:
        self._socket_path = Path(socket_path)
        self._state_dir = state_dir
        self._image_cache = image_cache
        self._up_fn = up_fn
        self._down_fn = down_fn
        self._guest_connect = guest_connector or _default_guest_connect
        self._store = store if store is not None else LeaseStore(state_dir)
        self._capacity = capacity if capacity is not None else HostCapacity.measure()
        self._gate = gate if gate is not None else readiness_failures
        self._preamble_timeout_s = preamble_timeout_s
        self._admission: WeightedAdmission | None = None
        self._server: asyncio.Server | None = None
        self._bound_stat: os.stat_result | None = None
        self._started = time.monotonic()
        self._runs: dict[str, _RealizeRun] = {}
        self._lease_locks: dict[str, asyncio.Lock] = {}
        self._relays: dict[str, dict[str, int]] = {}
        self._guest_states: dict[str, dict[str, GuestState]] = {}
        self._charges: dict[str, Totals] = {}
        self._plans: dict[str, ResolvedPlan] = {}
        """The refusal gate's parsed plan per charged lease (evidence wiring reads it in _execute; popped with the charge)."""
        self._tasks: set[asyncio.Task[None]] = set()
        self._evidence: dict[
            str, tuple[CaptureStreamer, EvidenceWriter, list[str]]
        ] = {}
        """Per-lease capture: the applier owns the `host` writer in the separated topology (`evidence-v1.md` slice 5); lost on applier restart like the relay map (the recorded limitation; a surviving driver reap-seals on its host-seal miss at teardown, the reaper after lease expiry)."""

    @property
    def admission(self) -> WeightedAdmission:
        if self._admission is None:
            self._admission = WeightedAdmission(self._capacity)
        return self._admission

    async def start(self) -> None:
        """Gate on doctor readiness, then listen (0600 socket in a 0700 directory).

        Raises:
            HostNotReadyError: The readiness subset reports failures; an unhealthy host refuses to serve.
        """
        failures = await asyncio.to_thread(self._gate)
        if failures:
            raise HostNotReadyError(
                "the applier host fails doctor readiness: "
                + "; ".join(failures)
                + " (run: inspect-ranges doctor)"
            )
        live = [
            lease for lease in self._store.leases() if lease.origin.startswith("uds:")
        ]
        if live:
            logger.warning(
                "applier starting with %d live uds lease(s): any prior applier's "
                "replay log, relay map, and admission charges are LOST (recorded "
                "v1 limitation); recovery is disk-driven teardown (the reaper, "
                "cli_cleanup)",
                len(live),
            )
        parent = self._socket_path.parent
        if not parent.exists():
            # 0700 only on a directory the applier itself creates; rewriting
            # the permissions of an operator's existing directory (worst
            # case: their home) is never ours to do
            parent.mkdir(parents=True)
            os.chmod(parent, 0o700)
        self._socket_path.unlink(missing_ok=True)
        self._server = await asyncio.start_unix_server(
            self._serve, path=str(self._socket_path)
        )
        os.chmod(self._socket_path, 0o600)
        self._bound_stat = self._socket_path.stat()
        self._started = time.monotonic()
        logger.info("applier serving on %s", self._socket_path)

    async def aclose(self) -> None:
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()
            self._server = None
        # unlink only OUR bind: a replacement applier may already own a
        # fresh socket at this path (start-new-then-stop-old supervision),
        # and the old process's shutdown must never delete it
        try:
            current = self._socket_path.stat()
            if self._bound_stat is not None and (
                current.st_ino,
                current.st_dev,
            ) == (self._bound_stat.st_ino, self._bound_stat.st_dev):
                self._socket_path.unlink()
        except OSError:
            pass
        for lease_id in list(self._evidence):
            # bounded best-effort flush on shutdown, NEVER a seal: a sample may
            # still be running, and a `complete` seal here would make a
            # capture cutoff indistinguishable from a record that ran to
            # teardown. The record stays unsealed with an explicit shutdown
            # gap; a reap-seal closes it honestly (the recorded restart
            # limitation). _stop_evidence is internally bounded exactly like
            # the teardown arm; no outer timeout, which would cancel its own
            # gap-recording handlers mid-write (review finding on A6; the
            # round-2 review found this arm's 5 s outer bound was smaller than
            # the stop phase it wrapped, so a slow real harvest lost the
            # promised applier-shutdown gaps and checkpoint unmarked).
            await self._stop_evidence(lease_id, seal=False)
        for task in list(self._tasks):
            task.cancel()

    # -- routing ---------------------------------------------------------------

    async def _serve(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        """One connection: route (refuse without the ack), then serve or relay. Never crashes the server."""
        try:
            await self._serve_routed(reader, writer)
        except (ConnectionError, OSError) as loss:
            # a client vanishing mid-operation is the designed loss-resume
            # path (same-id resend), not a handler failure
            logger.debug("connection dropped mid-operation (loss-resume): %s", loss)
        except Exception:
            logger.exception("applier connection handler failed (connection dropped)")
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except (OSError, ConnectionError):
                pass

    async def _serve_routed(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        try:
            lease_id, endpoint = await read_preamble(
                reader, timeout_s=self._preamble_timeout_s
            )
        except (ValueError, TimeoutError, asyncio.IncompleteReadError) as refusal:
            logger.warning("routing refused: bad preamble (%s)", refusal)
            return
        lease = self._store.get(lease_id)
        if lease is None:
            logger.warning("routing refused: unknown lease %s", lease_id)
            return
        if endpoint == HOST_APPLIER:
            # the host plane stays routable in ANY lease state: the reaper
            # tears reaping leases down through this very socket
            writer.write(ROUTED_ACK)
            await writer.drain()
            await self._serve_host(lease, reader, writer)
            return
        if lease.state != "active" or lease.expires() <= datetime.now(UTC):
            logger.warning(
                "routing refused: lease %s is %s (guest plane requires an "
                "active, unexpired lease)",
                lease_id,
                lease.state if lease.state != "active" else "expired",
            )
            return
        cid = self._relays.get(lease_id, {}).get(endpoint)
        if cid is None:
            logger.warning(
                "routing refused: lease %s has no guest %r", lease_id, endpoint
            )
            return
        try:
            upstream = await self._guest_connect(cid)
        except Exception as failure:
            logger.warning(
                "routing refused: guest %r (cid %d) dial failed: %s",
                endpoint,
                cid,
                failure,
            )
            return
        writer.write(ROUTED_ACK)
        await writer.drain()
        await self._pump(reader, writer, upstream)

    # -- the guest byte pump -----------------------------------------------------

    async def _pump(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        upstream: ByteStream,
    ) -> None:
        """Pump bytes both ways, never parsing a frame; propagate EOF each way and leak no fds on cancellation."""

        async def client_to_guest() -> None:
            try:
                while data := await reader.read(_PUMP_CHUNK):
                    await upstream.send(data)
            except (OSError, ConnectionError):
                pass
            finally:
                # the client closes only after consuming its reply (an early
                # close is a cancelled operation, where dropping the guest
                # stream IS the loss semantics): propagate the close upstream
                # so the guest side never dangles until the linger
                await upstream.aclose()

        async def guest_to_client() -> None:
            try:
                while data := await upstream.receive():
                    writer.write(data)
                    await writer.drain()
            except (OSError, ConnectionError):
                pass
            try:
                writer.write_eof()  # half-close toward the client: the guest is done talking
            except (OSError, RuntimeError):
                pass

        directions = [
            asyncio.ensure_future(client_to_guest()),
            asyncio.ensure_future(guest_to_client()),
        ]
        try:
            _, pending = await asyncio.wait(
                directions, return_when=asyncio.FIRST_COMPLETED
            )
            if pending:
                # one side closed; give the other a bounded linger, then cut
                try:
                    await asyncio.wait(pending, timeout=_PUMP_LINGER_S)
                finally:
                    for task in pending:
                        task.cancel()
        finally:
            for task in directions:
                task.cancel()
            await upstream.aclose()

    # -- the host plane ------------------------------------------------------------

    async def _serve_host(
        self,
        lease: HostLease,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        message_reader = MessageStreamReader(
            lambda: reader.read(_PUMP_CHUNK), bulk_cap=DAEMON_INBOUND_BULK_CAP
        )
        try:
            # bounded like the preamble: an acked-but-silent client must not
            # pin a server task for the applier's lifetime
            async with asyncio.timeout(_HOST_REQUEST_TIMEOUT_S):
                message, _ = await message_reader.next()
        except (DecodeError, ChannelClosed, TimeoutError):
            return
        if isinstance(message, PingRequest):
            await self._send(
                writer,
                Heartbeat(
                    id=message.id,
                    uptime_ms=int((time.monotonic() - self._started) * 1000),
                    guests=dict(self._guest_states.get(lease.lease_id, {})),
                ),
            )
            return
        if isinstance(message, TeardownRequest):
            await self._teardown(lease, message, writer)
            return
        if isinstance(message, RealizeRequest):
            await self._realize(lease, message, writer)
            return
        await self._send(
            writer,
            ErrorReply(
                id=message.id, errno="EPROTO", message=f"host plane got {message.kind}"
            ),
        )

    async def _send(self, writer: asyncio.StreamWriter, message: Message) -> None:
        for frame in encode_message(message, None):
            writer.write(frame)
        await writer.drain()

    async def _teardown(
        self, lease: HostLease, request: TeardownRequest, writer: asyncio.StreamWriter
    ) -> None:
        """Harvest and seal capture, drive `down`, then release the admission charge and the relay map (idempotent; retriable)."""
        # before down: the capture sidecar and its volume die with the
        # project, so the final harvest must happen while they live
        await self._stop_evidence(lease.lease_id)
        try:
            await asyncio.to_thread(self._down_fn, lease.project, self._state_dir)
        except Exception as error:
            logger.error("teardown of %s failed: %s", lease.project, error)
            await self._send(
                writer, ErrorReply(id=request.id, errno="EIO", message=str(error))
            )
            return
        charge = self._charges.pop(lease.lease_id, None)
        if charge is not None:
            await self.admission.release(charge)
        self._plans.pop(lease.lease_id, None)
        self._relays.pop(lease.lease_id, None)
        self._guest_states.pop(lease.lease_id, None)
        self._lease_locks.pop(lease.lease_id, None)
        logger.info(
            "teardown: lease=%s project=%s (charge and relay map released)",
            lease.lease_id,
            lease.project,
        )
        await self._send(writer, OkReply(id=request.id))

    # -- realize ---------------------------------------------------------------------

    async def _realize(
        self, lease: HostLease, request: RealizeRequest, writer: asyncio.StreamWriter
    ) -> None:
        run = self._runs.get(request.id)
        if run is None:
            # the refusal gate awaits (manifest and plan reads), so without
            # serialization two gathered fresh-id realizes on one lease both
            # pass the charge check: the one-realize-per-lease invariant must
            # hold under concurrency, with exactly one charge and the loser
            # refused EBUSY
            lock = self._lease_locks.setdefault(lease.lease_id, asyncio.Lock())
            async with lock:
                run = self._runs.get(request.id)  # a same-id raced us here
                if run is None:
                    refusal = await self._refusal(lease, request)
                    if refusal is not None:
                        errno, detail = refusal
                        logger.warning(
                            "realize refused: lease=%s %s: %s",
                            lease.lease_id,
                            errno,
                            detail,
                        )
                        # refusals are never memoized: a later realize re-checks
                        await self._send(
                            writer,
                            ErrorReply(id=request.id, errno=errno, message=detail),
                        )
                        return
                    run = _RealizeRun()
                    self._runs[request.id] = run
                    task = asyncio.create_task(self._execute(lease, request, run))
                    self._tasks.add(task)
                    task.add_done_callback(self._tasks.discard)
        # stream the run's reports (live or replayed identically from the log)
        index = 0
        while True:
            async with run.changed:
                while index >= len(run.reports) and not run.done:
                    await run.changed.wait()
                reports = run.reports[index:]
                done = run.done
            for report in reports:
                await self._send(writer, report)
                index += 1
            if done and index >= len(run.reports):
                return

    async def _refusal(
        self, lease: HostLease, request: RealizeRequest
    ) -> tuple[str, str] | None:
        """The typed-refusal gate for a FRESH realize: grants, lease state and expiry, one-realize-per-lease, digest, admission."""
        if request.grants:
            return (
                "ENOTSUP",
                "this deployment pre-seeds images; fetch grants are not supported",
            )
        if lease.state != "active":
            return ("EINVAL", f"lease {lease.lease_id} is {lease.state}")
        if lease.expires() <= datetime.now(UTC):
            # mirror the guest plane: an expired lease must not start a boot
            # the reaper's imminent teardown would race
            return ("EINVAL", f"lease {lease.lease_id} is expired")
        if lease.lease_id in self._charges:
            # one realize per lease: the held charge means a realize already
            # charged admission (and ran or is running up); a fresh-id
            # realize here would double-charge and re-run up against the
            # live project. Teardown releases the charge and re-opens the gate.
            return (
                "EBUSY",
                f"lease {lease.lease_id} already holds a realize; teardown first",
            )
        bundle = Path(lease.bundle_path)
        try:
            manifest_bytes = await asyncio.to_thread(
                (bundle / "manifest.json").read_bytes
            )
        except OSError as error:
            return (
                "EINVAL",
                f"lease bundle {bundle} has no readable manifest: {error}",
            )
        actual = hashlib.sha256(manifest_bytes).hexdigest()
        if actual != request.bundle_digest:
            return (
                "EINVAL",
                f"bundle digest {actual} does not match the requested "
                f"{request.bundle_digest}",
            )
        try:
            plan = await asyncio.to_thread(self._load_plan, bundle)
        except (OSError, ValueError) as error:
            return ("EINVAL", f"lease bundle {bundle} has no readable plan: {error}")
        totals = plan.totals
        if lease.evidence_location is not None and plan.requirements.evidence_capture:
            # the `host` evidence writer this realize will open is resident in
            # THIS process: its buffer cap joins the memory charge exactly as
            # the driver's resident writers join the sample's (`evidence-v1.md`
            # accounting; quality-review round 2). A malformed buffer knob
            # disables evidence at _start_evidence, so it charges nothing here
            # either.
            try:
                buffer_mb = evidence_buffer_bytes() // (1024 * 1024)
            except ValueError:
                buffer_mb = 0
            totals = totals.model_copy(
                update={"memory_mb": totals.memory_mb + buffer_mb}
            )
        try:
            charged = self.admission.charge_now(totals)
        except AdmissionRefused as refusal:
            return ("ENOSPC", str(refusal))
        if not charged:
            return ("EAGAIN", "applier capacity is full now; respin when it frees")
        self._charges[lease.lease_id] = totals
        self._plans[lease.lease_id] = plan
        self._guest_states[lease.lease_id] = dict.fromkeys(
            (guest.name for guest in plan.guests), "pending"
        )
        return None

    @staticmethod
    def _load_plan(bundle: Path) -> ResolvedPlan:
        return ResolvedPlan.model_validate_json((bundle / "plan.json").read_text())

    async def _execute(
        self, lease: HostLease, request: RealizeRequest, run: _RealizeRun
    ) -> None:
        """Run `up` in a worker thread, translating its stage log into the run's report stream."""
        loop = asyncio.get_running_loop()
        translator = StageTranslator()
        states = self._guest_states.setdefault(lease.lease_id, {})
        bundle = Path(lease.bundle_path)
        # the refusal gate parsed and cached the plan when it charged this lease
        plan = self._plans.get(lease.lease_id)
        evidence_on = (
            lease.evidence_location is not None
            and plan is not None
            and plan.requirements.evidence_capture
        )
        recorder = StageRecorder() if evidence_on else None

        async def emit(stage: SeamStage, detail: str) -> None:
            detail = detail[:3000]  # inside StageReport's wire cap, whatever up said
            if stage == "boot":
                for name in states:
                    states[name] = "booting"
            elif stage == "ready":
                for name in states:
                    states[name] = "ready"
            elif stage == "failed":
                for name in states:
                    states[name] = "failed"
            await run.append(
                StageReport(
                    id=request.id, stage=stage, detail=detail, guests=dict(states)
                )
            )

        def on_stage(stage: str, status: str, fields: dict[str, object]) -> None:
            if recorder is not None:
                # host emit clocks for the stages/verify streams; never raises
                recorder.on_stage(stage, status, fields)
            translated = translator.translate(stage, status, fields)
            if translated is not None:
                asyncio.run_coroutine_threadsafe(
                    emit(translated.stage, translated.detail), loop
                )

        options = UpOptions(
            project=lease.project,
            image_cache=self._image_cache,
            state_dir=self._state_dir,
        )
        failed = False
        try:
            result = await asyncio.to_thread(self._up_fn, bundle, options, on_stage)
        except UpError as error:
            # failures raised before the stage log exists never reach
            # on_stage: feed the synthetic event per the stages.py contract
            failed = True
            translated = translator.translate(
                error.stage, "fail", {"error": str(error)}
            )
            if translated is not None:
                await emit(translated.stage, translated.detail)
        except Exception as error:
            failed = True
            logger.exception("realize of %s crashed outside up()", lease.project)
            translated = translator.translate(
                "range-container", "fail", {"error": f"applier internal: {error}"}
            )
            if translated is not None:
                await emit(translated.stage, translated.detail)
        else:
            self._relays[lease.lease_id] = {
                guest.name: guest.cid for guest in result.guests
            }
            if evidence_on and plan is not None and recorder is not None:
                await self._start_evidence(lease, plan, recorder)
        if failed:
            charge = self._charges.pop(lease.lease_id, None)
            if charge is not None:
                await self.admission.release(charge)
            self._plans.pop(lease.lease_id, None)
        await run.finish()
        self._bound_runs()

    async def _start_evidence(
        self, lease: HostLease, plan: ResolvedPlan, recorder: StageRecorder
    ) -> None:
        """Open the host writer and capture streamer for one realized lease; never raises (evidence trouble never fails a realize)."""
        assert lease.evidence_location is not None
        try:
            writer = EvidenceWriter(
                sink_for_location(lease.evidence_location),
                writer="host",
                lease_id=lease.lease_id,
                sample_id=lease.sample_id,
                buffer_cap_bytes=evidence_buffer_bytes(),
                max_total_bytes=evidence_max_bytes(),
            )
            segments = [network.name for network in plan.networks]
            streamer = CaptureStreamer(
                writer,
                ComposeTap(lease.project, Path(lease.bundle_path)),
                segments=segments,
                console_guests=[guest.name for guest in plan.guests],
                stage_recorder=recorder,
            )
            await streamer.start()
            self._evidence[lease.lease_id] = (streamer, writer, segments)
            logger.info(
                "evidence capture started: lease=%s location=%s",
                lease.lease_id,
                lease.evidence_location,
            )
        except Exception:
            logger.exception(
                "evidence capture failed to start for lease=%s (sample "
                "proceeds without host-side evidence)",
                lease.lease_id,
            )

    async def _stop_evidence(self, lease_id: str, *, seal: bool = True) -> None:
        """Harvest one lease's capture before its containers die; bounded and never raises (a wedged tap must not stall the teardown reply).

        With `seal` (the teardown path) the record closes `complete`. Without it (applier shutdown mid-sample) the record gets an explicit `applier-shutdown` gap per segment and stays UNSEALED for a reap-seal (the surviving driver's at teardown, or the reaper's after lease expiry): sealing a cutoff `complete` would be the dishonesty the format exists to prevent.
        """
        entry = self._evidence.pop(lease_id, None)
        if entry is None:
            return
        streamer, writer, segments = entry
        stops_clean = True
        try:
            # stop() is internally bounded; no outer timeout, which would
            # cancel its own gap-recording handlers mid-write (review finding
            # on A6). The phase budgets are single-sourced beside the streamer;
            # the seal reserve below stays protected regardless.
            await streamer.stop(
                stop_timeout_s=CAPTURE_STOP_TIMEOUT_S,
                harvest_timeout_s=CAPTURE_HARVEST_TIMEOUT_S,
            )
        except Exception:
            stops_clean = False
            logger.exception(
                "evidence capture stop failed for lease=%s (sealing what was "
                "delivered)",
                lease_id,
            )
        try:
            async with asyncio.timeout(_EVIDENCE_SEAL_RESERVE_S):
                if not seal:
                    for segment in segments:
                        await writer.gap(f"pcap/{segment}", cause="applier-shutdown")
                    # checkpoint, not flush: the shutdown gaps must land in a
                    # DELIVERED manifest part or the unsealed record shows
                    # nothing (part batching would hold them in memory)
                    await writer.checkpoint()
                    logger.warning(
                        "evidence capture for lease=%s left UNSEALED at applier "
                        "shutdown (explicit applier-shutdown gaps recorded; a "
                        "surviving driver reap-seals at teardown, the reaper "
                        "after lease expiry)",
                        lease_id,
                    )
                    return
                _, digest = await writer.seal(
                    "complete" if stops_clean else "incomplete"
                )
            logger.info("evidence capture sealed: lease=%s digest=%s", lease_id, digest)
        except TimeoutError:
            logger.warning(
                "evidence seal for lease=%s exceeded its %.0fs reserve (record "
                "stays unsealed, reported as such by verify; the reaper can "
                "reap-seal only while the lease lives)",
                lease_id,
                _EVIDENCE_SEAL_RESERVE_S,
            )
        except Exception:
            logger.exception(
                "evidence capture seal failed for lease=%s (record stays "
                "unsealed, reported as such by verify)",
                lease_id,
            )

    def _bound_runs(self) -> None:
        completed = [rid for rid, run in self._runs.items() if run.done]
        while len(completed) > _COMPLETED_RUN_CAP:
            self._runs.pop(completed.pop(0), None)

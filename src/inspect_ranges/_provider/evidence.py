"""The sample's evidence session: location, writers, capture lifecycle, and the store binding.

One `EvidenceSession` per sample wires `evidence-v1.md`'s slice-5 contract into the provider: the location is derived at acquire (beside the eval log, via the active-sample identity or the override), evidence opens with the first stage report, `finalize evidence` runs before destroy under a budget, and the binding (evidence pointer, per-writer seal digests, chain heads) lands in the Inspect sample store so the eval log and the evidence record mutually verify.

Topology decides who writes capture. Co-resident (`local`): the capture streamer runs in this process under the `host` writer identity, and the stage recorder it drains carries host emit clocks. Separated (`uds:`): the applier owns the `host` writer (it reads the location from the lease), while this session's recorder observes the folded stage reports with driver receive clocks, the receive-side half of the clock-offset pairs; the host's seal digest is read back from the store after a successful teardown, best-effort, because the applier's `OkReply` carries nothing.

Evidence never destabilizes the sample: every method here is guarded, a session that cannot open flags and disables itself, finalize is bounded and idempotent, and a missing binding degrades to the INFO log line that always carries the same values.

Writers open only after a successful boot: acquisition respins reuse the sample's location, so writing during a failed attempt would turn the retry into write-once conflicts. Stage events from every attempt accumulate in the recorder and ship once a boot succeeds, so failed-attempt stages are still in the record.
"""

import asyncio
import logging
import os
import uuid
from collections.abc import Awaitable, Callable
from pathlib import Path

from .._compiler.plan import ResolvedPlan
from .._evidence.capture import (
    CAPTURE_HARVEST_TIMEOUT_S,
    CAPTURE_STOP_TIMEOUT_S,
    CaptureStreamer,
    ComposeTap,
    StageRecorder,
    json_lines,
)
from .._evidence.location import (
    EVIDENCE_SINK_OVERRIDE_VAR,
    active_evidence_identity,
    evidence_location_for,
    fallback_evidence_location,
)
from .._evidence.manifest import Seal, SealStatus, clock_now, seal_digest, seal_key
from .._evidence.reader import EvidenceStore
from .._evidence.s3 import sink_for_location, store_for_location
from .._evidence.sealer import seal_abandoned
from .._evidence.sink import DEFAULT_BUFFER_CAP_BYTES, EvidenceWriter

logger = logging.getLogger("inspect_ranges.provider")

EVIDENCE_BUFFER_MB_VAR = "INSPECT_RANGES_EVIDENCE_BUFFER_MB"
EVIDENCE_MAX_MB_VAR = "INSPECT_RANGES_EVIDENCE_MAX_MB"

DEFAULT_EVIDENCE_MAX_MB = 4096
"""Default per-writer evidence volume cap (`INSPECT_RANGES_EVIDENCE_MAX_MB`). Enforced per writer identity (a sample has at most two: `driver` and `host`); breach yields in-chain `evidence-cap` gaps and an `incomplete` seal, never silent loss and never a failed sample."""

FINALIZE_BUDGET_S = 30.0
"""The nominal `finalize evidence` budget: teardown is never hostage to a slow uplink. Enforced as the SUM of its phases (`PRODUCER_STOPS_SHARE_S`, the capture streamer's internal bounds, `SEAL_RESERVE_S`), not one outer timeout: an outer timeout would cancel the streamer's own gap-recording handlers mid-write (quality-review A6 review round)."""

SEAL_RESERVE_S = 10.0
"""The finalize budget's reserved seal share: producer and capture stops run under the remainder, so a wedged stop can never starve the seal attempt (quality-review A6; the probes/pollers alone could previously over-subscribe the whole budget, stranding a permanently unsealed record on a healthy teardown)."""

PRODUCER_STOPS_SHARE_S = 6.0
"""The producers' slice of the stops phase, one JOINT bound: every producer's `stop()` starts before any is awaited, so a wedged stop can consume the share but never starve a sibling's stop call (a never-stopped producer would keep running, and probing, against the sealed record for the remaining life of the driver process; quality-review round 2). The capture streamer's stop runs after it with its own internal bounds (`CAPTURE_STOP_TIMEOUT_S` per stop window, `CAPTURE_HARVEST_TIMEOUT_S` for the real-teardown harvest tail), so the worst case can exceed the nominal `FINALIZE_BUDGET_S` by a bounded margin while the typical case sits far under it; what the phase split guarantees is only, and exactly, that the seal reserve is never starved."""

HOST_SEAL_READ_BUDGET_S = 5.0
"""Post-teardown budget for reading the applier-side seal back for the binding (separated topology)."""

STORE_BINDING_KEY = "inspect_ranges:evidence"
"""The Inspect sample-store key carrying the binding."""


def _mb_env_bytes(var: str, default_bytes: int) -> int:
    """One megabyte-valued knob, parsed and scaled; errors always name the variable.

    Raises:
        ValueError: The variable is set but not a positive integer.
    """
    raw = os.environ.get(var)
    if raw is None:
        return default_bytes
    try:
        value = int(raw)
    except ValueError:
        raise ValueError(f"{var} must be an integer, got {raw!r}") from None
    if value < 1:
        raise ValueError(f"{var} must be >= 1, got {raw!r}")
    return value * 1024 * 1024


def evidence_buffer_bytes() -> int:
    """`INSPECT_RANGES_EVIDENCE_BUFFER_MB` in bytes (default `DEFAULT_BUFFER_CAP_BYTES`).

    Raises:
        ValueError: The variable is set but not a positive integer.
    """
    return _mb_env_bytes(EVIDENCE_BUFFER_MB_VAR, DEFAULT_BUFFER_CAP_BYTES)


def evidence_max_bytes() -> int:
    """`INSPECT_RANGES_EVIDENCE_MAX_MB` in bytes (default `DEFAULT_EVIDENCE_MAX_MB`).

    Raises:
        ValueError: The variable is set but not a positive integer.
    """
    return _mb_env_bytes(EVIDENCE_MAX_MB_VAR, DEFAULT_EVIDENCE_MAX_MB * 1024 * 1024)


class EvidenceSession:
    """One sample's evidence lifecycle, from location derivation to the store binding."""

    def __init__(
        self,
        location: str,
        *,
        sample_id: str,
        capture_local: bool,
    ) -> None:
        self.location = location
        self.sample_id = sample_id
        self.capture_local = capture_local
        self.recorder = StageRecorder()
        self._driver: EvidenceWriter | None = None
        self._host: EvidenceWriter | None = None
        self._streamer: CaptureStreamer | None = None
        self._lease_id: str | None = None
        self._seals: dict[str, str] = {}
        self._chain_heads: dict[str, dict[str, str]] = {}
        self._finalized = False
        self._disabled = False
        self._producers: list[Callable[[], Awaitable[None]]] = []

    # -- admission -------------------------------------------------------------

    def admission_memory_mb(self) -> int:
        """What this session adds to the sample's admission memory charge: one buffer cap per writer resident in the driver process."""
        writers = 2 if self.capture_local else 1
        return (evidence_buffer_bytes() * writers) // (1024 * 1024)

    # -- lifecycle -------------------------------------------------------------

    async def open(
        self,
        *,
        lease_id: str | None,
        project: str,
        bundle: Path,
        plan: ResolvedPlan,
    ) -> None:
        """Open the writers after a successful boot; start capture when this process owns it.

        Never raises: a session that cannot open disables itself with one loud log line, and the sample proceeds without evidence rather than failing.
        """
        if self._disabled or self._driver is not None:
            return
        try:
            self._lease_id = lease_id
            sink = sink_for_location(self.location)
            self._driver = EvidenceWriter(
                sink,
                writer="driver",
                lease_id=lease_id,
                sample_id=self.sample_id,
                buffer_cap_bytes=evidence_buffer_bytes(),
                max_total_bytes=evidence_max_bytes(),
            )
            if self.capture_local and plan.requirements.evidence_capture:
                self._host = EvidenceWriter(
                    sink,
                    writer="host",
                    lease_id=lease_id,
                    sample_id=self.sample_id,
                    buffer_cap_bytes=evidence_buffer_bytes(),
                    max_total_bytes=evidence_max_bytes(),
                )
                self._streamer = CaptureStreamer(
                    self._host,
                    ComposeTap(project, bundle),
                    segments=[network.name for network in plan.networks],
                    console_guests=[guest.name for guest in plan.guests],
                    stage_recorder=self.recorder,
                )
                await self._streamer.start()
            else:
                # separated topology (or capture not rendered): the recorder's
                # buffered stage events are the driver's receive-side record
                await self._drain_recorder()
            logger.info(
                "evidence open: location=%s capture=%s project=%s",
                self.location,
                "local" if self._streamer is not None else "host-side-or-off",
                project,
            )
        except Exception:
            self._disabled = True
            self._driver = None
            self._host = None
            self._streamer = None
            logger.exception(
                "evidence session failed to open (sample proceeds WITHOUT "
                "evidence): location=%s",
                self.location,
            )

    async def record_session_pins(self, sessions: dict[str, str]) -> None:
        """Record the boot-time daemon session pins (the `session` stream, driver-side)."""
        stamp = clock_now()
        await self._driver_append(
            "session",
            json_lines(
                [
                    {
                        "event": "pinned",
                        "guest": guest,
                        "session": session,
                        "wall": stamp.wall,
                        "monotonic": stamp.monotonic,
                    }
                    for guest, session in sorted(sessions.items())
                ]
            ),
        )

    async def record_session_event(self, guest: str, session: str, event: str) -> None:
        """Record one daemon session observation (`re-pinned` after a restart; ops hook)."""
        stamp = clock_now()
        await self._driver_append(
            "session",
            json_lines(
                [
                    {
                        "event": event,
                        "guest": guest,
                        "session": session,
                        "wall": stamp.wall,
                        "monotonic": stamp.monotonic,
                    }
                ]
            ),
        )

    async def record_draws(self, seed: str, draws: dict[str, int | str]) -> None:
        """Record the sample's variable draws on the `draws` stream (driver-side, variable-draws-v0).

        Draws are non-secret by construction (`password` variables refuse `draw:`), so the values ride the record verbatim beside the seed: a recorded sample's draws are reproducible post-hoc from either. Clock stamps are added here; appends are best-effort like every driver stream.
        """
        stamp = clock_now()
        await self._driver_append(
            "draws",
            json_lines(
                [
                    {
                        "event": "drawn",
                        "seed": seed,
                        "draws": draws,
                        "wall": stamp.wall,
                        "monotonic": stamp.monotonic,
                    }
                ]
            ),
        )

    @property
    def enabled(self) -> bool:
        """Whether this session is live: opened writers and not disabled (the evidence-sink observer exists)."""
        return self._driver is not None and not self._disabled

    async def record_plant(self, record: dict[str, object]) -> None:
        """Record one plant observation on the `plants` stream (driver-side T1, `challenges-v1.md`).

        The record carries metadata and a digest, NEVER a plant value: evidence is durable and auditor-readable, so the comparison value lives only in the sample's in-memory `PlantStore`. Clock stamps are added here; appends are best-effort like every driver stream.
        """
        stamp = clock_now()
        await self._driver_append(
            "plants",
            json_lines([{**record, "wall": stamp.wall, "monotonic": stamp.monotonic}]),
        )

    async def finalize(self) -> None:
        """`finalize evidence`: stop capture, drain, seal every writer this process owns; bounded, idempotent, never raises (cancellation excepted).

        Phase-split budgets (quality-review A6): the stops run under the budget minus the reserved seal share, and the seal phase ALWAYS runs, sealing `complete` after clean stops and `incomplete` after a stop timeout (producer tails were lost, which is what `incomplete` means). Only a sink that is itself unresponsive leaves the record unsealed, reported as such by verify; the reaper can reap-seal it only while the lease still exists, so the warning says so instead of promising recovery.

        Cancellation (the second-ctrl-C family during teardown) propagates, and it is NOT completion: the idempotency latch resets so a retried teardown re-enters finalize and the seal still happens (quality-review round 2: a latched cancel made the retry a no-op that wrote `seals={}` and then released the lease, destroying the reap-seal anchor).
        """
        if self._finalized or self._driver is None:
            self._finalized = True
            return
        self._finalized = True
        try:
            await self._finalize_phases()
        except asyncio.CancelledError:
            self._finalized = False
            raise

    async def _finalize_phases(self) -> None:
        """The finalize phases (producer stops, capture stop, drain and seal), each under its own share."""
        assert self._driver is not None
        stops_clean = True
        if self._producers:
            # every stop() starts before any is awaited: the share is one
            # joint bound, and a wedged stop may consume it but must never
            # starve a sibling's stop CALL (an unstopped producer keeps
            # running against the sealed record; quality-review round 2).
            # A timeout cancels the gather, which cancels the still-running
            # stop tasks.
            stops = [
                asyncio.create_task(self._stop_producer(stop))
                for stop in self._producers
            ]
            try:
                async with asyncio.timeout(PRODUCER_STOPS_SHARE_S):
                    await asyncio.gather(*stops)
            except TimeoutError:
                stops_clean = False
                logger.warning(
                    "evidence producer stops exceeded their %.0fs share: "
                    "location=%s (sealing what was delivered; the seal reads "
                    "incomplete)",
                    PRODUCER_STOPS_SHARE_S,
                    self.location,
                )
        if self._streamer is not None:
            # stop() is internally bounded; no outer timeout, which would
            # cancel its own gap-recording handlers mid-write (review finding
            # on A6). The phase budgets are single-sourced beside the streamer
            # (their sizing rationale lives on the constants), and the seal
            # reserve stays protected regardless: the worst case grows the
            # nominal budget, never starves the seal.
            try:
                await self._streamer.stop(
                    stop_timeout_s=CAPTURE_STOP_TIMEOUT_S,
                    harvest_timeout_s=CAPTURE_HARVEST_TIMEOUT_S,
                )
            except Exception:
                stops_clean = False
                logger.exception(
                    "capture stop failed (sealing what was delivered): location=%s",
                    self.location,
                )
        status: SealStatus = "complete" if stops_clean else "incomplete"
        try:
            async with asyncio.timeout(SEAL_RESERVE_S):
                await self._drain_recorder()
                if self._host is not None:
                    await self._seal("host", self._host, status=status)
                await self._seal("driver", self._driver, status=status)
        except TimeoutError:
            logger.warning(
                "evidence seal phase exceeded its %.0fs reserve: location=%s "
                "(record stays unsealed, reported as such by verify; the "
                "reaper can reap-seal only while the lease lives)",
                SEAL_RESERVE_S,
                self.location,
            )
        except Exception:
            logger.exception("evidence finalize failed: location=%s", self.location)

    async def read_host_seal(self) -> None:
        """Best-effort post-teardown read of the applier-side `host` seal for the binding (separated topology); bounded, never raises.

        A missing seal means the applier never sealed (it restarted mid-sample and lost its writer map, or its seal failed). This driver sits at exactly the reaper's ordering point, after teardown and before the lease release that deletes the reaper's only pointer, so the miss path reap-seals HERE (`seal_abandoned`, which skips sealed writers, under the seal reserve) and reads the `reaped` seal back for the binding; left to the reaper, the record would stay unsealed forever (quality-review round 2).
        """
        if "host" in self._seals or self._disabled:
            return
        try:
            store: EvidenceStore = store_for_location(self.location)
            try:
                async with asyncio.timeout(HOST_SEAL_READ_BUDGET_S):
                    raw = await store.get(seal_key("host"))
            except FileNotFoundError:
                async with asyncio.timeout(SEAL_RESERVE_S):
                    await seal_abandoned(
                        self.location,
                        lease_id=self._lease_id,
                        sample_id=self.sample_id,
                    )
                    raw = await store.get(seal_key("host"))
            seal = Seal.model_validate_json(raw)
            self._seals["host"] = seal_digest(seal)
            self._chain_heads["host"] = {
                stream: summary.chain for stream, summary in seal.streams.items()
            }
        except FileNotFoundError:
            logger.warning(
                "no host seal at %s after teardown and nothing to reap-seal "
                "(evidence was off host-side, or the record cannot be "
                "replayed); binding carries the driver seal only",
                self.location,
            )
        except Exception as error:
            logger.warning(
                "host seal read failed at %s (binding carries the driver seal "
                "only): %s",
                self.location,
                error,
            )

    def binding(self) -> dict[str, object]:
        """The log/evidence binding: pointer, per-writer seal digests, per-writer chain heads."""
        return {
            "location": self.location,
            "seals": dict(self._seals),
            "chain_heads": {
                writer: dict(heads) for writer, heads in self._chain_heads.items()
            },
        }

    def write_binding(self) -> None:
        """Write the binding to the Inspect sample store, and ALWAYS mirror it to the log.

        The store write is best-effort: `task_cleanup` (deferred teardowns) runs outside the sample's store context, where the values survive only in the log line. Never raises.
        """
        binding = self.binding()
        logger.info(
            "evidence binding: location=%s seals=%s chain_heads=%s",
            binding["location"],
            binding["seals"],
            binding["chain_heads"],
        )
        try:
            from inspect_ai.util import store

            store().set(STORE_BINDING_KEY, binding)
        except Exception as error:
            logger.warning(
                "evidence binding not written to the sample store (values are "
                "in the log line above): %s",
                error,
            )

    # -- internals ---------------------------------------------------------------

    async def _stop_producer(self, stop: Callable[[], Awaitable[None]]) -> None:
        """One producer stop under the joint share: its own failure is logged, never a sibling's problem."""
        try:
            await stop()
        except Exception:
            logger.exception(
                "evidence producer stop failed (continuing): location=%s",
                self.location,
            )

    async def _drain_recorder(self) -> None:
        """Ship the recorder's buffered stage events through the driver writer (separated topology and finalize; the local streamer drains it instead)."""
        if self._streamer is not None:
            return  # the streamer owns the recorder in the local topology
        stages, verify = self.recorder.drain()
        if stages:
            await self._driver_append("stages", stages)
        if verify:
            await self._driver_append("verify", verify)

    @property
    def driver_writer(self) -> EvidenceWriter | None:
        """The driver-side writer (the telemetry poller appends through it directly); `None` before open or when disabled."""
        return None if self._disabled else self._driver

    def register_producer(self, stop: Callable[[], Awaitable[None]]) -> None:
        """Register a driver-side evidence producer (prober, telemetry poller) stopped at finalize.

        Producers are stopped before the drain and seals, inside the finalize budget; a producer's `stop` must itself never raise (the house teardown contract), and a raise here is caught and logged anyway.
        """
        self._producers.append(stop)

    async def flush_capture(self) -> int:
        """Snapshot-ship the active capture chunks (`CaptureStreamer.flush`); never raises.

        Local capture only: under the separated topology the applier owns the streamer and this returns `0` (a flush verb on the applier is a recorded follow-up). Returns the snapshot chunks shipped.
        """
        if not self.enabled or self._streamer is None:
            return 0
        try:
            return await self._streamer.flush()
        except Exception as error:  # noqa: BLE001  (never load-bearing)
            logger.info("capture flush skipped: %s", error)
            return 0

    async def append_driver(self, stream: str, data: bytes) -> None:
        """Append to a driver-side evidence stream (guarded: disabled sessions and backend trouble no-op, never raise)."""
        await self._driver_append(stream, data)

    async def _driver_append(self, stream: str, data: bytes) -> None:
        if self._driver is None or self._disabled or not data:
            return
        try:
            await self._driver.append(stream, data)
            await self._driver.flush()
        except Exception:
            logger.exception(
                "evidence append failed (continuing): stream=%s location=%s",
                stream,
                self.location,
            )

    async def _seal(
        self, name: str, writer: EvidenceWriter, *, status: SealStatus = "complete"
    ) -> None:
        try:
            seal, digest = await writer.seal(status)
        except Exception as error:
            logger.warning(
                "evidence seal failed for writer %r at %s (record stays "
                "unsealed, reported as such by verify): %s",
                name,
                self.location,
                error,
            )
            return
        self._seals[name] = digest
        self._chain_heads[name] = {
            stream: summary.chain for stream, summary in seal.streams.items()
        }


def resolve_evidence_session(
    *, sample_id: str, run_hint: str, capture_local: bool
) -> EvidenceSession | None:
    """Derive the sample's evidence session, or `None` (one INFO line) when no location is derivable.

    The active-sample identity is the primary source (`sample_active()`, available at `sample_init`); outside an eval context the `INSPECT_RANGES_EVIDENCE_SINK` override enables evidence with the documented fallback layout (`run_hint`, the task name, plays the run id). No identity and no override means evidence is off: deriving a location from nothing would scatter records nobody can find from a log.
    """
    identity = active_evidence_identity()
    if identity is not None:
        # the active sample's own identity is authoritative (the provider's
        # metadata sample id is the same value, stringified)
        location = evidence_location_for(identity)
    elif os.environ.get(EVIDENCE_SINK_OVERRIDE_VAR):
        # the run id must be unique per run: a static task name would collide
        # across repeated runs and turn the second run's whole record into
        # write-once conflicts (review finding, 2026-10-15)
        location = fallback_evidence_location(
            os.environ[EVIDENCE_SINK_OVERRIDE_VAR],
            f"{run_hint}-{uuid.uuid4().hex[:8]}",
            sample_id=sample_id,
            epoch=1,
            attempt=1,
        )
    else:
        logger.info(
            "evidence off for %s: no active-sample context and no %s override",
            run_hint,
            EVIDENCE_SINK_OVERRIDE_VAR,
        )
        return None
    try:
        # validate the knobs HERE: a malformed value must disable evidence
        # with a loud named error, never fail the sample (the applier handles
        # the same misconfiguration the same way)
        evidence_buffer_bytes()
        evidence_max_bytes()
    except ValueError:
        logger.exception("evidence disabled for %s: invalid evidence knob", run_hint)
        return None
    return EvidenceSession(location, sample_id=sample_id, capture_local=capture_local)

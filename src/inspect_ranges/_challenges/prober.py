"""The active prober: nonce-bound probes from the declared probe endpoint, recorded as evidence.

One asyncio task per probe target, started by `plant_goals()` when a challenge carries prober-based goals and stopped by the evidence session at finalize (`stop()` never raises; it is teardown-bound). Each tick generates a fresh nonce driver-side and runs the bundle's probe client inside the zero-capability probe sidecar (`docker compose exec`), which originates the flow from the clamped probe veth; the verdict binds to the nonce (`ok` requires the response to carry sha256(nonce), so canned and replayed responses read `mumble`, never `ok`). Per-probe records land on the `probe/<goal id>` driver evidence stream, batched like telemetry meta records; the scorer reads recorded results and never probes at scoring time.

Probe values in records are nonces and measures, never plant material; the one value that rides a probe argv is a `tamper` goal's DISCLOSED needle, which is agent-known by design (the uniform logging rule still applies: records carry a found flag, not the needle).
"""

import asyncio
import contextlib
import json
import logging
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from secrets import token_hex
from typing import TYPE_CHECKING

from .._evidence.capture import json_lines

# Re-exported for compatibility: the grammar lives in schema.py so validation
# enforces the same rule the runtime parses (quality review B15).
from .schema import parse_tamper_location as parse_tamper_location

if TYPE_CHECKING:
    from .._provider.evidence import EvidenceSession

logger = logging.getLogger("inspect_ranges.challenges")

__all__ = ["ProbeTarget", "Prober", "parse_tamper_location"]

PROBE_CADENCE_S = 2.0
"""Seconds between probes per target (measure-first: a knob arrives only if measurement demands one)."""

PROBE_BATCH_S = 15.0
"""Probe-record batching cadence, matching the telemetry meta batching decision: routine records batch into one chunk per interval; `down` verdicts and stop flush immediately."""

PROBE_EXEC_TIMEOUT_S = 15.0
"""Hard cap on one probe client invocation (the client's own HTTP timeout is 5 s)."""


async def _run_probe_client(argv: list[str]) -> bytes:
    """Run the probe client in the sidecar and return its stdout (the default client runner).

    The kill lives in `finally`: external cancellation (the prober's own `stop()`, the exact moment a wedged `docker compose exec` matters) must not leak the child, which the old timeout-only arm did (quality review B19). The event loop's child watcher reaps the killed process.
    """
    process = await asyncio.create_subprocess_exec(
        *argv,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.DEVNULL,
    )
    try:
        async with asyncio.timeout(PROBE_EXEC_TIMEOUT_S):
            stdout, _ = await process.communicate()
        return stdout
    finally:
        if process.returncode is None:
            with contextlib.suppress(ProcessLookupError):
                process.kill()


@dataclass
class ProbeTarget:
    """One probed surface, derived from a prober-based goal at plant time."""

    goal_id: str
    ip: str
    """The probed guest's address on the probe endpoint's segment."""
    port: int
    path: str = "/probe"
    """v1 probe surface convention: GET `<path>?nonce=<n>`, response carries sha256(nonce) (the battery service implements it; real services need a probe surface, a scenario-design contract recorded in `challenges-v1.md`)."""
    needle: str | None = None
    """A `tamper` goal's disclosed value: the verdict reports whether it appears in the body."""


@dataclass
class _TargetState:
    records: list[dict[str, object]] = field(default_factory=lambda: [])
    last_flush: float = field(default_factory=time.monotonic)


class Prober:
    """Drives per-target probe loops and ships their records to evidence."""

    def __init__(
        self,
        session: "EvidenceSession",
        project: str,
        targets: list[ProbeTarget],
        *,
        cadence_s: float = PROBE_CADENCE_S,
        batch_s: float = PROBE_BATCH_S,
        client_runner: "Callable[[list[str]], Awaitable[bytes]] | None" = None,
    ) -> None:
        self._client_runner = client_runner or _run_probe_client
        self._session = session
        self._project = project
        self._targets = targets
        self._cadence_s = cadence_s
        self._batch_s = batch_s
        self._states: dict[str, _TargetState] = {}
        self._tasks: dict[str, asyncio.Task[None]] = {}
        self._stopping = False

    def start(self) -> None:
        """Start one probe loop per target (idempotent)."""
        for target in self._targets:
            if target.goal_id in self._tasks:
                continue
            self._states[target.goal_id] = _TargetState()
            self._tasks[target.goal_id] = asyncio.create_task(
                self._run(target), name=f"probe:{target.goal_id}"
            )
        logger.info(
            "prober started targets=%d cadence=%.1fs project=%s",
            len(self._targets),
            self._cadence_s,
            self._project,
        )

    async def stop(self, *, stop_timeout_s: float = 20.0) -> None:
        """Stop every loop and flush remaining records; never raises for loop trouble (teardown-bound).

        `stop()` ITSELF being cancelled (the finalize budget expiring) must propagate, which is why each wait shields the loop task and distinguishes the task's own cancellation (`task.cancelled()`) from an external one, the `TelemetryPoller.stop` pattern.
        """
        self._stopping = True
        for task in self._tasks.values():
            task.cancel()
        for goal_id, task in self._tasks.items():
            try:
                await asyncio.wait_for(asyncio.shield(task), stop_timeout_s)
            except TimeoutError:
                logger.warning("probe loop for %s did not stop in time", goal_id)
            except asyncio.CancelledError:
                if task.cancelled():
                    continue
                raise
            except Exception:
                logger.warning("probe loop for %s ended with an error", goal_id)
        for goal_id in list(self._states):
            await self._flush(goal_id, force=True)
        self._tasks.clear()

    async def probe_once(self, target: ProbeTarget) -> dict[str, object]:
        """One probe tick: fresh nonce, client run in the probe sidecar, verdict record."""
        nonce = token_hex(8)
        wall = time.time()
        argv = [
            "docker",
            "compose",
            "-p",
            self._project,
            "exec",
            "-T",
            "probe",
            "python3",
            "/render/probe/probeclient.py",
            target.ip,
            str(target.port),
            target.path,
            nonce,
        ]
        if target.needle is not None:
            argv += ["--needle", target.needle]
        record: dict[str, object] = {
            "goal": target.goal_id,
            "nonce": nonce,
            "wall": wall,
            "status": "down",
            "rtt_ms": None,
        }
        try:
            stdout = await self._client_runner(argv)
            parsed = json.loads(stdout.decode(errors="replace").strip() or "{}")
            for key in ("status", "http", "rtt_ms", "echo", "found"):
                if key in parsed:
                    record[key] = parsed[key]
        except Exception as error:
            record["error"] = f"{type(error).__name__}"
        return record

    async def _run(self, target: ProbeTarget) -> None:
        while not self._stopping:
            record = await self.probe_once(target)
            state = self._states[target.goal_id]
            state.records.append(record)
            await self._flush(target.goal_id, force=record.get("status") == "down")
            await asyncio.sleep(self._cadence_s)

    async def _flush(self, goal_id: str, *, force: bool) -> None:
        state = self._states[goal_id]
        if not state.records:
            return
        if not force and time.monotonic() - state.last_flush < self._batch_s:
            return
        batch, state.records = state.records, []
        state.last_flush = time.monotonic()
        await self._session.append_driver(f"probe/{goal_id}", json_lines(batch))

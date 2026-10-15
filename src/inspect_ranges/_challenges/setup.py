"""Per-sample goal setup: `plant_goals()` runs every goal's planting before the agent acts.

Setup is symmetric with scoring (`challenges-v1.md`): a prepended solver builds the oracle and plants per-sample proof material from independent entropy, refusing up front when a required observer is unavailable or a plant fails. A refusal raises, which Inspect records as a sample error: infrastructure failure is never read as agent failure, and the sample never starts half-planted (plants already written are unwound).

Setup dispatches through the goal-type registry (`engine.py`): each type's `setup` plants what its proof contract needs and returns plant keys for unwind. Observer-arming types (prober, detection) join with their slices.
"""

import logging
import time
from typing import TYPE_CHECKING

from inspect_ai.solver import Generate, Solver, TaskState, solver

from .._evidence.telemetry import CollectorSpec, TelemetryPoller
from .dataset import CHALLENGE_METADATA_KEY
from .engine import goal_type
from .oracle import RangeOracle, range_oracle
from .prober import Prober, ProbeTarget, parse_tamper_location
from .schema import (
    AvailabilityGoal,
    Challenge,
    DegradeGoal,
    DetectionGoal,
    TamperGoal,
    required_observers,
)
from .submission import submit_goal

if TYPE_CHECKING:
    from .._compiler.plan import ResolvedPlan

logger = logging.getLogger("inspect_ranges.challenges")

__all__ = ["plant_goals", "plant_secret_file", "run_setup"]


async def plant_secret_file(
    oracle: RangeOracle,
    *,
    key: str,
    goal_id: str,
    guest: str,
    path: str,
    owner: str,
    mode: int = 0o600,
) -> str:
    """Plant a fresh per-sample secret at `guest:path`, owned by `owner`.

    The T1 record precedes guest state: the store records the digest first, then the file lands with `mode` applied from the first byte and ownership transferred. The value never appears in argv, env, or any log. The default mode keeps plants readable only by `owner`; `exfiltrate` canaries widen it deliberately (protection comes from placement).

    Args:
        oracle: The sample's oracle.
        key: Plant-store key (`<type>:<goal id>` by convention).
        goal_id: The goal this plant proves.
        guest: Guest to plant on.
        path: Absolute in-guest path.
        owner: Account that owns the plant.
        mode: Permission bits applied atomically with the write.

    Returns:
        The plant-store key, for unwind bookkeeping.
    """
    value = oracle.nonce().encode()
    await oracle.store.record(key, value, goal_id=goal_id, guest=guest, path=path)
    try:
        await oracle.write_file(guest, path, value, mode=mode, owner=owner)
    except BaseException:
        # Scrub the frame: locals-rendered tracebacks (INSPECT_TRACEBACK_LOCALS=1)
        # would otherwise carry the plant value into the eval log.
        del value
        await oracle.store.discard(key, reason="write failed")
        raise
    return key


async def _unwind(oracle: RangeOracle, keys: list[str]) -> None:
    """Best-effort removal of already-planted files, newest first; every plant is discarded from the record regardless."""
    for key in reversed(keys):
        plant = oracle.store.plant(key)
        try:
            removal = await oracle.exec(
                plant.guest, ["rm", "-f", "--", plant.path], user="root"
            )
            if removal.rc != 0:
                logger.warning(
                    "setup unwind: removing %s:%s failed (rc %d)",
                    plant.guest,
                    plant.path,
                    removal.rc,
                )
        except Exception:
            logger.warning(
                "setup unwind: removing %s:%s failed", plant.guest, plant.path
            )
        await oracle.store.discard(key, reason="setup unwound")


async def run_setup(
    oracle: RangeOracle,
    challenge: Challenge,
    *,
    extra_observers: frozenset[str] = frozenset(),
) -> None:
    """Run the challenge's setups against `oracle`: observer gate first, then plants in goal order.

    Args:
        oracle: The sample's oracle.
        challenge: The challenge being planted.
        extra_observers: Observers the caller supplies beyond the deployment's own (`telemetry-collector` when `plant_goals` was given a matching collector spec).

    Raises:
        RuntimeError: A required observer is unavailable, or a plant failed (plants already written are unwound first). Callers treat this as infrastructure refusal, never agent failure.
    """
    missing = (
        required_observers(challenge) - oracle.available_observers() - extra_observers
    )
    if missing:
        raise RuntimeError(
            f"challenge {challenge.id!r} requires observers this deployment "
            f"cannot supply: {sorted(missing)}"
        )
    planted: list[str] = []
    for goal in challenge.goals:
        try:
            goal_engine = goal_type(goal.type)
        except KeyError as error:
            await _unwind(oracle, planted)
            raise RuntimeError(
                f"challenge {challenge.id!r} uses goal type {goal.type!r} "
                "with no registered engine (slice 4 types arrive with their "
                "slices; custom types register via register_goal_type)"
            ) from error
        start = time.monotonic()
        try:
            keys = await goal_engine.setup(goal, oracle)
        except Exception as error:
            await _unwind(oracle, planted)
            raise RuntimeError(
                f"challenge {challenge.id!r} setup failed at goal {goal.id!r}"
            ) from error
        planted.extend(keys)
        logger.info(
            "planted goal=%s type=%s plants=%d elapsed=%.3fs",
            goal.id,
            goal.type,
            len(keys),
            time.monotonic() - start,
        )


@solver
def plant_goals(
    telemetry_collectors: "list[CollectorSpec] | None" = None,
) -> Solver:
    """Plant every goal's per-sample material before the agent acts, and start the sample's observers.

    Prepend to the task's solver chain. Refuses (raises) when the sample carries no challenge metadata, a required observer is unavailable in this deployment, or any plant fails; plants written before a failure are unwound, so the agent never starts against a half-planted range.

    Prober-based goals (`availability`, `degrade`, `tamper`) start the active prober after a successful setup, probing from the rendered probe endpoint on a cadence; `detection` goals start the telemetry export poller for their collector, which must have a matching entry in `telemetry_collectors` (poll mechanics are deployment knowledge the schema deliberately does not carry: the collector name binds the two). Both producers write evidence mid-run and are stopped by the evidence session at finalize; the scorer reads recorded results only.

    Multi-goal challenges get the `submit_goal` tool added to `state.tools` (the dataset's appended prompt paragraph names it, so the harness guarantees it for generate-driven solvers). Agents that carry their own toolset, like `react(tools=...)`, must include `submit_goal()` themselves; single-goal challenges work without it through the completion fallback.
    """
    collectors = telemetry_collectors or []

    async def solve(state: TaskState, generate: Generate) -> TaskState:
        raw = state.metadata.get(CHALLENGE_METADATA_KEY)
        if raw is None:
            raise RuntimeError(
                "sample carries no challenge metadata; build the dataset with "
                "challenge_dataset()"
            )
        challenge = Challenge.model_validate(raw)
        if len(challenge.goals) > 1 and not _has_submit_goal(state):
            state.tools.append(submit_goal())
        oracle = range_oracle()
        supplied = frozenset(spec.name for spec in collectors)
        needed = {
            goal.collector
            for goal in challenge.goals
            if isinstance(goal, DetectionGoal)
        }
        unmatched = needed - supplied
        if unmatched:
            raise RuntimeError(
                f"challenge {challenge.id!r} declares detection collectors "
                f"with no telemetry spec supplied to plant_goals(): "
                f"{sorted(unmatched)}"
            )
        extra: frozenset[str] = (
            frozenset({"telemetry-collector"}) if needed else frozenset()
        )
        await run_setup(oracle, challenge, extra_observers=extra)
        await _start_producers(
            oracle,
            challenge,
            [spec for spec in collectors if spec.name in needed],
        )
        return state

    return solve


async def _start_producers(
    oracle: RangeOracle,
    challenge: Challenge,
    collectors: "list[CollectorSpec]",
) -> None:
    """Start the prober and telemetry poller the challenge needs; both stop at evidence finalize."""
    session = oracle.evidence_session()
    targets = _probe_targets(oracle, challenge)
    if not targets and not collectors:
        return
    if session is None or not session.enabled:
        raise RuntimeError("prober or telemetry goals need a live evidence session")
    if targets:
        prober = Prober(session, oracle.project, targets)
        prober.start()
        session.register_producer(prober.stop)
    if collectors:
        writer = session.driver_writer
        if writer is None:
            raise RuntimeError("telemetry export needs the driver evidence writer")
        poller = TelemetryPoller(oracle.channel, writer, collectors)
        await poller.start()
        session.register_producer(poller.stop)


def _probe_targets(oracle: RangeOracle, challenge: Challenge) -> list[ProbeTarget]:
    """Derive probe targets from the challenge's prober-based goals against the rendered plan.

    Raises:
        RuntimeError: A prober goal's host has no interface on any rendered probe segment (the planning gate should have refused earlier; this is the honest backstop).
    """
    plan = oracle.resolved()
    probe_segments = set(plan.requirements.probe_segments)
    targets: list[ProbeTarget] = []
    for goal in challenge.goals:
        if isinstance(goal, (AvailabilityGoal, DegradeGoal)):
            port, path = goal.port, "/probe"
            needle = None
        elif isinstance(goal, TamperGoal):
            port, path = parse_tamper_location(goal.location)
            needle = oracle.store.get(f"tamper:{goal.id}").decode()
        else:
            continue
        wanted = (
            {goal.segment} & probe_segments
            if goal.segment is not None
            else probe_segments
        )
        ip = _probe_target_ip(plan, goal.host, wanted)
        if ip is None:
            raise RuntimeError(
                f"goal {goal.id!r} probes host {goal.host!r}, which has no "
                "interface on any rendered probe segment"
            )
        targets.append(
            ProbeTarget(goal_id=goal.id, ip=ip, port=port, path=path, needle=needle)
        )
    return targets


def _probe_target_ip(
    plan: "ResolvedPlan", host: str, probe_segments: set[str]
) -> str | None:
    for guest in plan.guests:
        if guest.name != host:
            continue
        for interface in guest.interfaces:
            if interface.network in probe_segments:
                return str(interface.ip)
    return None


def _has_submit_goal(state: TaskState) -> bool:
    from inspect_ai.tool import ToolDef

    for existing in state.tools:
        try:
            if ToolDef(existing).name == "submit_goal":
                return True
        except Exception:  # a tool ToolDef cannot introspect is not ours
            continue
    return False

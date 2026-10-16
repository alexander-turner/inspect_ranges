"""Per-sample goal setup: `plant_goals()` runs every goal's planting before the agent acts.

Setup is symmetric with scoring (`challenges-v1.md`): a prepended solver builds the oracle and plants per-sample proof material from independent entropy, refusing up front when a required observer is unavailable or a plant fails. A refusal raises, which Inspect records as a sample error: infrastructure failure is never read as agent failure, and the sample never starts half-planted (plants already written are unwound).

Setup dispatches through the goal-type registry (`engine.py`): each type's `setup` plants what its proof contract needs and returns plant keys for unwind. Observer-arming types (prober, detection) join with their slices.
"""

import asyncio
import logging
import time
from typing import TYPE_CHECKING

from inspect_ai.solver import Generate, Solver, TaskState, solver

from .._evidence.telemetry import CollectorSpec, TelemetryPoller
from .dataset import CHALLENGE_METADATA_KEY
from .engine import goal_type
from .oracle import RangeOracle, range_oracle
from .poller import start_goal_poller
from .prober import Prober, ProbeTarget, parse_tamper_location
from .schema import (
    AnswerGoal,
    AvailabilityGoal,
    Challenge,
    DegradeGoal,
    DetectionGoal,
    EvadeGoal,
    PatchGoal,
    TamperGoal,
    required_observers,
)
from .submission import submit_goal
from .timings import add_timing

if TYPE_CHECKING:
    from inspect_ai.util import Store

if TYPE_CHECKING:
    from .._compiler.plan import ResolvedPlan

logger = logging.getLogger("inspect_ranges.challenges")

__all__ = ["plant_and_start", "plant_goals", "plant_secret_file", "run_setup"]


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
    """Best-effort removal of already-planted files, newest first; every plant is discarded from the record regardless.

    Only absolute paths name guest files; a record-only plant (`tamper`'s `PORT/PATH` location, `hijack`'s service name) carries placement facts, not a file, and running `rm` on it was wrong-shaped (quality review, challenges D nits). The disclosed foothold files are their own plants (`disclosed:<goal id>`), so they unwind here naturally.
    """
    for key in reversed(keys):
        plant = oracle.store.plant(key)
        if not plant.path.startswith("/"):
            logger.debug(
                "setup unwind: %s is a record-only plant (placement %r, no guest file)",
                key,
                plant.path,
            )
            await oracle.store.discard(key, reason="setup unwound")
            continue
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


async def _unwind_shielded(oracle: RangeOracle, keys: list[str]) -> None:
    """`_unwind`, immune to the caller's cancellation (review finding on the fix round).

    A sample cancellation arriving mid-unwind would otherwise abort it partway: exactly the half-planted ledger state the unwind exists to prevent. The range teardown removes planted files regardless; what this preserves is the plant ledger's discard events, so on a second cancellation the unwind finishes detached rather than dying.
    """
    if not keys:
        return
    task = asyncio.create_task(_unwind(oracle, keys))
    try:
        await asyncio.shield(task)
    except asyncio.CancelledError:
        if task.cancelled():
            raise

        def _log_outcome(done: "asyncio.Task[None]") -> None:
            if not done.cancelled() and done.exception() is not None:
                logger.warning(
                    "detached setup unwind failed: %s",
                    type(done.exception()).__name__,
                )

        task.add_done_callback(_log_outcome)
        logger.warning(
            "setup unwind detached under cancellation (range teardown removes planted files)"
        )
        raise


async def run_setup(
    oracle: RangeOracle,
    challenge: Challenge,
    store: "Store | None" = None,
    *,
    extra_observers: frozenset[str] = frozenset(),
) -> list[str]:
    """Run the challenge's setups against `oracle`: observer gate first, then plants in goal order.

    Args:
        oracle: The sample's oracle.
        challenge: The challenge being planted.
        store: The sample store; when given, per-goal setup timings accumulate under `inspect_ranges:timings` (the measure-first surface).
        extra_observers: Observers the caller supplies beyond the deployment's own (`telemetry-collector` when `plant_goals` was given a matching collector spec).

    Returns:
        Every planted key, in plant order, so a caller whose LATER step fails (producer start) can unwind the sample to never-half-planted (quality review B15).

    Raises:
        RuntimeError: A required observer is unavailable, an `answer` goal names a variable the range does not declare, or a plant failed (plants already written are unwound first). Callers treat this as infrastructure refusal, never agent failure.
    """
    missing = (
        required_observers(challenge) - oracle.available_observers() - extra_observers
    )
    if missing:
        raise RuntimeError(
            f"challenge {challenge.id!r} requires observers this deployment "
            f"cannot supply: {sorted(missing)}"
        )
    # answer variables have no plant to fail loudly at plant time, so on the
    # range_spec-omitted dataset path an unknown variable would otherwise run
    # the full episode and score an opaque indeterminate (quality review R2-8);
    # the spec rides the oracle's handle, so the cross-reference is cheap here
    unknown_variables = sorted(
        {
            goal.variable
            for goal in challenge.goals
            if isinstance(goal, AnswerGoal)
            and goal.variable is not None
            and goal.variable not in oracle.range_spec().variables
        }
    )
    if unknown_variables:
        raise RuntimeError(
            f"challenge {challenge.id!r} names answer variables the range "
            f"does not declare: {unknown_variables} (validate with "
            "challenge_dataset(..., range_spec=...) to catch this at authoring)"
        )
    planted: list[str] = []
    for goal in challenge.goals:
        try:
            goal_engine = goal_type(goal.type)
        except KeyError as error:
            await _unwind_shielded(oracle, planted)
            raise RuntimeError(
                f"challenge {challenge.id!r} uses goal type {goal.type!r} "
                "with no registered engine (slice 4 types arrive with their "
                "slices; custom types register via register_goal_type)"
            ) from error
        start = time.monotonic()
        try:
            keys = await goal_engine.setup(goal, oracle)
        except BaseException as error:
            # BaseException: a sample cancellation mid-plant must unwind too
            # (shielded), not leave the half-planted state (review finding)
            await _unwind_shielded(oracle, planted)
            if isinstance(error, Exception):
                raise RuntimeError(
                    f"challenge {challenge.id!r} setup failed at goal {goal.id!r}"
                ) from error
            raise
        planted.extend(keys)
        elapsed = time.monotonic() - start
        if store is not None:
            add_timing(store, f"goal:{goal.id}", "setup", elapsed)
        logger.info(
            "planted goal=%s type=%s plants=%d elapsed=%.3fs",
            goal.id,
            goal.type,
            len(keys),
            elapsed,
        )
    return planted


def telemetry_goal_collectors(challenge: Challenge) -> set[str]:
    """The collectors the challenge's telemetry-reading goals (`detection`, `evade`) need wired."""
    return {
        goal.collector
        for goal in challenge.goals
        if isinstance(goal, (DetectionGoal, EvadeGoal))
    }


@solver
def plant_goals(
    telemetry_collectors: "list[CollectorSpec] | None" = None,
) -> Solver:
    """Plant every goal's per-sample material before the agent acts, and start the sample's observers.

    Prepend to the task's solver chain. Refuses (raises) when the sample carries no challenge metadata, a required observer is unavailable in this deployment, or any plant fails; plants written before a failure are unwound, so the agent never starts against a half-planted range.

    Prober-based goals (`availability`, `degrade`, `tamper`) start the active prober after a successful setup, probing from the rendered probe endpoint on a cadence; `detection` and `evade` goals start the telemetry export poller for their collector, which must have a matching entry in `telemetry_collectors` (poll mechanics are deployment knowledge the schema deliberately does not carry: the collector name binds the two). Both producers write evidence mid-run and are stopped by the evidence session at finalize; the scorer reads recorded results only.

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
        needed = telemetry_goal_collectors(challenge)
        unmatched = needed - supplied
        if unmatched:
            raise RuntimeError(
                f"challenge {challenge.id!r} declares telemetry collectors "
                f"with no telemetry spec supplied to plant_goals(): "
                f"{sorted(unmatched)}"
            )
        extra: frozenset[str] = (
            frozenset({"telemetry-collector"}) if needed else frozenset()
        )
        await plant_and_start(
            oracle,
            challenge,
            state.store,
            [spec for spec in collectors if spec.name in needed],
            extra_observers=extra,
        )
        # The cheap-tier poller (slice 5): latches mid-run passes with their
        # timestamps; the scorer stops it. Failure to start is logged by the
        # poller itself and never blocks the sample.
        start_goal_poller(oracle, challenge, state.store)
        return state

    return solve


async def plant_and_start(
    oracle: RangeOracle,
    challenge: Challenge,
    store: "Store | None",
    collectors: "list[CollectorSpec]",
    *,
    extra_observers: frozenset[str] = frozenset(),
) -> None:
    """Plant the challenge, then start its producers, holding never-half-planted across BOTH steps.

    A producer-start refusal (missing evidence session, no driver writer, an unreachable probe target) unwinds every plant `run_setup` wrote, so the sample never starts, or errors, against a half-planted range (quality review B15: producer failures previously skipped the unwind).
    """
    planted = await run_setup(oracle, challenge, store, extra_observers=extra_observers)
    try:
        await _start_producers(oracle, challenge, collectors)
    except BaseException:
        await _unwind_shielded(oracle, planted)
        raise


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
    # every raise-able step happens BEFORE anything starts: a failing
    # telemetry half must not leave an already-started prober probing the
    # unwound range of a refused sample (review finding on the fix round)
    poller: TelemetryPoller | None = None
    if collectors:
        writer = session.driver_writer
        if writer is None:
            raise RuntimeError("telemetry export needs the driver evidence writer")
        poller = TelemetryPoller(oracle.channel, writer, collectors)
    if poller is not None:
        await poller.start()
        session.register_producer(poller.stop)
    if targets:
        prober = Prober(session, oracle.project, targets)
        prober.start()
        session.register_producer(prober.stop)


def _probe_targets(oracle: RangeOracle, challenge: Challenge) -> list[ProbeTarget]:
    """Derive probe targets from the challenge's prober-based goals against the rendered plan.

    Raises:
        RuntimeError: A prober goal's host has no interface on any rendered probe segment (the planning gate should have refused earlier; this is the honest backstop).
    """
    plan = oracle.resolved()
    probe_segments = set(plan.requirements.probe_segments)
    targets: list[ProbeTarget] = []
    for goal in challenge.goals:
        if isinstance(goal, (AvailabilityGoal, DegradeGoal, PatchGoal)):
            port, path = goal.port, "/probe"
            needle = None
        elif isinstance(goal, TamperGoal):
            try:
                port, path = parse_tamper_location(goal.location)
            except ValueError as error:
                # schema validation enforces the grammar, so this is the honest
                # backstop for a hand-built goal object; it carries the goal
                raise RuntimeError(f"goal {goal.id!r}: {error}") from error
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

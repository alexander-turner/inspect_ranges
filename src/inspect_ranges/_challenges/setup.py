"""Per-sample goal setup: `plant_goals()` runs every goal's planting before the agent acts.

Setup is symmetric with scoring (`challenges-v1.md`): a prepended solver builds the oracle and plants per-sample proof material from independent entropy, refusing up front when a required observer is unavailable or a plant fails. A refusal raises, which Inspect records as a sample error: infrastructure failure is never read as agent failure, and the sample never starts half-planted (plants already written are unwound).

Setup dispatches through the goal-type registry (`engine.py`): each type's `setup` plants what its proof contract needs and returns plant keys for unwind. Observer-arming types (prober, detection) join with their slices.
"""

import logging
import time

from inspect_ai.solver import Generate, Solver, TaskState, solver

from .dataset import CHALLENGE_METADATA_KEY
from .engine import goal_type
from .oracle import RangeOracle, range_oracle
from .schema import Challenge, required_observers
from .submission import submit_goal

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


async def run_setup(oracle: RangeOracle, challenge: Challenge) -> None:
    """Run the challenge's setups against `oracle`: observer gate first, then plants in goal order.

    Raises:
        RuntimeError: A required observer is unavailable, or a plant failed (plants already written are unwound first). Callers treat this as infrastructure refusal, never agent failure.
    """
    missing = required_observers(challenge) - oracle.available_observers()
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
def plant_goals() -> Solver:
    """Plant every goal's per-sample material before the agent acts.

    Prepend to the task's solver chain. Refuses (raises) when the sample carries no challenge metadata, a required observer is unavailable in this deployment, or any plant fails; plants written before a failure are unwound, so the agent never starts against a half-planted range.

    Multi-goal challenges get the `submit_goal` tool added to `state.tools` (the dataset's appended prompt paragraph names it, so the harness guarantees it for generate-driven solvers). Agents that carry their own toolset, like `react(tools=...)`, must include `submit_goal()` themselves; single-goal challenges work without it through the completion fallback.
    """

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
        await run_setup(range_oracle(), challenge)
        return state

    return solve


def _has_submit_goal(state: TaskState) -> bool:
    from inspect_ai.tool import ToolDef

    for existing in state.tools:
        try:
            if ToolDef(existing).name == "submit_goal":
                return True
        except Exception:  # a tool ToolDef cannot introspect is not ours
            continue
    return False

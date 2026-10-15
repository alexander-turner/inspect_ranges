"""Per-sample goal setup: `plant_goals()` runs every goal's planting before the agent acts.

Setup is symmetric with scoring (`challenges-v1.md`): a prepended solver builds the oracle and plants per-sample proof material from independent entropy, refusing up front when a required observer is unavailable or a plant fails. A refusal raises, which Inspect records as a sample error: infrastructure failure is never read as agent failure, and the sample never starts half-planted (plants already written are unwound).

Slice note: the planting seam below covers the file-planting types (`flag`, `control`/`privilege`, `execute`); the goal-type registry absorbs it when the engine lands, and observer-arming types (prober, detection) join with their slices.
"""

import logging
import time
from collections.abc import Awaitable, Callable

from inspect_ai.solver import Generate, Solver, TaskState, solver

from .dataset import CHALLENGE_METADATA_KEY
from .oracle import RangeOracle, range_oracle
from .schema import (
    Challenge,
    ControlGoal,
    ExecuteGoal,
    FlagGoal,
    GoalBase,
    required_observers,
)

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
) -> str:
    """Plant a fresh per-sample secret at `guest:path`, readable only by `owner`.

    The T1 record precedes guest state: the store records the digest first, then the file lands mode 0600 with ownership transferred. The value never appears in argv, env, or any log.

    Args:
        oracle: The sample's oracle.
        key: Plant-store key (`<type>:<goal id>` by convention).
        goal_id: The goal this plant proves.
        guest: Guest to plant on.
        path: Absolute in-guest path.
        owner: Account the plant is readable by.

    Returns:
        The plant-store key, for unwind bookkeeping.
    """
    value = oracle.nonce().encode()
    await oracle.store.record(key, value, goal_id=goal_id, guest=guest, path=path)
    try:
        await oracle.write_file(guest, path, value, mode=0o600, owner=owner)
    except BaseException:
        await oracle.store.discard(key, reason="write failed")
        raise
    return key


async def _plant_flag(oracle: RangeOracle, goal: GoalBase) -> str | None:
    assert isinstance(goal, FlagGoal)
    return await plant_secret_file(
        oracle,
        key=f"flag:{goal.id}",
        goal_id=goal.id,
        guest=goal.host,
        path=goal.path,
        owner=goal.owner,
    )


async def _plant_control(oracle: RangeOracle, goal: GoalBase) -> str | None:
    assert isinstance(goal, ControlGoal)
    return await plant_secret_file(
        oracle,
        key=f"control:{goal.id}",
        goal_id=goal.id,
        guest=goal.host,
        path=goal.secret_path,
        owner=goal.principal,
    )


async def _plant_execute(oracle: RangeOracle, goal: GoalBase) -> str | None:
    assert isinstance(goal, ExecuteGoal)
    return await plant_secret_file(
        oracle,
        key=f"execute:{goal.id}",
        goal_id=goal.id,
        guest=goal.host,
        path=goal.token_path,
        owner=goal.service_user,
    )


SetupFn = Callable[[RangeOracle, GoalBase], Awaitable[str | None]]
"""One goal type's planting step; returns the plant key for unwind, `None` when nothing planted."""

_SETUPS: dict[str, SetupFn] = {
    "flag": _plant_flag,
    "control": _plant_control,
    "privilege": _plant_control,
    "execute": _plant_execute,
}


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
        plant = _SETUPS.get(goal.type)
        if plant is None:
            continue
        start = time.monotonic()
        try:
            key = await plant(oracle, goal)
        except Exception as error:
            await _unwind(oracle, planted)
            raise RuntimeError(
                f"challenge {challenge.id!r} setup failed at goal {goal.id!r}"
            ) from error
        if key is not None:
            planted.append(key)
        logger.info(
            "planted goal=%s type=%s elapsed=%.3fs",
            goal.id,
            goal.type,
            time.monotonic() - start,
        )


@solver
def plant_goals() -> Solver:
    """Plant every goal's per-sample material before the agent acts.

    Prepend to the task's solver chain. Refuses (raises) when the sample carries no challenge metadata, a required observer is unavailable in this deployment, or any plant fails; plants written before a failure are unwound, so the agent never starts against a half-planted range.
    """

    async def solve(state: TaskState, generate: Generate) -> TaskState:
        raw = state.metadata.get(CHALLENGE_METADATA_KEY)
        if raw is None:
            raise RuntimeError(
                "sample carries no challenge metadata; build the dataset with "
                "challenge_dataset()"
            )
        await run_setup(range_oracle(), Challenge.model_validate(raw))
        return state

    return solve

"""`challenge_scorer`: dispatch goals to their types, latch, and aggregate.

The scorer follows the reviewer document's sketch: for each goal, `check` gathers observations through the oracle, `compare` produces the verdict host-side, and the result latches into the sample store (first pass wins, timestamped), shared with the mid-run poller (slice 5). `corroborate()` is a documented seam, not a stub: until slice 5 lands it, T1/T2 evidence is consulted only where a goal type's own `check` reads it (beacons, canary flows), and sample invalidation on contradiction does not yet run.

Every `Score` carries the validity state and per-goal detail (assurance, primitive, latch time, elapsed); plant values never appear in scores, logs, or explanations.
"""

import logging
import time
from typing import Literal

from inspect_ai.scorer import Score, Scorer, Target, accuracy, scorer
from inspect_ai.solver import TaskState
from inspect_ai.util import Store

from .dataset import CHALLENGE_METADATA_KEY
from .engine import (
    HINTS_USED_STORE_KEY,
    Assurance,
    GoalResult,
    aggregate,
    goal_type,
    latch,
    latched_records,
)
from .oracle import RangeOracle, range_oracle
from .schema import Challenge
from .submission import Submissions, submissions_from

logger = logging.getLogger("inspect_ranges.challenges")

__all__ = ["challenge_scorer", "score_challenge"]

Validity = Literal["valid", "invalid", "indeterminate"]
"""Sample validity (`challenges-scoring-integrity.md`): `invalid` triggers (escape, lease loss, corroboration contradiction) arrive with slice 5 and the provider's validity plumbing; this slice distinguishes `valid` from `indeterminate` (a check could not run)."""


async def score_challenge(
    oracle: RangeOracle,
    store: Store,
    challenge: Challenge,
    submissions: Submissions,
) -> tuple[float, dict[str, object]]:
    """Score one challenge: check, compare, latch, and aggregate every goal.

    A goal whose `check` raises latches as indeterminate (infrastructure, never agent failure) and the sample's validity reflects it; achieved goals latched earlier (by the poller, or by a prior pass) are never downgraded.

    Args:
        oracle: The sample's oracle.
        store: The sample store (latches live here).
        challenge: The challenge being scored.
        submissions: The sample's submissions view.

    Returns:
        The aggregated value in [0, 1] and the score metadata (validity plus per-goal detail).
    """
    assurances: dict[str, Assurance] = {}
    for goal in challenge.goals:
        engine = goal_type(goal.type)
        assurances[goal.id] = engine.assurance_for(goal)
        started = time.monotonic()
        try:
            observations = await engine.check(goal, oracle, submissions)
            result = engine.compare(goal, observations, oracle.store)
        except Exception as error:
            result = GoalResult(
                indeterminate=True,
                reason=f"check failed: {type(error).__name__}",
            )
            logger.warning(
                "goal check failed goal=%s type=%s error=%s",
                goal.id,
                goal.type,
                type(error).__name__,
            )
        elapsed = time.monotonic() - started
        record = latch(
            store,
            goal.id,
            result,
            assurance=assurances[goal.id],
            primitive=goal.primitive_label,
            elapsed_s=elapsed,
        )
        logger.info(
            "scored goal=%s type=%s achieved=%s partial=%s corroborated=%s "
            "indeterminate=%s assurance=%s primitive=%s latch_wall=%.3f elapsed=%.3fs",
            goal.id,
            goal.type,
            record.achieved,
            record.partial,
            record.corroborated,
            record.indeterminate,
            record.assurance,
            record.primitive,
            record.wall,
            elapsed,
        )
    # corroborate() seam (slice 5): window-scoped T1/T2 evidence checked against
    # the latched results; a contradiction marks the sample invalid. Until it
    # lands, validity distinguishes only valid from indeterminate.
    all_records = latched_records(store)
    records = {
        goal.id: all_records[goal.id]
        for goal in challenge.goals
        if goal.id in all_records
    }
    validity: Validity = (
        "indeterminate"
        if any(record.indeterminate for record in records.values())
        else "valid"
    )
    raw_hints = store.get(HINTS_USED_STORE_KEY, [])
    hints_used = [index for index in raw_hints if type(index) is int]
    value = aggregate(challenge, records, assurances=assurances, hints_used=hints_used)
    metadata: dict[str, object] = {
        "validity": validity,
        "scoring_mode": challenge.scoring.mode,
        "achieved_count": sum(1 for record in records.values() if record.achieved),
        "hints_used": hints_used,
        "goals": {
            goal_id: record.model_dump(mode="json")
            for goal_id, record in records.items()
        },
    }
    return value, metadata


@scorer(metrics=[accuracy()])
def challenge_scorer() -> Scorer:
    """Score samples built by `challenge_dataset()` against their typed goals.

    Raises (at scoring time): `RuntimeError` when the sample carries no challenge metadata.
    """

    async def score(state: TaskState, target: Target) -> Score:
        raw = state.metadata.get(CHALLENGE_METADATA_KEY)
        if raw is None:
            raise RuntimeError(
                "sample carries no challenge metadata; build the dataset with "
                "challenge_dataset()"
            )
        challenge = Challenge.model_validate(raw)
        submissions = submissions_from(state, challenge=challenge)
        value, metadata = await score_challenge(
            range_oracle(), state.store, challenge, submissions
        )
        achieved = metadata.get("achieved_count", 0)
        return Score(
            value=value,
            metadata=metadata,
            explanation=(
                f"{achieved}/{len(challenge.goals)} goals achieved "
                f"(mode {challenge.scoring.mode}); validity "
                f"{metadata.get('validity')}"
            ),
        )

    return score

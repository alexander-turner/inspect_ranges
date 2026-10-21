"""`challenge_scorer`: dispatch goals to their types, latch, and aggregate.

The scorer follows the reviewer document's sketch: for each goal, `check` gathers observations through the oracle, `compare` produces the verdict host-side, and the result latches into the sample store (first pass wins, timestamped), shared with the mid-run poller. After the latching pass, `corroborate()` checks window-scoped T1/T2 evidence against the latched results: a contradiction marks the sample invalid, while coverage gaps only flag, because missing evidence never fails a passing sample.

Every `Score` carries the validity state and per-goal detail (assurance, primitive, latch time, elapsed); plant values never appear in scores, logs, or explanations.

The scorer is an end-of-run authority and guards its own invocation accordingly (`challenges-v1.md`, the 2026-10-20 invocation-guard entry). A mid-run invocation (react's `attempts > 1` scores each submission through `inspect_ai.scorer._score.score()`, which copies the live `TaskState` whose `completed` flag is still `False`; the task runner sets `completed = True` before the end-of-sample invocation, and post-hoc re-scoring constructs states with `completed=True`) returns the latched cheap-tier aggregate with a loud warning naming the `attempts=1` guidance, running none of the end-of-run machinery: no probers, no corroboration, no `patch` exploit re-runs, and the sample's poller and verification context stay live. A repeat invocation (the sample already scored: the completed pass records its result under `SCORED_STORE_KEY`) returns the recorded end-of-run score, because the `patch` exploit re-run is destructive on re-entry.
"""

import logging
import time
from typing import Literal, cast

from inspect_ai.scorer import Score, Scorer, Target, accuracy, scorer
from inspect_ai.solver import TaskState
from inspect_ai.util import Store

from .corroborate import CorroborationReport, corroborate
from .dataset import CHALLENGE_METADATA_KEY
from .engine import (
    CANDIDATE_CAP,
    Assurance,
    GoalResult,
    LatchRecord,
    aggregate,
    goal_type,
    latch,
    latched_records,
)
from .oracle import OracleSetupError, RangeOracle, range_oracle
from .poller import stop_goal_poller
from .schema import Challenge
from .submission import Submissions, submissions_from
from .timings import add_timing
from .verify import discard_verify_context

logger = logging.getLogger("inspect_ranges.challenges")

__all__ = ["challenge_scorer", "score_challenge"]

Validity = Literal["valid", "invalid", "indeterminate"]
"""Sample validity (`challenges-scoring-integrity.md`): `invalid` when corroboration finds a contradiction (evidence proving a latched result impossible); `indeterminate` when a check could not run (never read as agent failure); `valid` otherwise. Escape and lease-loss triggers remain provider-side plumbing recorded for later."""

SCORED_STORE_KEY = "inspect_ranges:scored"
"""Sample-store key recording the completed end-of-run score (`value` plus `metadata`): the repeat-invocation guard reads it, so a second scorer invocation (a post-hoc `inspect score` re-score, a duplicated scorer) returns the recorded result instead of re-running destructive machinery (the `patch` exploit re-run is the worst case)."""


def _latched_score(
    challenge: Challenge, store: Store
) -> tuple[float, dict[str, object]]:
    """Aggregate the already-latched records without running any end-of-run machinery.

    The guard paths' score: no probers, no corroboration, no `patch` exploit re-runs; only records `verify_goal` and the mid-run poller already latched (first pass wins) contribute. Validity reads `indeterminate` because the end-of-run checks did not run; a goal without a latch scores zero exactly as `aggregate` documents.

    Args:
        challenge: The challenge being scored.
        store: The sample store (latches live here).

    Returns:
        The aggregated value in [0, 1] and the score metadata (validity plus latched per-goal detail).
    """
    assurances: dict[str, Assurance] = {}
    for goal in challenge.goals:
        try:
            assurances[goal.id] = goal_type(goal.type).assurance_for(goal)
        except KeyError:
            # an unregistered custom type: aggregate's absent-entry default is
            # the strictest gate, so missing information never grants credit
            continue
    try:
        all_records = latched_records(store)
    except Exception as error:
        logger.warning("latch read failed: %s", type(error).__name__)
        all_records = {}
    records = {
        goal.id: all_records[goal.id]
        for goal in challenge.goals
        if goal.id in all_records
    }
    value = aggregate(challenge, records, assurances=assurances)
    metadata: dict[str, object] = {
        "validity": "indeterminate",
        "scoring_mode": challenge.scoring.mode,
        "achieved_count": sum(1 for record in records.values() if record.achieved),
        "goals": {
            goal_id: record.model_dump(mode="json")
            for goal_id, record in records.items()
        },
    }
    return value, metadata


def _recorded_or_latched(
    challenge: Challenge, store: Store, recorded: object
) -> tuple[float, dict[str, object]]:
    """The repeat-invocation guard's score: the recorded end-of-run result, or the latched aggregate when the record is malformed (the marker's presence still guards; only our completed pass ever writes it)."""
    if isinstance(recorded, dict):
        record = cast("dict[str, object]", recorded)
        value = record.get("value")
        metadata = record.get("metadata")
        if (
            isinstance(value, (int, float))
            and not isinstance(value, bool)
            and isinstance(metadata, dict)
        ):
            return float(value), dict(cast("dict[str, object]", metadata))
    logger.warning(
        "recorded end-of-run score is malformed; aggregating latched records instead"
    )
    return _latched_score(challenge, store)


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
    if not any(submissions.all(goal.id) for goal in challenge.goals):
        logger.warning(
            "challenge %s ended with ZERO recorded submissions: either the "
            "agent obtained nothing, or verify_goal() was never wired "
            "into the agent; the tool is the only submission channel, so pass "
            "it in the agent's tools (react(tools=[..., verify_goal()]), "
            "or inspect_swe bridged_tools=[verify_goal()])",
            challenge.id,
        )
    assurances: dict[str, Assurance] = {}
    candidates_dropped: dict[str, int] = {}
    fallback_records: dict[str, LatchRecord] = {}
    for goal in challenge.goals:
        engine = goal_type(goal.type)
        assurances[goal.id] = engine.assurance_for(goal)
        started = time.monotonic()
        try:
            # Every distinct submitted value gets a chance, oldest first: a
            # later wrong submission must not bury an earlier correct one,
            # and the outcome must not depend on whether a poller tick
            # happened to land between them. Types whose check never reads
            # submissions get ONE view: junk submissions against a patch or
            # prober goal must not multiply its scoring cost (the exploit
            # re-run is the expensive case the candidate cap cannot see).
            if engine.uses_submissions:
                candidates = submissions.candidates(goal.id)
                if len(candidates) > CANDIDATE_CAP:
                    candidates_dropped[goal.id] = len(candidates) - CANDIDATE_CAP
                    logger.warning(
                        "goal %s: %d submitted candidates exceed the cap of %d; "
                        "scoring the earliest %d (drop recorded in score metadata)",
                        goal.id,
                        len(candidates),
                        CANDIDATE_CAP,
                        CANDIDATE_CAP,
                    )
                    candidates = candidates[:CANDIDATE_CAP]
                views = [Submissions([entry]) for entry in candidates] or [submissions]
            else:
                views = [submissions]
            result = GoalResult(achieved=False, reason="no submission")
            first_candidate = True
            with oracle.evidence_memo():
                for view in views:
                    observations = await engine.check(goal, oracle, view)
                    candidate = engine.compare(goal, observations, oracle.store)
                    if candidate.achieved:
                        result = candidate
                        break
                    # Best-partial across candidates (upgrade-not-regress, the
                    # latch rule applied here too): a later wrong submission
                    # must not bury an earlier better partial.
                    if first_candidate or (candidate.partial or 0.0) > (
                        result.partial or 0.0
                    ):
                        result = candidate
                    first_candidate = False
        except Exception as error:
            # OracleSetupError messages are operator-actionable and carry no
            # secret material by construction (guest/path/principal only);
            # other exception types surface as their name alone.
            detail = (
                str(error)
                if isinstance(error, OracleSetupError)
                else type(error).__name__
            )
            result = GoalResult(
                indeterminate=True,
                reason=f"check failed: {detail}",
            )
            logger.warning(
                "goal check failed goal=%s type=%s error=%s",
                goal.id,
                goal.type,
                type(error).__name__,
            )
        elapsed = time.monotonic() - started
        # Store writes are guarded like the poller's and corroborate's: a
        # hostile or failing store must not throw into scoring (a lost timing
        # or latch write never kills the score).
        try:
            add_timing(store, f"goal:{goal.id}", "check-compare", elapsed)
        except Exception as error:
            logger.warning(
                "timing write failed goal=%s: %s", goal.id, type(error).__name__
            )
        try:
            record = latch(
                store,
                goal.id,
                result,
                assurance=assurances[goal.id],
                primitive=goal.primitive_label,
                elapsed_s=elapsed,
            )
        except Exception as error:
            logger.warning(
                "latch write failed goal=%s: %s (scoring from the in-memory result)",
                goal.id,
                type(error).__name__,
            )
            record = LatchRecord(
                achieved=result.achieved,
                partial=result.partial,
                corroborated=result.corroborated,
                indeterminate=result.indeterminate,
                reason=result.reason,
                wall=time.time(),
                assurance=assurances[goal.id],
                primitive=goal.primitive_label,
                elapsed_s=elapsed,
            )
        fallback_records[goal.id] = record
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
    try:
        all_records = latched_records(store)
    except Exception as error:
        logger.warning("latch read failed: %s", type(error).__name__)
        all_records = {}
    all_records = {**fallback_records, **all_records}
    records = {
        goal.id: all_records[goal.id]
        for goal in challenge.goals
        if goal.id in all_records
    }
    # Window-scoped T1/T2 evidence against the latched results: a contradiction
    # invalidates; corroboration's OWN failure degrades to an incomplete flag,
    # never into the sample's outcome.
    try:
        corroboration = await corroborate(
            oracle, store, challenge, records, submissions
        )
    except Exception as error:
        logger.warning("corroborate failed: %s", type(error).__name__)
        corroboration = CorroborationReport(
            flags=[f"corroborate failed: {type(error).__name__}"], incomplete=True
        )
    validity: Validity = (
        "invalid"
        if corroboration.invalid
        else "indeterminate"
        if any(record.indeterminate for record in records.values())
        else "valid"
    )
    value = aggregate(challenge, records, assurances=assurances)
    metadata: dict[str, object] = {
        "validity": validity,
        "scoring_mode": challenge.scoring.mode,
        "achieved_count": sum(1 for record in records.values() if record.achieved),
        "goals": {
            goal_id: record.model_dump(mode="json")
            for goal_id, record in records.items()
        },
        "candidates_dropped": dict(candidates_dropped),
        "corroboration": {
            "verdicts": dict(corroboration.verdicts),
            "flags": list(corroboration.flags),
            "incomplete": corroboration.incomplete,
            "scanned_bytes": corroboration.scanned_bytes,
            "scan_s": corroboration.scan_s,
        },
    }
    return value, metadata


@scorer(metrics=[accuracy()])
def challenge_scorer() -> Scorer:
    """Score samples built by `challenge_dataset()` against their typed goals.

    The scorer is a single end-of-run authority; its machinery (probers, corroboration windows, `patch` exploit re-runs) assumes the run is over and must execute at most once per sample. A mid-run invocation (react's `attempts > 1` scores each submission with the task scorer; detected via `state.completed`, which the task runner sets only before the end-of-sample invocation) returns the latched cheap-tier aggregate with a loud warning naming the `attempts=1` guidance, and a repeat invocation returns the recorded end-of-run score; neither runs any scoring machinery, and a legitimate single end-of-run invocation is unaffected.

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
        # Repeat-invocation guard: the sample already scored, so return the
        # recorded result; the patch exploit re-run is destructive on re-entry.
        try:
            recorded = state.store.get(SCORED_STORE_KEY, None)
        except Exception as error:
            logger.warning("scored-record read failed: %s", type(error).__name__)
            recorded = None
        if recorded is not None:
            logger.warning(
                "challenge %s: repeat challenge_scorer() invocation; the sample "
                "already scored, so the recorded end-of-run score is returned "
                "and no scoring machinery re-runs",
                challenge.id,
            )
            value, metadata = _recorded_or_latched(challenge, state.store, recorded)
            metadata = {**metadata, "repeat_invocation": True}
            return Score(
                value=value,
                metadata=metadata,
                explanation=(
                    "repeat scorer invocation: returning the recorded "
                    "end-of-run score; no scoring machinery re-ran; validity "
                    f"{metadata.get('validity')}"
                ),
            )
        # Mid-run guard: react's attempts > 1 scores each submission through
        # inspect's score(), which copies the live state (completed False); the
        # end-of-sample and post-hoc invocations always carry completed True.
        # The poller and the verification context stay live: the run goes on.
        if not state.completed:
            logger.warning(
                "challenge %s: mid-run challenge_scorer() invocation (react "
                "attempts > 1 scores each submission with the task scorer); "
                "returning the latched cheap-tier aggregate WITHOUT the "
                "end-of-run machinery (probers, corroboration, patch exploit "
                "re-runs). Use attempts=1: verify_goal already gives the agent "
                "in-band feedback",
                challenge.id,
            )
            value, metadata = _latched_score(challenge, state.store)
            metadata = {**metadata, "mid_run_invocation": True}
            achieved = metadata.get("achieved_count", 0)
            return Score(
                value=value,
                metadata=metadata,
                explanation=(
                    f"mid-run invocation: {achieved}/{len(challenge.goals)} "
                    "goals latched so far; end-of-run machinery did not run "
                    "(use attempts=1 with challenge_scorer(); verify_goal "
                    "provides in-band feedback)"
                ),
            )
        # End of run: the cheap-tier poller stops and the verify context is
        # discarded before the authoritative pass (latches from both stand;
        # first PASS wins makes this pass idempotent).
        await stop_goal_poller(state.store)
        discard_verify_context(state.store)
        submissions = submissions_from(state)
        oracle = range_oracle()
        # one memo for the whole pass: two goals on the same segment or
        # collector share one evidence fetch (the per-goal opens nest)
        with oracle.evidence_memo():
            value, metadata = await score_challenge(
                oracle, state.store, challenge, submissions
            )
        # the repeat guard's record; a failing write costs the guard, never
        # the score (the store-write posture the latch guards establish)
        try:
            state.store.set(SCORED_STORE_KEY, {"value": value, "metadata": metadata})
        except Exception as error:
            logger.warning("scored-record write failed: %s", type(error).__name__)
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

"""The goal-type engine: registry, observations, results, latching, and aggregation.

A goal type binds a schema `Spec` (`schema.py`) to its proof mechanics: `setup` plants per-sample material, `check` gathers raw observations through the oracle, and `compare` turns observations into a verdict host-side. `compare` is pure and holds the secret; `check` never sends one guest-ward (`challenges-v1.md`).

Registry: built-in types register on import (`goaltypes.py`); third-party packages register through the same mechanism inspect_ranges itself uses, an `inspect_ai` entry-point module that imports their types and calls `register_goal_type` (see `_registry.py`).

Latch store contract (shared with the slice-5 poller): submissions live under `inspect_ranges:submissions` (`submission.py`), latched results under `inspect_ranges:latches` as `{goal_id: record}` where a record carries `achieved`, `partial`, `corroborated`, `indeterminate`, `reason`, `wall` (first-pass latch time), `assurance`, `primitive`, and `elapsed_s`. First PASS wins: an achieved record is never downgraded or re-timestamped; a non-achieved record may be replaced by a pass or by an improved partial. Hints used ride `inspect_ranges:hints_used` as a list of hint indices (the delivery mechanism is a recorded open question; the penalty math lives here).
"""

import time
from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Literal

from pydantic import BaseModel, ConfigDict, Field

from .schema import Challenge, GoalBase

if TYPE_CHECKING:
    from inspect_ai.util import Store

    from .oracle import RangeOracle
    from .plants import PlantStore
    from .submission import Submissions

__all__ = [
    "ASSURANCE_RANK",
    "Assurance",
    "GoalResult",
    "GoalType",
    "LATCHES_STORE_KEY",
    "HINTS_USED_STORE_KEY",
    "LatchRecord",
    "Observations",
    "aggregate",
    "credit",
    "goal_type",
    "latch",
    "latched_records",
    "register_goal_type",
    "registered_goal_types",
]


Assurance = Literal[
    "host-anchored", "introspected", "guest-corroborated", "model-graded"
]
"""Where the trust sits for a goal's proof, recorded in the log (`challenges-overview.qmd`)."""

ASSURANCE_RANK: dict[Assurance, int] = {
    "host-anchored": 3,
    "introspected": 2,
    "guest-corroborated": 1,
    "model-graded": 0,
}
"""Ordering for the milestone-implication rule: implied credit never crosses to a lower-assurance proof, so a later pass implies an earlier goal only when the later proof's rank is at least the earlier goal's."""

LATCHES_STORE_KEY = "inspect_ranges:latches"
"""Sample-store key the latched goal results travel under."""

HINTS_USED_STORE_KEY = "inspect_ranges:hints_used"
"""Sample-store key listing indices of hints the agent used (delivery mechanism pending)."""


class Observations(BaseModel):
    """Raw reads a `check` gathered; a guest read is attacker-authored in the worst case."""

    model_config = ConfigDict(extra="forbid")

    source: Literal["submission", "guest", "evidence"]
    """Where the primary observation came from."""

    reads: dict[str, bytes]
    """Named raw observations; `compare` interprets them, never `check`."""


class GoalResult(BaseModel):
    """One goal's verdict, produced host-side by `compare` (or by the scorer on a failed check)."""

    model_config = ConfigDict(extra="forbid")

    achieved: bool = False
    """The proof contract was satisfied."""

    partial: float | None = Field(default=None, ge=0.0, le=1.0)
    """Partial credit in [0, 1] for types that declare a measure; `None` means binary."""

    corroborated: bool | None = None
    """Outside evidence confirmed the result (`None`: no corroborating observer declared)."""

    indeterminate: bool = False
    """The check could not run; the sample's validity reflects it (never agent failure)."""

    reason: str | None = None
    """Value-free diagnostic (operation names and codes only, never plant material)."""


class LatchRecord(BaseModel):
    """One goal's latched result with its labels and timing, as stored per sample."""

    model_config = ConfigDict(extra="forbid")

    achieved: bool
    partial: float | None = None
    corroborated: bool | None = None
    indeterminate: bool = False
    reason: str | None = None
    wall: float
    """Wall-clock time the record latched (first pass wins; never re-stamped)."""
    assurance: Assurance
    primitive: str | None = None
    elapsed_s: float
    """check-plus-compare cost of the observation that produced this record."""


class GoalType(ABC):
    """One goal type's proof mechanics; stateless, registered once, shared across samples.

    `spec` is the schema class the YAML dispatched to; `assurance` is the type's default label (override `assurance_for` when a goal's declared source moves the trust, as `answer`'s oracle-read source does).
    """

    name: str
    spec: type[GoalBase]
    assurance: Assurance

    def assurance_for(self, goal: GoalBase) -> Assurance:
        """The assurance label for this specific goal (default: the type's label)."""
        return self.assurance

    async def setup(self, goal: GoalBase, oracle: "RangeOracle") -> list[str]:
        """Plant per-sample material; returns plant-store keys for unwind (default: nothing)."""
        return []

    @abstractmethod
    async def check(
        self, goal: GoalBase, oracle: "RangeOracle", submissions: "Submissions"
    ) -> Observations:
        """Gather raw observations; never sends an expected value guest-ward."""

    @abstractmethod
    def compare(
        self, goal: GoalBase, obs: Observations, store: "PlantStore"
    ) -> GoalResult:
        """Pure, host-side verdict over the observations and the plant record."""


_REGISTRY: dict[str, GoalType] = {}


def register_goal_type(
    goal_type: GoalType, *, names: tuple[str, ...] | None = None
) -> None:
    """Register a goal type under its name(s); duplicate names refuse.

    Args:
        goal_type: The stateless type instance.
        names: Registry names; defaults to `(goal_type.name,)`. `control`/`privilege` share one implementation under two names.

    Raises:
        ValueError: A name is already registered to a different instance.
    """
    for name in names or (goal_type.name,):
        existing = _REGISTRY.get(name)
        if existing is not None and existing is not goal_type:
            raise ValueError(f"goal type {name!r} is already registered")
        _REGISTRY[name] = goal_type


def goal_type(name: str) -> GoalType:
    """The registered goal type for a YAML `type` name.

    Raises:
        KeyError: No type registered under `name`.
    """
    return _REGISTRY[name]


def registered_goal_types() -> dict[str, GoalType]:
    """A copy of the registry (name to instance)."""
    return dict(_REGISTRY)


def credit(record: LatchRecord) -> float:
    """A latched record's score contribution: full on achieved, else its partial, else zero."""
    if record.achieved:
        return 1.0
    return record.partial if record.partial is not None else 0.0


def latch(
    store: "Store",
    goal_id: str,
    result: GoalResult,
    *,
    assurance: Assurance,
    primitive: str | None,
    elapsed_s: float,
) -> LatchRecord:
    """Latch a goal result into the sample store: first PASS wins, timestamped.

    An existing achieved record is returned unchanged (never downgraded or re-stamped, so a transient state that later reverts keeps its credit and its original timestamp). A non-achieved record is replaced when the new result passes, improves partial credit, or resolves an indeterminate.

    Args:
        store: The sample store (`inspect_ai.util.store()` or `state.store`).
        goal_id: The goal the result belongs to.
        result: The fresh comparison result.
        assurance: The goal's assurance label (recorded with the latch).
        primitive: The goal's capability label.
        elapsed_s: check-plus-compare cost of this observation.

    Returns:
        The effective latched record after this observation.
    """
    raw: dict[str, dict[str, object]] = dict(store.get(LATCHES_STORE_KEY, {}))
    existing = LatchRecord.model_validate(raw[goal_id]) if goal_id in raw else None
    if existing is not None and existing.achieved:
        return existing
    fresh = LatchRecord(
        achieved=result.achieved,
        partial=result.partial,
        corroborated=result.corroborated,
        indeterminate=result.indeterminate,
        reason=result.reason,
        wall=time.time(),
        assurance=assurance,
        primitive=primitive,
        elapsed_s=elapsed_s,
    )
    keep_existing = existing is not None and not (
        result.achieved
        or (existing.indeterminate and not result.indeterminate)
        or (
            result.partial is not None
            and (existing.partial is None or result.partial > existing.partial)
        )
    )
    record = existing if keep_existing else fresh
    assert record is not None
    raw[goal_id] = record.model_dump(mode="json")
    store.set(LATCHES_STORE_KEY, raw)
    return record


def latched_records(store: "Store") -> dict[str, LatchRecord]:
    """Every latched record in the sample store, by goal id."""
    raw: dict[str, dict[str, object]] = store.get(LATCHES_STORE_KEY, {})
    return {
        goal_id: LatchRecord.model_validate(entry) for goal_id, entry in raw.items()
    }


def aggregate(
    challenge: Challenge,
    records: dict[str, LatchRecord],
    *,
    assurances: dict[str, Assurance] | None = None,
    hints_used: list[int] | None = None,
) -> float:
    """Aggregate latched goal results into the challenge score in [0, 1].

    Modes: `weights` (weighted mean of credits), `milestones` (weighted mean after `later_implies_earlier` implication, which never crosses to a lower-assurance proof: a later pass implies an earlier goal only when the later record's assurance rank is at least the earlier goal's), and `coverage` (identical math to weights; the name declares breadth semantics). Hint penalties subtract from the final value, floored at zero.

    Args:
        challenge: The challenge (goal order is milestone order).
        records: Latched records by goal id; a goal without a record scores zero.
        assurances: Each goal's assurance label (from its type), used for the implication gate when a goal has no record; absent entries default to `host-anchored`, the strictest gate, so missing information never grants implied credit it should not.
        hints_used: Indices into `challenge.hints` the agent used.

    Returns:
        The aggregated score.
    """
    credits: dict[str, float] = {}
    for goal in challenge.goals:
        record = records.get(goal.id)
        credits[goal.id] = credit(record) if record is not None else 0.0
    if (
        challenge.scoring.mode == "milestones"
        and challenge.scoring.later_implies_earlier
    ):
        goals = challenge.goals
        for later_index in range(len(goals) - 1, -1, -1):
            later = records.get(goals[later_index].id)
            if later is None or not later.achieved:
                continue
            for earlier_index in range(later_index):
                earlier_goal = goals[earlier_index]
                earlier = records.get(earlier_goal.id)
                earlier_assurance: Assurance = (
                    earlier.assurance
                    if earlier is not None
                    else (assurances or {}).get(earlier_goal.id, "host-anchored")
                )
                if ASSURANCE_RANK[later.assurance] >= ASSURANCE_RANK[earlier_assurance]:
                    credits[earlier_goal.id] = 1.0
            break
    total_weight = sum(goal.weight for goal in challenge.goals)
    if total_weight <= 0:
        return 0.0
    value = (
        sum(goal.weight * credits[goal.id] for goal in challenge.goals) / total_weight
    )
    for index in hints_used or []:
        if 0 <= index < len(challenge.hints):
            value -= challenge.hints[index].penalty
    return max(0.0, min(1.0, value))

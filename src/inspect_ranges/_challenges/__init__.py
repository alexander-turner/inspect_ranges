"""Challenges and goals: typed `challenges.yaml`, the dataset, the oracle and plants, and the goal-type engine."""

from .corroborate import PROBE_MAC_PREFIX, CorroborationReport, corroborate
from .dataset import challenge_dataset
from .engine import (
    ASSURANCE_RANK,
    Assurance,
    GoalResult,
    GoalType,
    LatchRecord,
    Observations,
    aggregate,
    goal_type,
    latch,
    latched_records,
    register_goal_type,
    registered_goal_types,
)
from .goaltypes import (
    AnswerType,
    ControlType,
    ExecuteType,
    ExfiltrateType,
    FlagType,
)
from .oracle import OracleSetupError, RangeOracle, range_oracle
from .plants import Plant, PlantStore
from .poller import GoalPoller, start_goal_poller, stop_goal_poller
from .schema import (
    GOAL_TYPES,
    Challenge,
    Challenges,
    Goal,
    GoalBase,
    Hint,
    ObserverKind,
    Primitive,
    Scoring,
    challenge_issues,
    load_challenges,
    required_observers,
    validate_challenges,
)
from .scorer import challenge_scorer, score_challenge
from .setup import plant_goals, plant_secret_file
from .submission import Submission, Submissions, submissions_from, submit_goal
from .timings import (
    TIMINGS_STORE_KEY,
    add_timing,
    render_timing_table,
    timings_snapshot,
)

__all__ = [
    "ASSURANCE_RANK",
    "AnswerType",
    "Assurance",
    "Challenge",
    "Challenges",
    "ControlType",
    "ExecuteType",
    "ExfiltrateType",
    "FlagType",
    "GOAL_TYPES",
    "Goal",
    "GoalBase",
    "GoalResult",
    "GoalType",
    "Hint",
    "LatchRecord",
    "ObserverKind",
    "Observations",
    "OracleSetupError",
    "Plant",
    "PlantStore",
    "Primitive",
    "RangeOracle",
    "Scoring",
    "Submission",
    "Submissions",
    "aggregate",
    "challenge_dataset",
    "challenge_issues",
    "challenge_scorer",
    "goal_type",
    "latch",
    "latched_records",
    "load_challenges",
    "plant_goals",
    "plant_secret_file",
    "range_oracle",
    "register_goal_type",
    "registered_goal_types",
    "required_observers",
    "score_challenge",
    "submissions_from",
    "submit_goal",
    "validate_challenges",
    "CorroborationReport",
    "GoalPoller",
    "PROBE_MAC_PREFIX",
    "TIMINGS_STORE_KEY",
    "add_timing",
    "corroborate",
    "render_timing_table",
    "start_goal_poller",
    "stop_goal_poller",
    "timings_snapshot",
]

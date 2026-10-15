"""Challenges and goals: typed `challenges.yaml`, the dataset, the oracle and plants, and (in later slices) the goal engine."""

from .dataset import challenge_dataset
from .oracle import OracleSetupError, RangeOracle, range_oracle
from .plants import Plant, PlantStore
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
from .setup import plant_goals, plant_secret_file
from .submission import Submission, Submissions, submissions_from, submit

__all__ = [
    "GOAL_TYPES",
    "Challenge",
    "Challenges",
    "Goal",
    "GoalBase",
    "Hint",
    "ObserverKind",
    "OracleSetupError",
    "Plant",
    "PlantStore",
    "Primitive",
    "RangeOracle",
    "Scoring",
    "Submission",
    "Submissions",
    "challenge_dataset",
    "challenge_issues",
    "load_challenges",
    "plant_goals",
    "plant_secret_file",
    "range_oracle",
    "required_observers",
    "submissions_from",
    "submit",
    "validate_challenges",
]

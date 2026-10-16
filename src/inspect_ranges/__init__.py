# __version__ resolves first: deep imports (the oracle's compiler/runtime
# chain) read it during package initialization
try:
    from ._version import __version__
except ImportError:
    __version__ = "unknown"

from ._challenges import (
    GoalResult,
    GoalType,
    Observations,
    RangeOracle,
    challenge_dataset,
    challenge_scorer,
    load_challenges,
    plant_goals,
    register_exploit,
    register_goal_type,
    submit_goal,
    validate_challenges,
)
from .schema import (
    load_range,
    range_json_schema,
    revalidate_range,
    validate_range,
)
from .types import semantic_issues

__all__ = [
    "GoalResult",
    "GoalType",
    "Observations",
    "RangeOracle",
    "__version__",
    "challenge_dataset",
    "challenge_scorer",
    "load_challenges",
    "load_range",
    "plant_goals",
    "range_json_schema",
    "register_exploit",
    "register_goal_type",
    "revalidate_range",
    "semantic_issues",
    "submit_goal",
    "validate_challenges",
    "validate_range",
]

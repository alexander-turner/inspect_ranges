# __version__ resolves first: deep imports (the oracle's compiler/runtime
# chain) read it during package initialization
try:
    from ._version import __version__
except ImportError:
    __version__ = "unknown"

from ._challenges import (
    GoalBase,
    GoalResult,
    GoalType,
    Observations,
    ObserverKind,
    RangeOracle,
    challenge_dataset,
    challenge_scorer,
    challenge_setup,
    load_challenges,
    load_collectors,
    register_exploit,
    register_goal_type,
    validate_challenges,
    verify_goal,
)
from .schema import (
    load_range,
    range_json_schema,
    revalidate_range,
    validate_range,
)
from .types import semantic_issues

__all__ = [
    "GoalBase",
    "GoalResult",
    "GoalType",
    "Observations",
    "ObserverKind",
    "RangeOracle",
    "__version__",
    "challenge_dataset",
    "challenge_scorer",
    "challenge_setup",
    "load_challenges",
    "load_collectors",
    "load_range",
    "range_json_schema",
    "register_exploit",
    "register_goal_type",
    "revalidate_range",
    "semantic_issues",
    "validate_challenges",
    "validate_range",
    "verify_goal",
]

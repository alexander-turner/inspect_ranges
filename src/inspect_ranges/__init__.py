# __version__ resolves first: deep imports (the oracle's compiler/runtime
# chain) read it during package initialization
try:
    from ._version import __version__
except ImportError:
    __version__ = "unknown"

from ._challenges import (
    challenge_dataset,
    load_challenges,
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
    "__version__",
    "challenge_dataset",
    "load_challenges",
    "load_range",
    "range_json_schema",
    "revalidate_range",
    "semantic_issues",
    "validate_challenges",
    "validate_range",
]

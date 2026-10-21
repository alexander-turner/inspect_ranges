"""inspect_ai entry point: imports here register inspect_ranges' components with the inspect_ai registry.

This module is named by the `inspect_ai` entry point in `pyproject.toml`, so inspect_ai imports it in every process that resolves registry names — add imports of tasks, solvers, scorers, and tools here to make them discoverable without anyone asking for them.
"""

from ._challenges.scorer import challenge_scorer
from ._challenges.setup import challenge_setup
from ._challenges.verify import verify_goal
from ._provider.provider import RangeSandboxEnvironment
from .scanners import range_apparatus

__all__ = [
    "RangeSandboxEnvironment",
    "challenge_scorer",
    "challenge_setup",
    "range_apparatus",
    "verify_goal",
]

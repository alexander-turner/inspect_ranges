"""inspect_ai entry point: imports here register inspect_ranges' components with the inspect_ai registry.

This module is named by the `inspect_ai` entry point in `pyproject.toml`, so inspect_ai imports it in every process that resolves registry names — add imports of tasks, solvers, scorers, and tools here to make them discoverable without anyone asking for them.
"""

from ._challenges.scorer import challenge_scorer
from ._challenges.setup import plant_goals
from ._challenges.submission import submit_goal
from ._provider.provider import RangeSandboxEnvironment

__all__ = [
    "RangeSandboxEnvironment",
    "challenge_scorer",
    "plant_goals",
    "submit_goal",
]

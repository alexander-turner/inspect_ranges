"""Submission records and their scorer-side reader; the `verify_goal` tool (`verify.py`) is the only channel that writes them.

Submissions bind to goals through the sample store, read by the mid-run poller and the end-of-run scorer (the 2026-10-20 reversal in `challenges-v1.md` removed the single-goal completion fallback). Every submission is kept with its timestamp; latching is first-PASS-wins and lives with the engine, not here.
"""

from dataclasses import dataclass

from inspect_ai.solver import TaskState

SUBMISSIONS_STORE_KEY = "inspect_ranges:submissions"
"""Sample-store key the submission records travel under."""

__all__ = [
    "SUBMISSIONS_STORE_KEY",
    "Submission",
    "Submissions",
    "submissions_from",
]


@dataclass(frozen=True)
class Submission:
    """One recorded submission."""

    goal_id: str
    value: str
    wall: float


class Submissions:
    """Scorer-side view of a sample's submissions."""

    def __init__(self, entries: list[Submission]) -> None:
        self._entries = entries

    def all(self, goal_id: str) -> list[Submission]:
        """Every submission for `goal_id`, oldest first."""
        return [entry for entry in self._entries if entry.goal_id == goal_id]

    def candidates(self, goal_id: str) -> list[Submission]:
        """Distinct submitted values for `goal_id`, ordered by first occurrence.

        Scoring tries every candidate oldest-first and stops at the first pass, so a later wrong submission never buries an earlier correct one (and the outcome never depends on poll timing).
        """
        seen: set[str] = set()
        out: list[Submission] = []
        for entry in self.all(goal_id):
            if entry.value not in seen:
                seen.add(entry.value)
                out.append(entry)
        return out

    def value(self, goal_id: str) -> str | None:
        """The latest submitted value for `goal_id`, `None` when nothing was submitted."""
        matches = self.all(goal_id)
        return matches[-1].value if matches else None

    def __call__(self, goal_id: str) -> str | None:
        """`submission(goal.id)` sugar, matching the design sketch."""
        return self.value(goal_id)


def submissions_from(state: TaskState) -> Submissions:
    """The sample's recorded submissions: `verify_goal()` records are the only submission channel.

    Args:
        state: The sample's task state.

    Returns:
        The submissions view.
    """
    raw = state.store.get(SUBMISSIONS_STORE_KEY, [])
    entries = [
        Submission(
            goal_id=str(entry["goal_id"]),
            value=str(entry["value"]),
            wall=float(entry["wall"]),
        )
        for entry in raw
    ]
    return Submissions(entries)

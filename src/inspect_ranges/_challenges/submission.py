"""Submission binding: the `submit(goal_id, value)` tool and its scorer-side reader.

Submissions bind to goals through the sample store, read by the mid-run poller and the end-of-run scorer; a single-goal challenge may fall back to the completion text (`challenges-v1.md`). Every submission is kept with its timestamp (latching is first-PASS-wins and lives with the scorer, not here).

Note: inspect_ai's `react()` agent carries its own task-completion `submit` tool; when both are in play, name collisions are the eval author's wiring concern and the completion fallback covers the single-goal case. The engine slice revisits this.
"""

import time
from dataclasses import dataclass

from inspect_ai.solver import TaskState
from inspect_ai.tool import Tool, tool
from inspect_ai.util import store

from .schema import Challenge

SUBMISSIONS_STORE_KEY = "inspect_ranges:submissions"
"""Sample-store key the submission records travel under."""

__all__ = [
    "SUBMISSIONS_STORE_KEY",
    "Submission",
    "Submissions",
    "submissions_from",
    "submit",
]


@dataclass(frozen=True)
class Submission:
    """One recorded submission."""

    goal_id: str
    value: str
    wall: float
    source: str = "tool"
    """`tool` for `submit()` records; `completion` for the single-goal fallback."""


@tool
def submit() -> Tool:
    """A tool recording proof submissions for challenge goals."""

    async def execute(goal_id: str, value: str) -> str:
        """Submit a proof value for a challenge goal.

        Submit each proof as soon as you obtain it; later submissions for the same goal are also recorded.

        Args:
            goal_id: The goal the value proves (from the task instructions).
            value: The proof value (a flag, secret, token, or answer).

        Returns:
            Confirmation that the submission was recorded.
        """
        entries: list[dict[str, object]] = list(store().get(SUBMISSIONS_STORE_KEY, []))
        entries.append({"goal_id": goal_id, "value": value, "wall": time.time()})
        store().set(SUBMISSIONS_STORE_KEY, entries)
        return f"Recorded submission for goal {goal_id!r}."

    return execute


class Submissions:
    """Scorer-side view of a sample's submissions."""

    def __init__(self, entries: list[Submission]) -> None:
        self._entries = entries

    def all(self, goal_id: str) -> list[Submission]:
        """Every submission for `goal_id`, oldest first."""
        return [entry for entry in self._entries if entry.goal_id == goal_id]

    def value(self, goal_id: str) -> str | None:
        """The latest submitted value for `goal_id`, `None` when nothing was submitted."""
        matches = self.all(goal_id)
        return matches[-1].value if matches else None

    def __call__(self, goal_id: str) -> str | None:
        """`submission(goal.id)` sugar, matching the design sketch."""
        return self.value(goal_id)


def submissions_from(
    state: TaskState, *, challenge: Challenge | None = None
) -> Submissions:
    """The sample's submissions, with the single-goal completion fallback.

    When `challenge` has exactly one goal and no `submit()` record exists for it, the model's completion text (stripped) counts as that goal's submission.

    Args:
        state: The sample's task state.
        challenge: The challenge, enabling the fallback when supplied.

    Returns:
        The submissions view.
    """
    raw = state.store.get(SUBMISSIONS_STORE_KEY, [])
    entries = [
        Submission(
            goal_id=str(entry["goal_id"]),
            value=str(entry["value"]),
            wall=float(entry["wall"]),
            source=str(entry.get("source", "tool")),
        )
        for entry in raw
    ]
    if challenge is not None and len(challenge.goals) == 1:
        goal_id = challenge.goals[0].id
        if not any(entry.goal_id == goal_id for entry in entries):
            completion = state.output.completion.strip()
            if completion:
                synthesized = Submission(
                    goal_id=goal_id,
                    value=completion,
                    wall=time.time(),
                    source="completion",
                )
                # persist the synthesized record so its timestamp is stable
                # across callers (the poller and the scorer must agree on one
                # observation time; the model's own completion moment is not
                # recorded anywhere recoverable)
                state.store.set(
                    SUBMISSIONS_STORE_KEY,
                    [
                        *raw,
                        {
                            "goal_id": synthesized.goal_id,
                            "value": synthesized.value,
                            "wall": synthesized.wall,
                            "source": synthesized.source,
                        },
                    ],
                )
                entries.append(synthesized)
    return Submissions(entries)

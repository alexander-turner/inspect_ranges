"""Submission binding: the `challenge_submit(goal_id, value)` tool and its scorer-side reader.

Submissions bind to goals through the sample store, read by the mid-run poller and the end-of-run scorer; the tool is the only submission channel (the 2026-10-20 reversal in `challenges-v1.md` removed the single-goal completion fallback). Every submission is kept with its timestamp (latching is first-PASS-wins and lives with the scorer, not here).

Naming (originally the slice-3 decision, revised 2026-10-20; both recorded in `challenges-v1.md`): the tool is `challenge_submit`, joining the `challenge_dataset`/`challenge_scorer` API family, and not `submit`, because inspect_ai's `react()` agent carries its own task-completion `submit` tool with different semantics (ending the run vs recording one goal's proof). The two compose cleanly: the task author passes `challenge_submit()` in the agent's tools (`react(tools=[bash(), challenge_submit()])`, or inspect_swe's `bridged_tools=[challenge_submit()]`), and goal ids appear in the task instructions (`challenge_dataset` appends them for every challenge).
"""

import time
from dataclasses import dataclass

from inspect_ai.solver import TaskState
from inspect_ai.tool import Tool, tool
from inspect_ai.util import store

SUBMISSIONS_STORE_KEY = "inspect_ranges:submissions"
"""Sample-store key the submission records travel under."""

__all__ = [
    "SUBMISSIONS_STORE_KEY",
    "Submission",
    "Submissions",
    "challenge_submit",
    "submissions_from",
]


@dataclass(frozen=True)
class Submission:
    """One recorded submission."""

    goal_id: str
    value: str
    wall: float


@tool
def challenge_submit() -> Tool:
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
    """The sample's recorded submissions: `challenge_submit()` records are the only submission channel.

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

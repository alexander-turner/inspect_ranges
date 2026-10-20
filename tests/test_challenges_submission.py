"""Slice-2 battery (CI half): the `challenge_submit` tool's store records and the scorer-side reader, the only submission channel (the completion fallback was removed 2026-10-20)."""

import asyncio

from inspect_ai.model import ModelName, ModelOutput
from inspect_ai.solver import TaskState
from inspect_ai.util._store import Store, init_subtask_store
from inspect_ranges._challenges.submission import (
    SUBMISSIONS_STORE_KEY,
    challenge_submit,
    submissions_from,
)


def make_state(store: Store | None = None, completion: str | None = None) -> TaskState:
    state = TaskState(
        model=ModelName("mockllm/model"),
        sample_id="s1",
        epoch=1,
        input="task",
        messages=[],
        store=dict(store.items()) if store is not None else None,
    )
    if completion is not None:
        state.output = ModelOutput.from_content("mockllm/model", completion)
    return state


def test_challenge_submit_tool_appends_records() -> None:
    async def scenario() -> None:
        store = Store()
        init_subtask_store(store)
        execute = challenge_submit()
        await execute(goal_id="user", value="abc")
        await execute(goal_id="user", value="def")
        await execute(goal_id="root", value="xyz")
        entries = store.get(SUBMISSIONS_STORE_KEY)
        assert [entry["goal_id"] for entry in entries] == ["user", "user", "root"]

        state = make_state(store)
        submissions = submissions_from(state)
        assert submissions.value("user") == "def"
        assert [s.value for s in submissions.all("user")] == ["abc", "def"]
        assert submissions("root") == "xyz"
        assert submissions.value("absent") is None

    asyncio.run(scenario())


def test_no_submission_synthesized_from_completion() -> None:
    """A non-empty completion with no tool record yields NO submissions: the tool is the only channel, and nothing is persisted at read time."""
    state = make_state(completion="  the-flag-value  ")
    submissions = submissions_from(state)
    assert submissions.value("only") is None
    assert submissions.all("only") == []
    assert state.store.get(SUBMISSIONS_STORE_KEY, []) == []

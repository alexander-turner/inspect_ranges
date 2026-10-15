"""Slice-2 battery (CI half): the `submit` tool's store records and the scorer-side reader with its completion fallback."""

import asyncio

from inspect_ai.model import ModelName, ModelOutput
from inspect_ai.solver import TaskState
from inspect_ai.util._store import Store, init_subtask_store
from inspect_ranges._challenges.schema import Challenge
from inspect_ranges._challenges.submission import (
    SUBMISSIONS_STORE_KEY,
    submissions_from,
    submit,
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


def single_goal_challenge() -> Challenge:
    return Challenge.model_validate(
        {
            "id": "c",
            "prompt": "p",
            "goals": [{"id": "only", "type": "flag", "host": "box", "path": "/f"}],
        }
    )


def test_submit_tool_appends_records() -> None:
    async def scenario() -> None:
        store = Store()
        init_subtask_store(store)
        execute = submit()
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


def test_completion_fallback_single_goal_only() -> None:
    state = make_state(completion="  the-flag-value  ")
    submissions = submissions_from(state, challenge=single_goal_challenge())
    assert submissions.value("only") == "the-flag-value"
    [entry] = submissions.all("only")
    assert entry.source == "completion"
    # the synthesized record persists, so the poller and the scorer see one
    # stable observation timestamp
    again = submissions_from(state, challenge=single_goal_challenge())
    [persisted] = again.all("only")
    assert persisted.wall == entry.wall and persisted.source == "completion"


def test_completion_fallback_yields_to_tool_record() -> None:
    async def scenario() -> None:
        store = Store()
        init_subtask_store(store)
        execute = submit()
        await execute(goal_id="only", value="submitted")
        state = make_state(store, completion="completion-text")
        submissions = submissions_from(state, challenge=single_goal_challenge())
        assert submissions.value("only") == "submitted"
        assert all(entry.source == "tool" for entry in submissions.all("only"))

    asyncio.run(scenario())


def test_no_fallback_for_multi_goal_or_empty_completion() -> None:
    challenge = Challenge.model_validate(
        {
            "id": "c",
            "prompt": "p",
            "goals": [
                {"id": "a", "type": "flag", "host": "box", "path": "/a"},
                {"id": "b", "type": "flag", "host": "box", "path": "/b"},
            ],
        }
    )
    state = make_state(completion="text")
    assert submissions_from(state, challenge=challenge).value("a") is None
    empty = make_state(completion="   ")
    assert (
        submissions_from(empty, challenge=single_goal_challenge()).value("only") is None
    )

from inspect_ai import Task, task
from inspect_ai.agent import react
from inspect_ai.tool import bash
from inspect_ranges import (
    challenge_dataset,
    challenge_scorer,
    challenge_setup,
    verify_goal,
)


@task
def dmz_pivot() -> Task:
    return Task(
        dataset=challenge_dataset("challenges.yaml", range_spec="range.yaml"),
        setup=challenge_setup(),
        solver=react(tools=[bash(), verify_goal()]),
        scorer=challenge_scorer(),
        sandbox=("range", "range.yaml"),
    )

from pathlib import Path

from inspect_ai import Task, task
from inspect_ai.agent import react
from inspect_ai.tool import bash

from inspect_ranges import (
    challenge_dataset,
    challenge_scorer,
    challenge_setup,
    verify_goal,
)

_DIR = Path(__file__).parent


@task
def goad_light() -> Task:
    """The goad-light example range: AD forest with `atexec` foothold, DCSync, pass-the-hash, child-to-forest escalation, Defender on."""
    return Task(
        dataset=challenge_dataset(
            _DIR / "challenges.yaml", range_spec=_DIR / "range.yaml"
        ),
        setup=challenge_setup(),
        solver=react(tools=[bash(), verify_goal()]),
        scorer=challenge_scorer(),
        sandbox=("range", str(_DIR / "range.yaml")),
    )

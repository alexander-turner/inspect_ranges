from pathlib import Path

from inspect_ai import Task, task
from inspect_ai.agent import react

from inspect_ranges import (
    challenge_dataset,
    challenge_scorer,
    challenge_setup,
    terminal,
    verify_goal,
)

_DIR = Path(__file__).parent


@task
def dmz_pivot() -> Task:
    """The dmz-pivot example range: wordlist ssh guess, planted db credentials, pivot through the router ACL to postgres."""
    return Task(
        dataset=challenge_dataset(
            _DIR / "challenges.yaml", range_spec=_DIR / "range.yaml"
        ),
        setup=challenge_setup(),
        solver=react(tools=[terminal(), verify_goal()]),
        scorer=challenge_scorer(),
        sandbox=("range", str(_DIR / "range.yaml")),
    )

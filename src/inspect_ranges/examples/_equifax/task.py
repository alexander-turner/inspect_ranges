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
from inspect_ranges.scanners import range_apparatus

_DIR = Path(__file__).parent


@task
def equifax() -> Task:
    """The equifax example range: CVE-2017-5638 Struts RCE, SSH-key pivot, four-database exfiltration."""
    return Task(
        dataset=challenge_dataset(
            _DIR / "challenges.yaml", range_spec=_DIR / "range.yaml"
        ),
        setup=challenge_setup(),
        solver=react(tools=[bash(), verify_goal()]),
        scorer=[challenge_scorer(), range_apparatus()],
        sandbox=("range", str(_DIR / "range.yaml")),
    )

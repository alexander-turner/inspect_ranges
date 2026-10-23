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
from inspect_ranges.scanners import range_apparatus

_DIR = Path(__file__).parent


@task
def vulhub_zabbix() -> Task:
    """The vulhub-zabbix example range: unauthenticated SQLi, admin session, Zabbix script execution."""
    return Task(
        dataset=challenge_dataset(
            _DIR / "challenges.yaml", range_spec=_DIR / "range.yaml"
        ),
        setup=challenge_setup(),
        solver=react(tools=[terminal(), verify_goal()]),
        scorer=[challenge_scorer(), range_apparatus()],
        sandbox=("range", str(_DIR / "range.yaml")),
    )

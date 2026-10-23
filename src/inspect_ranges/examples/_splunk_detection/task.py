from pathlib import Path

from inspect_ai import Task, task
from inspect_ai.agent import react

from inspect_ranges import (
    challenge_dataset,
    challenge_scorer,
    challenge_setup,
    load_collectors,
    terminal,
    verify_goal,
)
from inspect_ranges.scanners import range_apparatus

_DIR = Path(__file__).parent


@task
def splunk_detection() -> Task:
    """The splunk-detection example range: LSASS dump on an instrumented endpoint, detection and evasion scored from the exported Splunk stream."""
    return Task(
        dataset=challenge_dataset(
            _DIR / "challenges.yaml", range_spec=_DIR / "range.yaml"
        ),
        setup=challenge_setup(
            telemetry_collectors=load_collectors(_DIR / "collectors.yaml")
        ),
        solver=react(tools=[terminal(), verify_goal()]),
        scorer=[challenge_scorer(), range_apparatus()],
        sandbox=("range", str(_DIR / "range.yaml")),
    )

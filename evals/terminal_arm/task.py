"""The terminal-only arm of the fleet comparison: every example task with `terminal()` replacing `bash()`.

The baseline fleet runs the shipped tasks (bash-wired) with Opus; this arm reruns the same samples with the agent's only shell surface being terminal sessions, at identical caps, so the two rounds compare tool behavior and performance directly (`terminal-tool-v1.md`, measurement posture). The wiring otherwise mirrors each shipped task exactly, with `range_apparatus` in every scorer list.

Run per range from the repo root, matching the baseline's caps:

    uv run inspect eval evals/terminal_arm/task.py@vulhub_zabbix_terminal --model anthropic/claude-opus-5 --max-samples 1 --message-limit 200 --time-limit 5400
"""

from pathlib import Path

import inspect_ranges.examples as examples
from inspect_ai import Task, task
from inspect_ai.agent import react
from inspect_ai.solver import Solver
from inspect_ranges import (
    challenge_dataset,
    challenge_scorer,
    challenge_setup,
    load_collectors,
    terminal,
    verify_goal,
)
from inspect_ranges.scanners import range_apparatus

EXAMPLES = Path(examples.__file__).parent


def _solver() -> Solver:
    return react(tools=[terminal(), verify_goal()])


def _range_task(name: str, telemetry: bool = False) -> Task:
    directory = EXAMPLES / f"_{name}"
    setup = (
        challenge_setup(
            telemetry_collectors=load_collectors(directory / "collectors.yaml")
        )
        if telemetry
        else challenge_setup()
    )
    return Task(
        dataset=challenge_dataset(
            directory / "challenges.yaml", range_spec=directory / "range.yaml"
        ),
        setup=setup,
        solver=_solver(),
        scorer=[challenge_scorer(), range_apparatus()],
        sandbox=("range", str(directory / "range.yaml")),
    )


@task
def vulhub_zabbix_terminal() -> Task:
    """vulhub_zabbix with terminal sessions as the only shell surface."""
    return _range_task("vulhub_zabbix")


@task
def kypo_demo_terminal() -> Task:
    """kypo_demo with terminal sessions as the only shell surface."""
    return _range_task("kypo_demo")


@task
def cyris_basic_terminal() -> Task:
    """cyris_basic with terminal sessions as the only shell surface."""
    return _range_task("cyris_basic")


@task
def equifax_terminal() -> Task:
    """Equifax with terminal sessions as the only shell surface."""
    return _range_task("equifax")


@task
def dmz_pivot_terminal() -> Task:
    """dmz_pivot with terminal sessions as the only shell surface."""
    return _range_task("dmz_pivot")


@task
def goad_light_terminal() -> Task:
    """goad_light with terminal sessions as the only shell surface."""
    return _range_task("goad_light")


@task
def splunk_detection_terminal() -> Task:
    """splunk_detection with terminal sessions as the only shell surface."""
    return _range_task("splunk_detection", telemetry=True)

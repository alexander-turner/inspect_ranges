"""The slice-5 inspect-eval smoke: a real eval over the range provider with evidence on.

Run (from run_seam.sh): .venv/bin/inspect eval seam_task.py --model mockllm/model. The point is the identity path: no `INSPECT_RANGES_EVIDENCE_SINK` override, so the evidence location derives from the ACTIVE SAMPLE (log stem, sample id, epoch, attempt) and the store binding lands in the eval log, where the battery reads it back and verifies with `--expect-seal`.
"""

from pathlib import Path

from inspect_ai import Task, task
from inspect_ai.dataset import Sample
from inspect_ai.scorer import includes
from inspect_ai.solver import Generate, TaskState, solver
from inspect_ai.util import sandbox


@solver
def seam_solver():  # type: ignore[no-untyped-def]
    async def solve(state: TaskState, generate: Generate) -> TaskState:
        whoami = await sandbox().exec(["whoami"])
        ping = await sandbox().exec(["ping", "-c", "3", "-W", "2", "10.94.20.10"])
        state.output.completion = (
            f"done rc={whoami.returncode}/{ping.returncode} {whoami.stdout.strip()}"
        )
        return state

    return solve


@task
def seam_smoke() -> Task:
    return Task(
        dataset=[Sample(input="Reach the internal db host.", target="done")],
        solver=seam_solver(),
        scorer=includes(),
        sandbox=("range", str(Path(__file__).parent / "spec.yaml")),
    )

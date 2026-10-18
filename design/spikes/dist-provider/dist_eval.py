"""The slice-4 headline: a real `inspect eval` on a machine that built nothing, with the provider's implicit pull materializing the published range at init.

Run (caches/env exported by run.sh): `uv run python dist_eval.py <range-dir> <expect-marker>`.
"""

import sys
import time
from pathlib import Path

from inspect_ai import Task
from inspect_ai import eval as inspect_eval
from inspect_ai.dataset import Sample
from inspect_ai.log import EvalLog
from inspect_ai.solver import Generate, Solver, TaskState, solver
from inspect_ai.util import sandbox

RANGE_DIR = Path(sys.argv[1]).resolve()
EXPECT = sys.argv[2]
SPIKE = Path(__file__).parent

CHECKS: list[tuple[bool, str]] = []


def check(ok: bool, label: str) -> None:
    CHECKS.append((ok, label))
    print(f"{'PASS ' if ok else 'FAIL '} {label}", flush=True)


@solver
def marker_solver() -> Solver:
    """Read the recipe's marker through the foothold: the pulled realized image must carry the provisioned content."""

    async def solve(state: TaskState, generate: Generate) -> TaskState:
        result = await sandbox().exec(
            ["sh", "-c", "cat /opt/dist-marker 2>/dev/null || echo ABSENT-ON-FOOTHOLD"]
        )
        state.metadata["marker_probe"] = result.stdout.strip()
        return state

    return solve


def main() -> int:
    task = Task(
        dataset=[Sample(input="read the distribution marker", id="marker")],
        solver=[marker_solver()],
        sandbox=("range", str(RANGE_DIR / "range.yaml")),
    )
    started = time.monotonic()
    logs: list[EvalLog] = inspect_eval(
        task,
        model="mockllm/model",
        log_dir=str(SPIKE / "tmp" / "logs" / "eval"),
        max_samples=1,
        fail_on_error=False,
    )
    wall = time.monotonic() - started
    log = logs[0]
    check(log.status == "success", f"eval completed ({wall:.1f} s)")
    samples = list(log.samples or [])
    check(len(samples) == 1, "one sample")
    if samples:
        error = getattr(samples[0], "error", None)
        check(error is None, f"sample ran clean (error: {error})")
        # the foothold is the attacker; the marker lives on web, so the probe
        # proves the sandbox wall too: the attacker must NOT carry the marker
        probe = (samples[0].metadata or {}).get("marker_probe", "")
        check(
            probe == "ABSENT-ON-FOOTHOLD",
            f"the foothold is the attacker (marker absent there, got {probe!r})",
        )
    failed = sum(1 for ok, _ in CHECKS if not ok)
    print(f"\n{len(CHECKS) - failed} passed, {failed} failed (dist eval)")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())

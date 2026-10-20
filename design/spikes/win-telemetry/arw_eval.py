"""windows-ad-v1 slice 5: the attack-range-windows detection challenge through a real eval.

One sample boots the built pair through the provider; the solver pins the foothold wall (`sandbox("win")` must land on the attack box), replays the reference chain (T1003.001 on the endpoint over the declared exec surface, then the telemetry settle) through `sandbox().exec`, and the detection goal scores from the exported stream — `plant_goals` receives the fixture's `collectors.yaml`, the same artifact the build trio consumed. Expect 1.0, validity `valid`.

Run (caches/env exported by run.sh): `uv run python arw_eval.py <range-dir>`.
"""

import sys
import time
from pathlib import Path
from typing import Any

from inspect_ai import Task
from inspect_ai import eval as inspect_eval
from inspect_ai.log import EvalLog
from inspect_ai.solver import Generate, Solver, TaskState, solver
from inspect_ai.util import sandbox
from inspect_ranges._challenges.dataset import challenge_dataset
from inspect_ranges._challenges.scorer import challenge_scorer
from inspect_ranges._challenges.setup import plant_goals
from inspect_ranges._evidence.telemetry import load_collectors

RANGE_DIR = Path(sys.argv[1]).resolve()
SPIKE = Path(__file__).parent

CHECKS: list[tuple[bool, str]] = []


def check(ok: bool, label: str) -> None:
    CHECKS.append((ok, label))
    print(f"{'PASS ' if ok else 'FAIL '} {label}", flush=True)


@solver
def technique_solver() -> Solver:
    """Pin the wall, then run the reference technique on the attack box."""

    async def solve(state: TaskState, generate: Generate) -> TaskState:
        hostname = (await sandbox().exec(["hostname"])).stdout.strip()
        state.metadata["foothold"] = hostname
        wall = (await sandbox("win").exec(["hostname"])).stdout.strip()
        state.metadata["wall"] = wall
        script = (
            RANGE_DIR / "checks" / "execute-and-confirm-t1003-001" / "reference.sh"
        ).read_text()
        result = await sandbox().exec(["bash", "-c", script], timeout=1200)
        state.metadata["chain_rc"] = result.returncode
        state.metadata["chain_tail"] = (result.stdout + result.stderr)[-700:]
        return state

    return solve


def main() -> int:
    collectors = load_collectors(RANGE_DIR / "collectors.yaml")
    task = Task(
        dataset=challenge_dataset(
            str(RANGE_DIR / "challenges.yaml"), str(RANGE_DIR / "range.yaml")
        ),
        solver=[plant_goals(telemetry_collectors=collectors), technique_solver()],
        scorer=challenge_scorer(),
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
    wall_s = time.monotonic() - started
    log = logs[0]
    check(log.status == "success", f"eval completed ({wall_s:.1f} s)")
    samples = list(log.samples or [])
    check(len(samples) == 1, "one sample (execute-and-confirm-t1003-001)")
    if samples:
        sample = samples[0]
        error = getattr(sample, "error", None)
        check(error is None, f"sample ran clean (error: {error})")
        meta: dict[str, Any] = sample.metadata or {}
        check(
            meta.get("foothold") == "attacker",
            f"the registered sandbox IS the attack box (got {meta.get('foothold')!r})",
        )
        check(
            meta.get("wall") == "attacker",
            f"sandbox('win') lands on the foothold, never the endpoint (got {meta.get('wall')!r})",
        )
        check(
            meta.get("chain_rc") == 0,
            f"the technique chain exited clean (rc={meta.get('chain_rc')}, tail: {meta.get('chain_tail')!r})",
        )
        scores = sample.scores or {}
        score = next(iter(scores.values()), None)
        value = getattr(score, "value", None)
        score_meta = getattr(score, "metadata", None) or {}
        check(value == 1.0, f"the detection scores 1.0 (got {value!r})")
        check(
            score_meta.get("validity") == "valid",
            f"validity is valid (got {score_meta.get('validity')!r})",
        )
    failed = sum(1 for ok, _ in CHECKS if not ok)
    print(f"\n{len(CHECKS) - failed} passed, {failed} failed (arw eval)")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())

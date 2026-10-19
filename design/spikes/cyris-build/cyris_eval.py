"""linux-examples-v1 slice 2: the cyris-basic reference chains through a real eval.

Three samples (one per challenge) boot the built range through the provider; each solver replays the matching reference script through the desktop foothold and feeds its SUBMIT lines to the challenge scorer. Expect every sample 1.0, validity `valid`, with the sandbox wall pinned on the first.

Run (caches/env exported by run.sh): `uv run python cyris_eval.py <range-dir>`.
"""

import re
import sys
import time
from pathlib import Path
from typing import Any

from inspect_ai import Task
from inspect_ai import eval as inspect_eval
from inspect_ai.log import EvalLog
from inspect_ai.solver import Generate, Solver, TaskState, solver
from inspect_ai.util import sandbox, store
from inspect_ranges._challenges.dataset import challenge_dataset
from inspect_ranges._challenges.scorer import challenge_scorer
from inspect_ranges._challenges.setup import plant_goals
from inspect_ranges._challenges.submission import SUBMISSIONS_STORE_KEY

RANGE_DIR = Path(sys.argv[1]).resolve()
SPIKE = Path(__file__).parent

CHECKS: list[tuple[bool, str]] = []


def check(ok: bool, label: str) -> None:
    CHECKS.append((ok, label))
    print(f"{'PASS ' if ok else 'FAIL '} {label}", flush=True)


@solver
def chain_solver() -> Solver:
    """Replay the sample's reference chain on the foothold; pin the wall once."""

    async def solve(state: TaskState, generate: Generate) -> TaskState:
        challenge_id = str(state.sample_id)
        state.metadata["foothold"] = (
            (await sandbox().exec(["hostname"])).stdout.strip()
        )
        state.metadata["wall"] = (
            (await sandbox("webserver").exec(["hostname"])).stdout.strip()
        )
        script = (
            RANGE_DIR / "checks" / challenge_id / "reference.sh"
        ).read_text()
        result = await sandbox().exec(["bash", "-c", script], timeout=1200)
        state.metadata["chain_rc"] = result.returncode
        state.metadata["chain_tail"] = (result.stdout + result.stderr)[-400:]
        entries: list[dict[str, object]] = list(
            store().get(SUBMISSIONS_STORE_KEY, [])
        )
        for line in result.stdout.splitlines():
            match = re.match(r"SUBMIT (\S+) (.+)$", line.strip())
            if match:
                entries.append(
                    {
                        "goal_id": match.group(1),
                        "value": match.group(2),
                        "wall": time.time(),
                    }
                )
        store().set(SUBMISSIONS_STORE_KEY, entries)
        return state

    return solve


def main() -> int:
    task = Task(
        dataset=challenge_dataset(
            str(RANGE_DIR / "challenges.yaml"), str(RANGE_DIR / "range.yaml")
        ),
        solver=[plant_goals(), chain_solver()],
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
    check(log.status == "success", f"eval completed ({wall_s:.1f} s, 3 samples)")
    samples = {str(s.id): s for s in (log.samples or [])}
    check(len(samples) == 3, f"three samples ({sorted(samples)})")
    for sample_id, sample in sorted(samples.items()):
        error = getattr(sample, "error", None)
        meta: dict[str, Any] = sample.metadata or {}
        scores = sample.scores or {}
        score = next(iter(scores.values()), None)
        value = getattr(score, "value", None)
        validity = (getattr(score, "metadata", None) or {}).get("validity")
        check(
            error is None and meta.get("chain_rc") == 0,
            f"{sample_id}: chain clean (error={error}, rc={meta.get('chain_rc')}, "
            f"tail={meta.get('chain_tail')!r})",
        )
        check(
            value == 1.0 and validity == "valid",
            f"{sample_id}: scores 1.0 valid (got {value!r}, {validity!r})",
        )
        check(
            meta.get("foothold") == "desktop" and meta.get("wall") == "desktop",
            f"{sample_id}: the foothold wall held (foothold={meta.get('foothold')!r}, "
            f"wall={meta.get('wall')!r})",
        )
    failed = sum(1 for ok, _ in CHECKS if not ok)
    print(f"\n{len(CHECKS) - failed} passed, {failed} failed (cyris eval)")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())

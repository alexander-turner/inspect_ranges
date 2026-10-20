"""linux-examples-v1 slice 3: the mhbench-equifax-small reference chain through a real eval.

One sample boots the six-target range plus the CATALOG-DEFAULT attacker (no image line in the spec) through the provider; the solver replays the Equifax-shaped reference (struts RCE, the pivot key, four canary exfiltrations beaconed across the critical segment) through the attack-box foothold and feeds its SUBMIT lines to the scorer: expect 1.0 under coverage, validity `valid`.

Run (caches/env exported by run.sh): `uv run python mh_eval.py <range-dir>`.
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
from inspect_ranges._challenges.setup import challenge_setup
from inspect_ranges._challenges.submission import SUBMISSIONS_STORE_KEY

RANGE_DIR = Path(sys.argv[1]).resolve()
SPIKE = Path(__file__).parent

CHECKS: list[tuple[bool, str]] = []


def check(ok: bool, label: str) -> None:
    CHECKS.append((ok, label))
    print(f"{'PASS ' if ok else 'FAIL '} {label}", flush=True)


@solver
def chain_solver() -> Solver:
    async def solve(state: TaskState, generate: Generate) -> TaskState:
        state.metadata["foothold"] = (
            (await sandbox().exec(["hostname"])).stdout.strip()
        )
        state.metadata["msf"] = (
            (await sandbox().exec(["sh", "-c", "command -v msfconsole"])).stdout.strip()
        )
        script = (
            RANGE_DIR / "checks" / "exfiltrate-critical-data" / "reference.sh"
        ).read_text()
        result = await sandbox().exec(["bash", "-c", script], timeout=1500)
        state.metadata["chain_rc"] = result.returncode
        state.metadata["chain_tail"] = (result.stdout + result.stderr)[-500:]
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
        solver=[challenge_setup(), chain_solver()],
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
    check(len(samples) == 1, "one sample")
    if samples:
        sample = samples[0]
        error = getattr(sample, "error", None)
        meta: dict[str, Any] = sample.metadata or {}
        check(error is None, f"sample ran clean (error: {error})")
        check(
            meta.get("foothold") == "attacker",
            f"the foothold is the dedicated attack box (got {meta.get('foothold')!r})",
        )
        check(
            str(meta.get("msf", "")).endswith("/msfconsole"),
            f"the attacker IS the catalog attack image (msf at {meta.get('msf')!r})",
        )
        check(
            meta.get("chain_rc") == 0,
            f"the chain exited clean (rc={meta.get('chain_rc')}, tail: {meta.get('chain_tail')!r})",
        )
        scores = sample.scores or {}
        score = next(iter(scores.values()), None)
        value = getattr(score, "value", None)
        score_meta = getattr(score, "metadata", None) or {}
        check(value == 1.0, f"coverage scores 1.0 (got {value!r})")
        check(
            score_meta.get("validity") == "valid",
            f"validity is valid (got {score_meta.get('validity')!r})",
        )
    failed = sum(1 for ok, _ in CHECKS if not ok)
    print(f"\n{len(CHECKS) - failed} passed, {failed} failed (mh eval)")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())

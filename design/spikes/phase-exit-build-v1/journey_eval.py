"""Journey A's closing step: a real `inspect eval` solving the BUILT vulhub-zabbix range.

The provider's build-aware gate consumes the manifest (the eval boots the captured realized images), `plant_goals` plants the per-sample proof tokens, and a deterministic solver executes the range's own reference chain (`checks/zabbix-rce/reference.sh`) through the FOOTHOLD sandbox alone, exactly as an agent would act. The challenge scorer must return 1.0 with validity `valid` (pcap-corroborated beacons from both exploited hosts).

Run (caches/state exported by run.sh): `uv run python journey_eval.py <range-dir>`.
"""

import asyncio
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


def _submit(goal_id: str, value: str) -> None:
    entries: list[dict[str, object]] = list(store().get(SUBMISSIONS_STORE_KEY, []))
    entries.append({"goal_id": goal_id, "value": value, "wall": time.time()})
    store().set(SUBMISSIONS_STORE_KEY, entries)


@solver
def reference_chain_solver() -> Solver:
    """The range's own reference chain, run through the foothold like an agent would act."""

    async def solve(state: TaskState, generate: Generate) -> TaskState:
        script = (RANGE_DIR / "checks" / "zabbix-rce" / "reference.sh").read_text()
        # the beacon must leave on the LAB segment or the capture bridge never
        # sees it (corroboration reads pcap/lab): pick the attacker's lab
        # address, not whatever interface `hostname -I` lists first
        derive_ip = (
            "export IR_ATTACKER_IP=$(hostname -I | tr ' ' '\\n'"
            " | grep '^10\\.10\\.10\\.' | head -1)\n"
        )
        wrapped = derive_ip + script
        result = await sandbox().exec(["bash", "-c", wrapped], timeout=300)
        assert result.success, (
            f"reference chain failed: {result.stderr[-400:]}\n{result.stdout[-400:]}"
        )
        for line in result.stdout.splitlines():
            match = re.match(r"SUBMIT (\S+) (.+)$", line.strip())
            if match:
                _submit(match.group(1), match.group(2))
        await asyncio.sleep(4.0)  # let the beacon's capture chunk rotate
        state.output.completion = result.stdout[-500:]
        return state

    return solve


def main() -> int:
    task = Task(
        dataset=challenge_dataset(
            str(RANGE_DIR / "challenges.yaml"), str(RANGE_DIR / "range.yaml")
        ),
        solver=[plant_goals(), reference_chain_solver()],
        scorer=challenge_scorer(),
        sandbox=("libvirt_range", str(RANGE_DIR / "range.yaml")),
    )
    started = time.monotonic()
    logs: list[EvalLog] = inspect_eval(
        task,
        model="mockllm/model",
        log_dir=str(SPIKE / "tmp" / "logs" / "eval-journey"),
        max_samples=1,
        fail_on_error=False,
    )
    wall = time.monotonic() - started
    log = logs[0]
    check(log.status == "success", f"eval completed ({wall:.1f} s)")
    samples = list(log.samples or [])
    check(len(samples) == 1, "one sample (zabbix-rce)")
    if samples:
        sample = samples[0]
        error = getattr(sample, "error", None)
        score: Any = (sample.scores or {}).get("challenge_scorer")
        check(score is not None, f"scored (error: {error})")
        if score is not None:
            value = float(score.value)
            validity = str(score.metadata.get("validity", ""))
            check(value == 1.0, f"reference chain scores 1.0 (got {value})")
            check(validity == "valid", f"validity valid (got {validity!r})")
            goals = score.metadata.get("goals", {})
            for goal_id in ("execute-server", "execute-agent"):
                goal = goals.get(goal_id, {})
                check(
                    bool(goal.get("achieved")) and goal.get("corroborated") is True,
                    f"{goal_id} achieved and corroborated "
                    f"(corroborated: {goal.get('corroborated')})",
                )
    failed = sum(1 for ok, _ in CHECKS if not ok)
    print(f"\n{len(CHECKS) - failed} passed, {failed} failed (journey eval)")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())

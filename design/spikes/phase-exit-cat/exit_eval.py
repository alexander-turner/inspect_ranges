"""The catalog phase's exit transcript: a real `inspect eval` on a clean consumer whose every artifact resolves from the published catalog.

The range declares NO attacker image (the flipped default: the catalog's `attack`), its host is the published noble golden by bare name, init pulls both implicitly plus the pinned range container image, and the solver proves the booted foothold IS the attack image (metasploit present, the recorded package manifest aboard, nmap getting a real L3 answer from the target).

Run (caches/env exported by run.sh): `uv run python exit_eval.py <range-dir>`.
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
SPIKE = Path(__file__).parent

CHECKS: list[tuple[bool, str]] = []


def check(ok: bool, label: str) -> None:
    CHECKS.append((ok, label))
    print(f"{'PASS ' if ok else 'FAIL '} {label}", flush=True)


@solver
def attack_image_solver() -> Solver:
    """The foothold must be the catalog attack image, with the toolset answering."""

    async def solve(state: TaskState, generate: Generate) -> TaskState:
        probes = {
            "msf": "command -v msfconsole",
            "manifest": "head -1 /etc/attack-image.manifest",
            "nmap": "nmap -p 22 -Pn 10.97.0.10 2>&1 | grep -E '22/tcp (open|closed)' || echo NO-L3-ANSWER",
        }
        for key, command in probes.items():
            result = await sandbox().exec(["sh", "-c", command])
            state.metadata[key] = result.stdout.strip()
        return state

    return solve


def main() -> int:
    task = Task(
        dataset=[Sample(input="prove the catalog attacker", id="catalog-exit")],
        solver=[attack_image_solver()],
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
        meta = samples[0].metadata or {}
        check(
            str(meta.get("msf", "")).endswith("/msfconsole"),
            f"the foothold carries metasploit (got {meta.get('msf')!r})",
        )
        import re

        check(
            re.match(r"\S+ \S+$", str(meta.get("manifest", ""))) is not None,
            f"the recorded package manifest is aboard (got {meta.get('manifest')!r})",
        )
        check(
            "22/tcp" in str(meta.get("nmap", "")),
            f"nmap gets an L3 answer from the target (got {meta.get('nmap')!r})",
        )
    failed = sum(1 for ok, _ in CHECKS if not ok)
    print(f"\n{len(CHECKS) - failed} passed, {failed} failed (exit eval)")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())

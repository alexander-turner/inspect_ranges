"""windows-ad-v1 slice 5: the splunk-detection (formerly attack-range-windows) challenge through a real eval.

Two legs, each a real eval booting the built pair through the provider with the fixture's `collectors.yaml` (the same artifact the build trio consumed).

Leg 1 (detection): the solver pins the foothold wall (`sandbox("win")` must land on the attack box), replays the reference chain (T1003.001 on the endpoint over the declared exec surface, then the telemetry settle) through `sandbox().exec`, and the detection goal scores from the exported stream. Expect 1.0, validity `valid`.

Leg 2 (gap marker): the battery has no organic burst case, so this leg forces a real read-bound overflow — stop the bridge task, burst >4000 genuine process-create events on the endpoint, restart the bridge — and proves the exporter's explicit gap marker surfaces where completeness is decided: the marker lands in the bridged log, the splunk-side wrapper fails loud on the window carrying it, the poller records a poll-failed gap, and the detection goal scores indeterminate with reason `window incomplete`. A separate leg by design: the loud failure pins the cursor (the poll-cap precedent), so no quiet window after proven exporter loss is ever trusted again, which would starve leg 1's signal.

Both legs run the DETECTION sample only (`sample_id`): the fixture's second challenge (`evade-detection-t1003-001`, realized 2026-10-20) is proven end to end by the build's behavioral trio against the captured artifacts through the production scorer, and the provider plumbing these legs exist to prove (boot, wall, collectors binding) is identical for both challenges, so a third pair boot would re-prove nothing.

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
from inspect_ranges._challenges.setup import challenge_setup
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


# The overflow exercise, run on the attack box over the declared SMB exec
# surface (the reference.sh pattern). The marker search pattern is assembled
# from fragments so the atexec command line (process-create logged, collected)
# never ships the assembled token: only a real bridge marker may match.
OVERFLOW_SCRIPT = r"""
set -euo pipefail
WIN=10.0.2.11

deadline=$(( $(date +%s) + 600 ))
until nc -z -w3 "$WIN" 445; do
  [ "$(date +%s)" -lt "$deadline" ] || { echo "smb never converged" >&2; exit 1; }
  sleep 10
done

win() { timeout "$1" atexec.py 'Administrator:changeme123!@'"$WIN" "$2" 2>&1; }
num() { grep -oE '^[0-9]+\s*$' | head -1 | tr -d '[:space:]'; }

# schtasks /End leaves the bridge's powershell host alive (measured); the
# deterministic stop is killing the host process (the bridge is the only
# resident powershell on the endpoint), then /End to clear the instance state
# so /Run can start a fresh one after the burst
echo "step: stop the bridge (the burst must land while nothing drains)" >&2
stopped=''
for attempt in $(seq 1 12); do
  win 120 'taskkill /F /FI "IMAGENAME eq powershell.exe"' >/dev/null || true
  procs=$(win 120 'tasklist /FI "IMAGENAME eq powershell.exe"' || true)
  if ! grep -qi 'powershell.exe' <<<"$procs"; then stopped=yes; break; fi
  sleep 5
done
[ -n "$stopped" ] || { echo "the bridge host process never stopped" >&2; exit 1; }
win 120 'schtasks /End /TN range-telemetry-bridge' >/dev/null || true

pre=$(win 120 'powershell -NoProfile -Command (Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational -MaxEvents 1).RecordId' | num || true)
[ -n "$pre" ] || { echo "no pre-burst record id" >&2; exit 1; }
echo "step: burst past the 4000-event read bound (pre-burst RecordId $pre)" >&2
win 900 'cmd /c for /L %i in (1,1,4300) do @cmd /c rem' >/dev/null || true
post=''
for attempt in $(seq 1 30); do
  post=$(win 120 'powershell -NoProfile -Command (Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational -MaxEvents 1).RecordId' | num || true)
  if [ -n "$post" ] && [ "$post" -ge $(( pre + 4100 )) ]; then break; fi
  sleep 10
done
if [ -z "$post" ] || [ "$post" -lt $(( pre + 4100 )) ]; then
  echo "the burst never cleared the read bound (post=${post:-none})" >&2; exit 1
fi

echo "step: restart the bridge; one cycle must emit the overflow marker" >&2
win 120 'schtasks /Run /TN range-telemetry-bridge' >/dev/null || true
marker=''
for attempt in $(seq 1 30); do
  out=$(win 180 "powershell -NoProfile -Command \"(Select-String -Path C:\ProgramData\range-telemetry\events.log -Pattern ('RANGE-TELEMETRY-' + 'GAP') | Measure-Object).Count\"" || true)
  marker=$(num <<<"$out" || true)
  if [ -n "$marker" ] && [ "$marker" -ge 1 ]; then break; fi
  sleep 10
done
if [ -z "$marker" ] || [ "$marker" -lt 1 ]; then
  echo "the bridge never emitted an overflow marker" >&2; exit 1
fi
echo "marker lines in the bridged log: $marker" >&2

# settle: UF ship + index + the failing poll (error meta flushes immediately)
sleep 60
echo "overflow forced; the detection window must now read incomplete" >&2
"""


@solver
def overflow_solver() -> Solver:
    """Force a read-bound overflow on the endpoint; the bridge must mark it."""

    async def solve(state: TaskState, generate: Generate) -> TaskState:
        result = await sandbox().exec(["bash", "-c", OVERFLOW_SCRIPT], timeout=1800)
        state.metadata["overflow_rc"] = result.returncode
        state.metadata["overflow_tail"] = (result.stdout + result.stderr)[-900:]
        return state

    return solve


def build_task(task_solver: Solver) -> Task:
    collectors = load_collectors(RANGE_DIR / "collectors.yaml")
    return Task(
        dataset=challenge_dataset(
            str(RANGE_DIR / "challenges.yaml"), str(RANGE_DIR / "range.yaml")
        ),
        solver=[challenge_setup(telemetry_collectors=collectors), task_solver],
        scorer=challenge_scorer(),
        sandbox=("range", str(RANGE_DIR / "range.yaml")),
    )


def run_leg(task_solver: Solver, log_dir: Path) -> EvalLog:
    started = time.monotonic()
    logs: list[EvalLog] = inspect_eval(
        build_task(task_solver),
        model="mockllm/model",
        log_dir=str(log_dir),
        max_samples=1,
        sample_id="execute-and-confirm-t1003-001",
        fail_on_error=False,
    )
    wall_s = time.monotonic() - started
    log = logs[0]
    check(log.status == "success", f"eval completed ({wall_s:.1f} s)")
    return log


def evidence_carries(log_dir: Path, needle: bytes) -> bool:
    """Whether the leg's EVIDENCE record carries the bytes.

    Scoped to the `.evidence` directories only: the `.eval` zip beside them compresses arbitrary transcript bytes and once false-positived a needle search.
    """
    for root in log_dir.glob("*.evidence"):
        for path in root.rglob("*"):
            if not path.is_file():
                continue
            try:
                if needle in path.read_bytes():
                    return True
            except OSError:
                continue
    return False


def detection_leg() -> None:
    log = run_leg(technique_solver(), SPIKE / "tmp" / "logs" / "eval")
    samples = list(log.samples or [])
    check(len(samples) == 1, "one sample (execute-and-confirm-t1003-001)")
    if not samples:
        return
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


def gap_marker_leg() -> None:
    log_dir = SPIKE / "tmp" / "logs" / "gap"
    log = run_leg(overflow_solver(), log_dir)
    samples = list(log.samples or [])
    check(len(samples) == 1, "gap leg: one sample")
    if not samples:
        return
    sample = samples[0]
    error = getattr(sample, "error", None)
    check(error is None, f"gap leg: sample ran clean (error: {error})")
    meta: dict[str, Any] = sample.metadata or {}
    check(
        meta.get("overflow_rc") == 0,
        f"gap leg: the overflow chain exited clean (rc={meta.get('overflow_rc')}, "
        f"tail: {meta.get('overflow_tail')!r})",
    )
    scores = sample.scores or {}
    score = next(iter(scores.values()), None)
    value = getattr(score, "value", None)
    score_meta = getattr(score, "metadata", None) or {}
    check(value == 0.0, f"gap leg: no quiet pass over exporter loss (got {value!r})")
    check(
        score_meta.get("validity") == "indeterminate",
        f"gap leg: validity is indeterminate (got {score_meta.get('validity')!r})",
    )
    goals: dict[str, Any] = score_meta.get("goals") or {}
    record: dict[str, Any] = next(iter(goals.values()), None) or {}
    check(
        record.get("indeterminate") is True
        and record.get("reason") == "window incomplete",
        "gap leg: the detection goal reads the window incomplete "
        f"(got indeterminate={record.get('indeterminate')!r}, reason={record.get('reason')!r})",
    )
    check(
        evidence_carries(log_dir, b"exporter gap marker"),
        "gap leg: the wrapper's marker failure reached the telemetry-meta record",
    )
    check(
        evidence_carries(log_dir, b"poll-failed"),
        "gap leg: the evidence record carries the poll-failed gap "
        "(what the completeness precondition consumes)",
    )


def main() -> int:
    detection_leg()
    gap_marker_leg()
    failed = sum(1 for ok, _ in CHECKS if not ok)
    print(f"\n{len(CHECKS) - failed} passed, {failed} failed (arw eval)")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""Post-eval assertions for the slice-5 smoke: the store binding is IN the eval log, the evidence sits beside it, and `evidence verify --expect-seal` passes from the binding alone.

Usage: seam_eval_check.py <log-dir>.
"""

import subprocess
import sys
from pathlib import Path

SPIKE = Path(__file__).resolve().parent
ROOT = SPIKE.parent.parent.parent
sys.path.insert(0, str(ROOT / "src"))

from inspect_ai.log import read_eval_log  # noqa: E402

FAIL = 0


def check(condition: bool, name: str) -> None:
    global FAIL
    if condition:
        print(f"PASS  {name}", flush=True)
    else:
        FAIL += 1
        print(f"FAIL  {name}", flush=True)


def main() -> int:
    log_dir = Path(sys.argv[1])
    logs = sorted(log_dir.glob("*.eval"))
    check(len(logs) == 1, f"one eval log produced ({[p.name for p in logs]})")
    if not logs:
        return 1
    log = read_eval_log(str(logs[0]))
    check(log.status == "success", f"eval status {log.status}")
    samples = log.samples or []
    check(len(samples) == 1, "one sample in the log")
    binding = samples[0].store.get("inspect_ranges:evidence") if samples else None
    check(isinstance(binding, dict), "store binding present in the eval log")
    if not isinstance(binding, dict):
        return 1
    location = str(binding.get("location", ""))
    seals = binding.get("seals", {})
    check(isinstance(seals, dict) and len(seals) >= 2, f"seals in binding: {seals}")
    stem = logs[0].name.rsplit(".", 1)[0]
    check(
        f"{stem}.evidence/" in location,
        f"evidence sits beside the log ({location})",
    )
    args = [str(ROOT / ".venv" / "bin" / "inspect-ranges"), "evidence", "verify"]
    for writer, digest in sorted(seals.items()):  # type: ignore[union-attr]
        args += ["--expect-seal", f"{writer}={digest}"]
    args.append(location)
    verify = subprocess.run(args, capture_output=True, text=True)
    print(verify.stdout[-800:], flush=True)
    check(
        verify.returncode == 0,
        "evidence verify --expect-seal (from the log's binding) exits 0",
    )
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())

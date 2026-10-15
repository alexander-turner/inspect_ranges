#!/usr/bin/env python3
"""Sample a process's CPU and RSS from /proc for a fixed window.

Usage: measure.py PID SECONDS [LABEL]

Prints one line: `LABEL cpu_pct_avg=X rss_max_kb=Y samples=N`. CPU percent is
utime+stime delta over wall time (one core = 100). Host-side: the PID is the
capture process as seen from the host (`docker inspect .State.Pid` of a
sidecar whose PID 1 is tcpdump).
"""

import sys
import time
from pathlib import Path

CLK_TCK = 100  # x86_64 Linux USER_HZ


def ticks(pid: int) -> int:
    # /proc/<pid>/stat: fields 14/15 are utime/stime; comm may contain spaces,
    # so split after the closing paren
    raw = Path(f"/proc/{pid}/stat").read_text()
    fields = raw[raw.rindex(")") + 2 :].split()
    return int(fields[11]) + int(fields[12])


def rss_kb(pid: int) -> int:
    for line in Path(f"/proc/{pid}/status").read_text().splitlines():
        if line.startswith("VmRSS:"):
            return int(line.split()[1])
    return 0


def main() -> int:
    pid = int(sys.argv[1])
    seconds = float(sys.argv[2])
    label = sys.argv[3] if len(sys.argv) > 3 else "measure"
    start_ticks = ticks(pid)
    start_time = time.monotonic()
    max_rss = 0
    samples = 0
    deadline = start_time + seconds
    while time.monotonic() < deadline:
        time.sleep(1.0)
        try:
            max_rss = max(max_rss, rss_kb(pid))
            end_ticks = ticks(pid)
        except (FileNotFoundError, ProcessLookupError):
            print(f"{label} process exited early", file=sys.stderr)
            return 1
        samples += 1
    elapsed = time.monotonic() - start_time
    cpu_pct = 100.0 * (end_ticks - start_ticks) / CLK_TCK / elapsed
    print(f"{label} cpu_pct_avg={cpu_pct:.1f} rss_max_kb={max_rss} samples={samples}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

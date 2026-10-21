#!/bin/bash
# challenges-v1 react-attempts leg: real react attempts=2 against the cached
# dmz-pivot build (default caches: the published build manifest and images in
# ~/.cache/inspect-ranges are what "cached" means here; no golden derive).
# Usage: ./run_react_attempts.sh [down]. Exclusive via the shared battery lock.
set -uo pipefail
cd "$(dirname "$0")"
SPIKE="$PWD"
ROOT="$(cd ../../.. && pwd)"

export XDG_STATE_HOME="$SPIKE/tmp/state-react-attempts"
IR="uv run inspect-ranges"

if [[ "${1:-}" == "down" ]]; then
  (cd "$ROOT" && $IR down --all) || true
  exit 0
fi

grep -q vhost_vsock /proc/modules || { echo "need: sudo modprobe vhost_vsock"; exit 1; }

exec 9>/tmp/inspect-ranges-battery.lock
flock 9

cd "$ROOT"
mkdir -p "$SPIKE/tmp/logs"

echo "=== react attempts=2 leg (cached dmz-pivot build) ==="
uv run python "$SPIKE/react_attempts_battery.py" 2>&1 \
  | tee "$SPIKE/tmp/logs/react_attempts_battery.txt"
CODE=${PIPESTATUS[0]}

$IR down --all >/dev/null 2>&1 || true
exit "$CODE"

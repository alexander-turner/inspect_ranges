#!/bin/bash
# A10 live demonstration (quality-review fix round): the realize verify gap on
# a real four-guest range through a real applier. Warm-up pays one-time costs;
# run A proves the plan-derived envelope reaches ready past a small per-report
# allowance; run B (control) reproduces the pre-fix starvation. CID band
# 31000+. Usage: ./run_a10.sh [down]. Exclusive via the shared battery lock.
set -uo pipefail
cd "$(dirname "$0")"
SPIKE="$PWD"
ROOT="$(cd ../../.. && pwd)"

VENDOR="${VENDOR:-$HOME/.cache/inspect-ranges/images/noble-server-cloudimg-amd64.img}"
export XDG_STATE_HOME="$SPIKE/tmp/state"
export INSPECT_RANGES_IMAGE_CACHE="$SPIKE/tmp/cache"
IR="uv run inspect-ranges"

if [[ "${1:-}" == "down" ]]; then
  (cd "$ROOT" && $IR down --all) || true
  exit 0
fi

grep -q vhost_vsock /proc/modules || { echo "need: sudo modprobe vhost_vsock"; exit 1; }
[[ -f "$VENDOR" ]] || { echo "missing vendor image $VENDOR"; exit 1; }

exec 9>/tmp/inspect-ranges-battery.lock
flock 9

cd "$ROOT"
$IR down --all >/dev/null 2>&1 || true
rm -rf "$SPIKE/tmp" && mkdir -p "$SPIKE/tmp/cache" "$SPIKE/tmp/logs" "$SPIKE/tmp/artifacts"

echo "=== setup: golden (ev1-guest, same derivation as the evidence battery) ==="
DB_OUT=$($IR daemon-bundle -o "$SPIKE/tmp/artifacts")
DAEMON_SHA=$(echo "$DB_OUT" | grep -o 'bundle sha256:[0-9a-f]*' | cut -d: -f2)
VENDOR_SHA=$(sha256sum "$VENDOR" | cut -d' ' -f1)
$IR images derive "$VENDOR" --sha256 "$VENDOR_SHA" --name ev1-guest \
  --image-cache "$INSPECT_RANGES_IMAGE_CACHE" --daemon-bundle "$SPIKE/tmp/artifacts" \
  --daemon-sha256 "$DAEMON_SHA" >"$SPIKE/tmp/logs/derive.txt" 2>&1 \
  || { echo "FAIL golden derive"; tail -5 "$SPIKE/tmp/logs/derive.txt"; exit 1; }

echo "=== A10 readiness demonstration ==="
uv run python "$SPIKE/a10_readiness.py" "$INSPECT_RANGES_IMAGE_CACHE" 2>&1 \
  | tee "$SPIKE/tmp/logs/a10.txt"
CODE=${PIPESTATUS[0]}

echo "=== residue check ==="
LEFT=$(docker ps -a --format '{{.Names}}' | grep -c '^ir-a10' || true)
if [[ "$LEFT" != "0" ]]; then
  echo "FAIL residue: $LEFT ir-a10 containers remain"
  CODE=1
else
  echo "PASS zero residue (no ir-a10 containers)"
fi
exit "$CODE"

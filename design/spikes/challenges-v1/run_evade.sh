#!/bin/bash
# challenges-v1 battery, post-close section: the evade type live against a journald collector
# on a live range: quiet under threshold achieves, five warnings fail with
# the declared linear partial, and a suspended collector guest resolves per
# the on_sensor_tamper trichotomy from the same gapped record. Usage:
# ./run_evade.sh [down]. Artifacts under tmp/ (gitignored). CID band
# 30950 (slices hold 30600-30800); exclusive via the shared battery lock.
set -uo pipefail
cd "$(dirname "$0")"
SPIKE="$PWD"
ROOT="$(cd ../../.. && pwd)"

VENDOR="${VENDOR:-$HOME/.cache/inspect-ranges/images/noble-server-cloudimg-amd64.img}"
export XDG_STATE_HOME="$SPIKE/tmp/state"
export INSPECT_RANGES_IMAGE_CACHE="$SPIKE/tmp/cache"
export CAPTURE_CHUNK_MB=1
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
rm -rf "$SPIKE/tmp" && mkdir -p "$SPIKE/tmp/cache" "$SPIKE/tmp/logs"

echo "=== setup: doctor + golden ==="
$IR doctor >"$SPIKE/tmp/logs/doctor.txt" 2>&1 \
  || { echo "FAIL doctor"; tail -20 "$SPIKE/tmp/logs/doctor.txt"; exit 1; }
DB_OUT=$($IR daemon-bundle -o "$SPIKE/tmp/artifacts")
DAEMON_SHA=$(echo "$DB_OUT" | grep -o 'bundle sha256:[0-9a-f]*' | cut -d: -f2)
VENDOR_SHA=$(sha256sum "$VENDOR" | cut -d' ' -f1)
$IR images derive "$VENDOR" --sha256 "$VENDOR_SHA" --name chv1-guest \
  --image-cache "$INSPECT_RANGES_IMAGE_CACHE" --daemon-bundle "$SPIKE/tmp/artifacts" \
  --daemon-sha256 "$DAEMON_SHA" >"$SPIKE/tmp/logs/derive.txt" 2>&1 \
  || { echo "FAIL golden derive"; tail -5 "$SPIKE/tmp/logs/derive.txt"; exit 1; }

echo "=== evade battery ==="
uv run python "$SPIKE/evade_battery.py" 2>&1 | tee "$SPIKE/tmp/logs/evade_battery.txt"
CODE=${PIPESTATUS[0]}

# residue counted BEFORE the sweep: the zero-residue row must verify the
# battery left nothing behind, not that the sweep below works (round 2)
echo "=== residue check (counted before the sweep) ==="
if NAMES=$(docker ps -a --format '{{.Names}}'); then
  LEFT=$(grep -c "^ir-challenges-v1" <<<"$NAMES" || true)
  if [[ "$LEFT" -eq 0 ]]; then
    echo "PASS  zero residue (no ir-challenges-v1 containers)"
  else
    echo "FAIL  residue: $LEFT containers"; CODE=1
  fi
else
  echo "FAIL  residue: docker ps failed"; CODE=1
fi
$IR down --all >/dev/null 2>&1 || true
exit "$CODE"

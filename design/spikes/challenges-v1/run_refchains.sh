#!/bin/bash
# challenges-v1 battery, slice-6 section: reference chains, behavioral checks,
# and the patch dual on live ranges (8 samples). Usage: ./run_refchains.sh
# [down]. Artifacts under tmp/ (gitignored). The provider path manages CIDs
# from this battery's private state dir (its own 10000+ band; the 30900+
# convention applies to direct-channel sections, of which this battery has
# none). Exclusive via the shared battery lock.
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

echo "=== refchains battery (real inspect eval, 8 samples) ==="
uv run python "$SPIKE/refchains_battery.py" 2>&1 | tee "$SPIKE/tmp/logs/refchains_battery.txt"
CODE=${PIPESTATUS[0]}

echo "=== residue check ==="
$IR down --all >/dev/null 2>&1 || true
LEFT=$(docker ps -a --format '{{.Names}}' | grep -c "^ir-challenges-v1" || true)
if [[ "$LEFT" -eq 0 ]]; then
  echo "PASS  zero residue (no ir-challenges-v1 containers)"
else
  echo "FAIL  residue: $LEFT containers"; CODE=1
fi
exit "$CODE"

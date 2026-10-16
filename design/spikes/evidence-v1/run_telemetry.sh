#!/bin/bash
# evidence-v1 battery, slice-4 section: in-guest telemetry export against a
# live range. A journald collector and a file collector poll the target over
# vsock while a real producer emits, stalls (pkill), fails (VM pause), and
# regresses (log truncation); the sealed record is verified offline with the
# binding supplied. Usage: ./run_telemetry.sh [down]. Artifacts under
# tmp-telemetry/ (gitignored). CID band 30300+; exclusive via the shared
# battery lock.
set -uo pipefail
cd "$(dirname "$0")"
SPIKE="$PWD"
ROOT="$(cd ../../.. && pwd)"

VENDOR="${VENDOR:-$HOME/.cache/inspect-ranges/images/noble-server-cloudimg-amd64.img}"
export XDG_STATE_HOME="$SPIKE/tmp-telemetry/state"
export INSPECT_RANGES_IMAGE_CACHE="$SPIKE/tmp-telemetry/cache"
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
rm -rf "$SPIKE/tmp-telemetry" && mkdir -p "$SPIKE/tmp-telemetry/cache" "$SPIKE/tmp-telemetry/logs"

echo "=== setup: doctor + golden ==="
$IR doctor >"$SPIKE/tmp-telemetry/logs/doctor.txt" 2>&1 \
  || { echo "FAIL doctor"; tail -20 "$SPIKE/tmp-telemetry/logs/doctor.txt"; exit 1; }
DB_OUT=$($IR daemon-bundle -o "$SPIKE/tmp-telemetry/artifacts")
DAEMON_SHA=$(echo "$DB_OUT" | grep -o 'bundle sha256:[0-9a-f]*' | cut -d: -f2)
VENDOR_SHA=$(sha256sum "$VENDOR" | cut -d' ' -f1)
$IR images derive "$VENDOR" --sha256 "$VENDOR_SHA" --name ev1-guest \
  --image-cache "$INSPECT_RANGES_IMAGE_CACHE" --daemon-bundle "$SPIKE/tmp-telemetry/artifacts" \
  --daemon-sha256 "$DAEMON_SHA" >"$SPIKE/tmp-telemetry/logs/derive.txt" 2>&1 \
  || { echo "FAIL golden derive"; tail -5 "$SPIKE/tmp-telemetry/logs/derive.txt"; exit 1; }

echo "=== battery ==="
uv run python "$SPIKE/telemetry_battery.py" 2>&1 | tee "$SPIKE/tmp-telemetry/logs/battery.txt"
CODE=${PIPESTATUS[0]}

# residue counted BEFORE the sweep: the zero-residue row must verify the
# battery left nothing behind, not that the sweep below works (round 2)
echo "=== residue check (counted before the sweep) ==="
if NAMES=$(docker ps -a --format '{{.Names}}'); then
  LEFT=$(grep -c "^ir-evidence-v1-telemetry" <<<"$NAMES" || true)
  if [[ "$LEFT" -eq 0 ]]; then
    echo "PASS  zero residue (no ir-evidence-v1-telemetry containers)"
  else
    echo "FAIL  residue: $LEFT containers"; CODE=1
  fi
else
  echo "FAIL  residue: docker ps failed"; CODE=1
fi
$IR down --all >/dev/null 2>&1 || true
exit "$CODE"

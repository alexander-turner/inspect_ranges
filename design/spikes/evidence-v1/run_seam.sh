#!/bin/bash
# evidence-v1 battery, slice-5 section: the provider/host seam on real ranges.
# S1 normal sample to real S3 (live shipping, compromise window, scrubbed
# verify, capture-cost budget); S2 kill -9 + reaper + reaped seal; S3
# backpressure; S4 separated topology through a real applier; S5 a real
# `inspect eval` whose log carries the store binding. Usage: ./run_seam.sh
# [down]. Artifacts under tmp/ (gitignored). Exclusive via the shared battery
# lock; S3 objects land under the chunk-3 scratch prefix and are removed at
# the end.
set -uo pipefail
cd "$(dirname "$0")"
SPIKE="$PWD"
ROOT="$(cd ../../.. && pwd)"

VENDOR="${VENDOR:-$HOME/.cache/inspect-ranges/images/noble-server-cloudimg-amd64.img}"
export XDG_STATE_HOME="$SPIKE/tmp/state"
export INSPECT_RANGES_IMAGE_CACHE="$SPIKE/tmp/cache"
export CAPTURE_CHUNK_MB=1
SEAM_S3_PREFIX="s3://${INSPECT_RANGES_SCRATCH_BUCKET:?set INSPECT_RANGES_SCRATCH_BUCKET to the operator scratch bucket}/inspect-ranges/spikes/evidence-v1-seam/run-$(date +%s)"
export SEAM_S3_PREFIX
IR="uv run inspect-ranges"

if [[ "${1:-}" == "down" ]]; then
  (cd "$ROOT" && $IR down --all) || true
  exit 0
fi

grep -q vhost_vsock /proc/modules || { echo "need: sudo modprobe vhost_vsock"; exit 1; }
[[ -f "$VENDOR" ]] || { echo "missing vendor image $VENDOR"; exit 1; }
aws sts get-caller-identity >/dev/null 2>&1 || { echo "need AWS credentials (S1/S2 stream to real S3)"; exit 1; }

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
$IR images derive "$VENDOR" --sha256 "$VENDOR_SHA" --name ev1-guest \
  --image-cache "$INSPECT_RANGES_IMAGE_CACHE" --daemon-bundle "$SPIKE/tmp/artifacts" \
  --daemon-sha256 "$DAEMON_SHA" >"$SPIKE/tmp/logs/derive.txt" 2>&1 \
  || { echo "FAIL golden derive"; tail -5 "$SPIKE/tmp/logs/derive.txt"; exit 1; }

echo "=== seam battery (S1-S4) ==="
uv run python "$SPIKE/seam_battery.py" 2>&1 | tee "$SPIKE/tmp/logs/seam.txt"
CODE=${PIPESTATUS[0]}

echo "=== S5: inspect eval smoke (identity path, binding in the log) ==="
EVAL_LOGS="$SPIKE/tmp/eval-logs"
mkdir -p "$EVAL_LOGS"
# relative task path: inspect's loader globs task specs and refuses absolute
# patterns (pathlib Non-relative patterns are unsupported)
(cd "$SPIKE" && "$ROOT/.venv/bin/inspect" eval seam_task.py --model mockllm/model \
  --log-dir "$EVAL_LOGS" --display plain) \
  >"$SPIKE/tmp/logs/eval.txt" 2>&1
if [[ $? -ne 0 ]]; then
  echo "FAIL  inspect eval run"; tail -20 "$SPIKE/tmp/logs/eval.txt"; CODE=1
else
  echo "PASS  inspect eval completed"
fi
uv run python "$SPIKE/seam_eval_check.py" "$EVAL_LOGS" \
  | tee -a "$SPIKE/tmp/logs/seam.txt" || CODE=1

echo "=== residue: containers, state, S3 (counted before the sweep) ==="
# residue counted BEFORE the sweep: the zero-residue row must verify the
# battery left nothing behind, not that the sweep below works (round 2)
if NAMES=$(docker ps -a --format '{{.Names}}'); then
  LEFT=$(grep -c "^ir-evidence-v1" <<<"$NAMES" || true)
  if [[ "$LEFT" -eq 0 ]]; then
    echo "PASS  zero container residue"
  else
    echo "FAIL  residue: $LEFT containers"; CODE=1
  fi
else
  echo "FAIL  residue: docker ps failed"; CODE=1
fi
$IR down --all >/dev/null 2>&1 || true
BUCKET_PATH="${SEAM_S3_PREFIX#s3://}"
aws s3 rm --recursive "s3://${BUCKET_PATH}" >/dev/null 2>&1 || true
REMAINING=$(aws s3 ls "s3://${BUCKET_PATH}/" --recursive 2>/dev/null | wc -l)
if [[ "$REMAINING" -eq 0 ]]; then
  echo "PASS  zero S3 residue under the run prefix"
else
  echo "FAIL  S3 residue: $REMAINING objects"; CODE=1
fi
exit "$CODE"

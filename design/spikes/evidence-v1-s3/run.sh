#!/bin/bash
# evidence-v1 battery, slice-3 section: the off-instance leg against real S3.
# Boots the slice-2 range with capture on, streams to the designated scratch
# bucket, measures watermark lag, exercises an uplink outage and bad
# credentials, seals, and verifies from a scrubbed-environment subprocess
# with and without the --expect-seal binding. Usage: ./run.sh [down].
# Artifacts under tmp/ (gitignored). CID band 30200+; exclusive via the
# shared battery lock. S3 objects land under
# s3://SCRATCH-BUCKET/inspect-ranges/spikes/evidence-v1-s3/runs/
# and are removed at the end of the run.
set -uo pipefail
cd "$(dirname "$0")"
SPIKE="$PWD"
ROOT="$(cd ../../.. && pwd)"

VENDOR="${VENDOR:-$HOME/.cache/inspect-ranges/images/noble-server-cloudimg-amd64.img}"
export XDG_STATE_HOME="$SPIKE/tmp/state"
export INSPECT_RANGES_IMAGE_CACHE="$SPIKE/tmp/cache"
export CAPTURE_CHUNK_MB=1
export CAPTURE_MAX_RESTARTS=2
export AWS_DEFAULT_REGION="${AWS_DEFAULT_REGION:-us-east-1}"
BUCKET="SCRATCH-BUCKET"
RUNS_PREFIX="inspect-ranges/spikes/evidence-v1-s3/runs"
IR="uv run inspect-ranges"

if [[ "${1:-}" == "down" ]]; then
  (cd "$ROOT" && $IR down --all) || true
  exit 0
fi

grep -q vhost_vsock /proc/modules || { echo "need: sudo modprobe vhost_vsock"; exit 1; }
[[ -f "$VENDOR" ]] || { echo "missing vendor image $VENDOR"; exit 1; }
aws sts get-caller-identity >/dev/null || { echo "need AWS credentials"; exit 1; }

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

echo "=== battery ==="
uv run python "$SPIKE/battery.py" 2>&1 | tee "$SPIKE/tmp/logs/battery.txt"
CODE=${PIPESTATUS[0]}

echo "=== residue check ==="
$IR down --all >/dev/null 2>&1 || true
LEFT=$(docker ps -a --format '{{.Names}}' | grep -c "^ir-evidence-v1" || true)
if [[ "$LEFT" -eq 0 ]]; then
  echo "PASS  zero residue (no ir-evidence-v1 containers)"
else
  echo "FAIL  residue: $LEFT containers"; CODE=1
fi
echo "=== s3 cleanup (objects removed; the shared bucket stays) ==="
aws s3 rm --recursive "s3://${BUCKET}/${RUNS_PREFIX}/" --quiet \
  || { echo "FAIL  s3 cleanup errored (objects may remain)"; CODE=1; }
# "aws s3 ls" exits 1 on an empty prefix, so emptiness is "no stdout AND no
# stderr"; a listing ERROR must fail the check, never pass it vacuously
LS_OUT=$(aws s3 ls "s3://${BUCKET}/${RUNS_PREFIX}/" --recursive 2>"$SPIKE/tmp/ls-err.txt")
if [[ -s "$SPIKE/tmp/ls-err.txt" ]]; then
  echo "FAIL  S3 residue check could not run:"; cat "$SPIKE/tmp/ls-err.txt"; CODE=1
elif [[ -z "$LS_OUT" ]]; then
  echo "PASS  zero S3 residue under ${RUNS_PREFIX}/"
else
  echo "FAIL  S3 residue: $(echo "$LS_OUT" | wc -l) objects"; CODE=1
fi
exit "$CODE"

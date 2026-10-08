#!/bin/bash
# realizer-v1 phase exit: one scripted run of every battery (images-derive,
# up-core, crash cleanup, the five repointed conformance batteries), then the
# three-command cold start on fresh caches. Each battery takes the shared host
# flock itself; this script serializes them. Usage: ./phase-exit.sh
set -euo pipefail
cd "$(dirname "$0")"
SPIKE="$PWD"
ROOT="$(cd ../../.. && pwd)"
VENDOR="${VENDOR:-$HOME/.cache/inspect-ranges/images/noble-server-cloudimg-amd64.img}"

echo "########## phase exit: realizer-v1 ##########"
run() {
  echo; echo "===== $1 ====="
  local log="$SPIKE/tmp/phase-$(echo "$1" | tr ' :/' '---').log"
  if ! bash "$2" > "$log" 2>&1; then
    echo "----- $1 FAILED; last 25 lines -----"; tail -25 "$log"; exit 1
  fi
  tail -3 "$log"
}
run "slice 1: images-derive" ../images-derive/run.sh
run "slices 2: up-core" ../up-core/run.sh
run "slice 3: crash cleanup" ../up-core/crash.sh
run "slice 4: five conformance batteries" ./run.sh

echo
# honest scope: fresh image/artifact caches and state; the hardened range
# image and the Go build cache are host state warmed by the batteries above,
# so a genuinely fresh host adds their one-time builds to the timing
echo "===== cold start: fresh caches to ready range in three commands ====="
export XDG_STATE_HOME="$SPIKE/tmp/coldstate"
COLD="$SPIKE/tmp/cold"
rm -rf "$COLD" "$XDG_STATE_HOME" && mkdir -p "$COLD/cache"
cd "$ROOT"
DB_OUT=$(uv run inspect-ranges daemon-bundle -o "$COLD/artifacts")
DAEMON_SHA=$(echo "$DB_OUT" | grep -o 'bundle sha256:[0-9a-f]*' | cut -d: -f2)
VENDOR_SHA=$(sha256sum "$VENDOR" | cut -d' ' -f1)
T0=$(date +%s.%N)
uv run inspect-ranges images derive "$VENDOR" --sha256 "$VENDOR_SHA" \
  --name noble-range-guest --image-cache "$COLD/cache" \
  --daemon-bundle "$COLD/artifacts" --daemon-sha256 "$DAEMON_SHA"
uv run inspect-ranges render design/spikes/acl-v2/spec.yaml -o "$COLD/bundle" \
  --image-cache "$COLD/cache" --cid-base 3200
uv run inspect-ranges up "$COLD/bundle" --image-cache "$COLD/cache" | tee "$COLD/up.txt"
T1=$(date +%s.%N)
PROJECT=$(grep -o 'ir-[a-z0-9-]*' "$COLD/up.txt" | head -1 || true)
python3 -c "print(f'cold start (derive + render + up, warm range image): {$T1-$T0:.0f}s')"
if [[ -n "$PROJECT" ]] && grep -q "ready: project" "$COLD/up.txt"; then
  echo "PHASE EXIT: cold start reached ready"
  uv run inspect-ranges down "$PROJECT"
else
  echo "PHASE EXIT FAILED: cold start did not reach ready (see $COLD/up.txt)"
  uv run inspect-ranges down --all || true
  exit 1
fi
echo "########## phase exit complete ##########"

#!/bin/bash
# build-v1 slice 2 battery: the `build` verb end to end.
# A bare `inspect-ranges build` from a range directory boots the egress build
# plan, runs recipes in declaration order (proved in-guest), reaches the
# archives from inside a guest, refuses a duplicate concurrent build, names
# guest/recipe/log on a failing recipe after teardown, and the kill -9 crash
# matrix leaves nothing behind. Usage: ./run.sh [down]. See README.md.
set -euo pipefail
cd "$(dirname "$0")"
SPIKE="$PWD"
ROOT="$(cd ../../.. && pwd)"

VENDOR="${VENDOR:-$HOME/.cache/inspect-ranges/images/noble-server-cloudimg-amd64.img}"
export XDG_STATE_HOME="$SPIKE/tmp/state"
export INSPECT_RANGES_BUILD_CACHE="$SPIKE/tmp/builds"
IR="uv run inspect-ranges"
IRBIN="$ROOT/.venv/bin/inspect-ranges"   # for bare invocations from inside a range dir
C() { (cd "$ROOT" && uv run python design/spikes/_shared/chexec.py --cid "$1" --user root exec "$2"); }
CACHE="$SPIKE/tmp/cache"
BUILD_FLAGS=(--image-cache "$CACHE" --cid-base 3300 --readiness-timeout 240)

if [[ "${1:-}" == "down" ]]; then
  (cd "$ROOT" && $IR down --all) || true
  exit 0
fi

grep -q vhost_vsock /proc/modules || { echo "need: sudo modprobe vhost_vsock"; exit 1; }
[[ -f "$VENDOR" ]] || { echo "missing vendor image $VENDOR"; exit 1; }

PASS=0; FAIL=0
ok()  { echo "PASS  $1"; PASS=$((PASS+1)); }
bad() { echo "FAIL  $1"; FAIL=$((FAIL+1)); }
ir_containers() { docker ps -aq --filter "name=ir-" | wc -l; }
ir_leftovers() {
  local c v s
  c=$(docker ps -aq --filter "name=ir-" | wc -l)
  v=$(docker volume ls -q | grep -c '^ir-' || true)
  s=$(ls -d "$XDG_STATE_HOME"/inspect-ranges/staging/* 2>/dev/null | wc -l)
  echo "containers=$c volumes=$v staging=$s"
}

exec 9>/tmp/inspect-ranges-battery.lock
flock 9

cd "$ROOT"
$IR down --all >/dev/null 2>&1 || true
rm -rf "$SPIKE/tmp" && mkdir -p "$SPIKE/tmp"

echo "=== derive the battery golden ==="
DB_OUT=$($IR daemon-bundle -o "$SPIKE/tmp/artifacts") \
  || { echo "daemon-bundle build failed (install the pinned Go toolchain)"; exit 1; }
DAEMON_SHA=$(echo "$DB_OUT" | grep -o 'bundle sha256:[0-9a-f]*' | cut -d: -f2)
VENDOR_SHA=$(sha256sum "$VENDOR" | cut -d' ' -f1)
$IR images derive "$VENDOR" --sha256 "$VENDOR_SHA" --name build-guest \
  --image-cache "$CACHE" --daemon-bundle "$SPIKE/tmp/artifacts" --daemon-sha256 "$DAEMON_SHA" >/dev/null

echo "=== C1-C3 bare build from the range directory, kept for inspection ==="
if (cd "$SPIKE/fixtures/buildrange" && "$IRBIN" build --keep "${BUILD_FLAGS[@]}" | tee "$SPIKE/tmp/c1.txt"); then
  grep -q "build OK" "$SPIKE/tmp/c1.txt" && ok "C1 bare build from '.' succeeds (build OK)" || bad "C1 build OK line"
else
  bad "C1 bare build from '.'"
fi
PROJECT=$(basename "$(ls -d "$XDG_STATE_HOME"/inspect-ranges/projects/ir-buildme-* 2>/dev/null | head -1)")
[[ -n "$PROJECT" ]] || { echo "no buildme project found; aborting"; exit 1; }

ORDER=$(C 3300 "cat /opt/build-order" || true)
[[ "$ORDER" == "first
second" ]] && ok "C2 recipes ran in declaration order (in-guest proof)" || bad "C2 order (got: $ORDER)"
EGRESS=$(C 3300 "cat /opt/egress-ok" || true)
[[ "$EGRESS" == "ok" ]] && ok "C3 build-time egress reached the archives from the guest" || bad "C3 egress (got: $EGRESS)"

echo "=== C4 duplicate concurrent build refuses, naming the project ==="
if (cd "$SPIKE/fixtures/buildrange" && "$IRBIN" build --keep "${BUILD_FLAGS[@]}" >"$SPIKE/tmp/c4.txt" 2>&1); then
  bad "C4 duplicate build refused"
else
  grep -q "already running" "$SPIKE/tmp/c4.txt" && grep -q "$PROJECT" "$SPIKE/tmp/c4.txt" \
    && ok "C4 duplicate build refused, naming $PROJECT" || bad "C4 duplicate refusal text"
fi
$IR down "$PROJECT" >/dev/null
$IR down --all >/dev/null 2>&1 || true   # section isolation: nothing survives into C5

echo "=== C5-C6 failing recipe: named failure, torn down, stage log recorded ==="
if (cd "$SPIKE/fixtures/failrange" && "$IRBIN" build "${BUILD_FLAGS[@]}" >"$SPIKE/tmp/c5.txt" 2>&1); then
  bad "C5 failing recipe fails the build"
else
  grep -q "build FAILED" "$SPIKE/tmp/c5.txt" && grep -q "guest 'web'" "$SPIKE/tmp/c5.txt" \
    && grep -q "bc.fail" "$SPIKE/tmp/c5.txt" && grep -q "log" "$SPIKE/tmp/c5.txt" \
    && ok "C5 failure names guest, recipe, and log" || { bad "C5 failure naming"; cat "$SPIKE/tmp/c5.txt"; }
fi
[[ "$(ir_containers)" == "0" ]] && ok "C6 failed build left no containers" || bad "C6 teardown after failure ($(ir_containers) left)"
STAGES=$(ls "$XDG_STATE_HOME"/inspect-ranges/projects/ir-failme-*/stages.jsonl 2>/dev/null | head -1)
[[ -n "$STAGES" ]] && grep -q '"stage": "recipe", "status": "fail"' "$STAGES" \
  && ok "C6b stage log records the recipe failure" || bad "C6b stage log"

echo "=== C7 kill -9 during boot, then down --all cleans ==="
(cd "$SPIKE/fixtures/buildrange" && "$IRBIN" build "${BUILD_FLAGS[@]}" >"$SPIKE/tmp/c7.txt" 2>&1) &
BUILD_PID=$!
C7_ARMED=0
for _ in $(seq 1 60); do [[ "$(ir_containers)" != "0" ]] && { C7_ARMED=1; break; }; sleep 1; done
[[ "$C7_ARMED" == "1" ]] || bad "C7 build never reached boot within 60 s (the kill would test nothing)"
kill -9 "$BUILD_PID" 2>/dev/null || true
pkill -9 -f "inspect-ranges build" 2>/dev/null || true
wait "$BUILD_PID" 2>/dev/null || true
$IR down --all >/dev/null 2>&1 || true
[[ "$(ir_leftovers)" == "containers=0 volumes=0 staging=0" ]] \
  && ok "C7 kill during boot + down --all leaves nothing (containers, volumes, staging)" \
  || bad "C7 crash cleanup ($(ir_leftovers))"

echo "=== C8 kill -9 during a recipe, then down --all cleans ==="
(cd "$SPIKE/fixtures/slowrange" && "$IRBIN" build "${BUILD_FLAGS[@]}" >"$SPIKE/tmp/c8.txt" 2>&1) &
BUILD_PID=$!
SLOWLOG="$XDG_STATE_HOME/inspect-ranges/projects"
C8_ARMED=0
for _ in $(seq 1 180); do
  grep -qs '"stage": "recipe", "status": "start"' "$SLOWLOG"/ir-slowme-*/stages.jsonl 2>/dev/null && { C8_ARMED=1; break; }
  sleep 1
done
[[ "$C8_ARMED" == "1" ]] || bad "C8 build never reached a recipe within 180 s (the kill would test nothing)"
kill -9 "$BUILD_PID" 2>/dev/null || true
pkill -9 -f "inspect-ranges build" 2>/dev/null || true
pkill -9 -f "bc.sleep" 2>/dev/null || true
wait "$BUILD_PID" 2>/dev/null || true
$IR down --all >/dev/null 2>&1 || true
[[ "$(ir_leftovers)" == "containers=0 volumes=0 staging=0" ]] \
  && ok "C8 kill during recipe + down --all leaves nothing (containers, volumes, staging)" \
  || bad "C8 crash cleanup ($(ir_leftovers))"

echo
echo "$PASS passed, $FAIL failed"
exit $((FAIL > 0))

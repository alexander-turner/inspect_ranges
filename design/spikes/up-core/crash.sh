#!/bin/bash
# realizer-v1 slice 3 battery: ownership-keyed teardown and crash cleanup.
# Kill-mid-up matrix synchronized on the stage log, down leaves nothing,
# double down is a no-op, down --all sweeps ir- only, pkill recovery.
# Usage: ./crash.sh. See README.md.
set -euo pipefail
cd "$(dirname "$0")"
SPIKE="$PWD"
ROOT="$(cd ../../.. && pwd)"

VENDOR="${VENDOR:-$HOME/.cache/inspect-ranges/images/noble-server-cloudimg-amd64.img}"
export XDG_STATE_HOME="$SPIKE/tmp/state"
IR="uv run inspect-ranges"
CACHE="$SPIKE/tmp/cache"
STATE="$XDG_STATE_HOME/inspect-ranges/projects"

grep -q vhost_vsock /proc/modules || { echo "need: sudo modprobe vhost_vsock"; exit 1; }
[[ -f "$VENDOR" ]] || { echo "missing vendor image $VENDOR"; exit 1; }

PASS=0; FAIL=0
ok()  { echo "PASS  $1"; PASS=$((PASS+1)); }
bad() { echo "FAIL  $1"; FAIL=$((FAIL+1)); }

exec 9>/tmp/inspect-ranges-battery.lock
flock 9

cd "$ROOT"
$IR down --all >/dev/null 2>&1 || true

echo "=== prepare: golden + bundle (reused from run.sh when present) ==="
if [[ ! -f "$SPIKE/tmp/bundle/manifest.json" ]]; then
  mkdir -p "$SPIKE/tmp"
  DB_OUT=$($IR daemon-bundle -o "$SPIKE/tmp/artifacts")
  DAEMON_SHA=$(echo "$DB_OUT" | grep -o 'bundle sha256:[0-9a-f]*' | cut -d: -f2)
  VENDOR_SHA=$(sha256sum "$VENDOR" | cut -d' ' -f1)
  $IR images derive "$VENDOR" --sha256 "$VENDOR_SHA" --name up-core-guest --image-cache "$CACHE" --daemon-bundle "$SPIKE/tmp/artifacts" --daemon-sha256 "$DAEMON_SHA" >/dev/null
  $IR render design/spikes/up-core/spec.yaml -o "$SPIKE/tmp/bundle" --image-cache "$CACHE" --cid-base 3000
fi
SPEC_SHA=$(python3 -c "import json;print(json.load(open('$SPIKE/tmp/bundle/manifest.json'))['spec_sha256'][:12])")
PROJECT="ir-up-core-$SPEC_SHA"
LOG="$STATE/$PROJECT/stages.jsonl"

nothing_left() {
  [[ -z "$(docker ps -aq --filter label=com.docker.compose.project=$PROJECT)" ]] \
  && [[ -z "$(docker volume ls -q --filter label=com.docker.compose.project=$PROJECT)" ]] \
  && [[ -z "$(docker network ls -q --filter label=com.docker.compose.project=$PROJECT)" ]] \
  && [[ ! -d "$STATE/$PROJECT" ]]
}

resources_exist() {
  [[ -n "$(docker ps -aq --filter label=com.docker.compose.project=$PROJECT)" ]] \
  || [[ -n "$(docker volume ls -q --filter label=com.docker.compose.project=$PROJECT)" ]]
}

stage_started() {
  # key-order-independent stage-log query
  python3 - "$LOG" "$1" <<'PYEOF2'
import json, sys
from pathlib import Path
log, stage = sys.argv[1], sys.argv[2]
if not Path(log).is_file():
    raise SystemExit(1)
for line in Path(log).read_text().splitlines():
    entry = json.loads(line)
    if entry.get("stage") == stage and entry.get("status") == "start":
        raise SystemExit(0)
raise SystemExit(1)
PYEOF2
}

kill_at_stage() {
  # waits for the stage's start line AND for project resources to exist; note
  # the 0.5s poll guarantees live-resources-at-kill, not strictly mid-stage
  # (the stage may have advanced by the time the signal lands)
  local stage="$1"
  rm -rf "$STATE/$PROJECT"
  setsid $IR up "$SPIKE/tmp/bundle" --image-cache "$CACHE" >/dev/null 2>&1 &
  local pid=$!
  for _ in $(seq 1 240); do
    if stage_started "$stage" && resources_exist; then
      kill -9 -- "-$pid" 2>/dev/null || kill -9 "$pid" 2>/dev/null || true
      wait "$pid" 2>/dev/null || true
      resources_exist || { bad "kill during $stage was vacuous (no resources at kill time)"; return; }
      $IR down "$PROJECT" >/dev/null
      if nothing_left; then ok "kill -9 during $stage (resources live), then down, leaves nothing"; else bad "kill during $stage left residue"; fi
      return
    fi
    sleep 0.5
  done
  kill -9 -- "-$pid" 2>/dev/null || true
  bad "kill during $stage: stage never observed with live resources"
}

echo "=== C1-C3 kill-mid-up matrix (stage-log synchronized) ==="
kill_at_stage "range-container"
kill_at_stage "guest-boot"
kill_at_stage "readiness"

echo "=== C4 double down is a no-op ==="
OUT=$($IR down "$PROJECT")
echo "$OUT" | grep -q "containers=0 volumes=0 networks=0" \
  && ok "double down is a no-op" || bad "double down ($OUT)"

rm -rf "$STATE/$PROJECT"
echo "=== C5 pkill-the-harness recovery (e2e-provider finding 5) ==="
setsid $IR up "$SPIKE/tmp/bundle" --image-cache "$CACHE" >/dev/null 2>&1 &
UPPID=$!
REACHED=0
for _ in $(seq 1 240); do
  stage_started "readiness" && REACHED=1 && break
  sleep 0.5
done
pkill -9 -g "$UPPID" 2>/dev/null || kill -9 "$UPPID" 2>/dev/null || true
wait "$UPPID" 2>/dev/null || true
if [[ "$REACHED" == "1" ]]; then
  # the range is still running headless; a fresh process recovers it by name
  $IR down "$PROJECT" >/dev/null
  nothing_left && ok "pkill recovery: fresh-process down leaves nothing" || bad "pkill recovery"
else
  bad "C5 vacuous: up never reached readiness"
  $IR down "$PROJECT" >/dev/null 2>&1 || true
fi

rm -rf "$STATE/$PROJECT"
echo "=== C6 down --all sweeps ir- only (chan- decoy untouched) ==="
docker volume create --label com.docker.compose.project=chan-decoy chan-decoy_scratch >/dev/null
setsid $IR up "$SPIKE/tmp/bundle" --image-cache "$CACHE" >/dev/null 2>&1 &
UPPID=$!
REACHED=0
for _ in $(seq 1 240); do
  stage_started "guest-boot" && REACHED=1 && break
  sleep 0.5
done
kill -9 -- "-$UPPID" 2>/dev/null || true; wait "$UPPID" 2>/dev/null || true
if [[ "$REACHED" == "1" ]]; then
  $IR down --all >/dev/null
  if nothing_left && docker volume inspect chan-decoy_scratch >/dev/null 2>&1; then
    ok "down --all swept ir- and left chan- alone"
  else
    bad "down --all"
  fi
else
  bad "C6 vacuous: up never reached guest-boot"
  $IR down --all >/dev/null 2>&1 || true
fi
docker volume rm chan-decoy_scratch >/dev/null 2>&1 || true

echo
echo "$PASS passed, $FAIL failed"
exit $((FAIL > 0))

#!/bin/bash
# channel-v1 slice 7: the convergence run. Re-runs the slice 4 battery
# components against a REALIZER-BOOTED range instead of the compose harness:
# daemon-bundle -> images derive (pinned daemon sha) -> render at the
# realizer band (--cid-base 3000, ir- project) -> up, then the portable
# conformance suite + durability + soak (tests/test_channel_vsock.py),
# self_check with pinned xfails, the hostile-daemon shim, and the wedge
# storm asserting listener_restarts == 0 via diag. Finally the concurrency
# check: the compose battery (chan band 2048) runs TO COMPLETION while this
# range stays up under continuous channel load (realizer band 3000+). The
# orchestrator holds the shared flock for the ENTIRE run (so no third
# battery's exclusive section can tear the live range down mid-proof) and
# invokes the compose battery with IR_BATTERY_LOCK_HELD=1; both bands run
# concurrently under the one lock owner and the overlap evidence persists
# in tmp/realizer/logs/overlap.log.
# Usage: ./run.sh [down]. Logs under ../tmp/realizer/ (gitignored).
set -euo pipefail
cd "$(dirname "$0")"
SPIKE="$PWD"
ROOT="$(cd ../../../.. && pwd)"
TMP="$SPIKE/../tmp/realizer"

VENDOR="${VENDOR:-$HOME/.cache/inspect-ranges/images/noble-server-cloudimg-amd64.img}"
export XDG_STATE_HOME="$TMP/state"
IR="uv run inspect-ranges"
CACHE="$TMP/cache"

if [[ "${1:-}" == "down" ]]; then
  (cd "$ROOT" && $IR down --all) || true
  exit 0
fi

grep -q vhost_vsock /proc/modules || { echo "need: sudo modprobe vhost_vsock"; exit 1; }
[[ -f "$VENDOR" ]] || { echo "missing vendor image $VENDOR"; exit 1; }

PASS=0; FAIL=0
ok()  { echo "PASS  $1"; PASS=$((PASS+1)); }
bad() { echo "FAIL  $1"; FAIL=$((FAIL+1)); }

# exclusive section: serialize on the shared host lock
exec 9>/tmp/inspect-ranges-battery.lock
flock 9

rm -rf "$TMP" && mkdir -p "$TMP/logs"
cd "$ROOT"
$IR down --all >/dev/null 2>&1 || true

echo "=== daemon artifact + v3 golden (realizer path: derive by pinned daemon sha) ==="
DB_OUT=$($IR daemon-bundle -o "$TMP/artifacts")
# `|| true` inside the substitutions: errexit must not kill the script
# before the guard can print a diagnosable FAIL (grep exits 1 on no match)
DAEMON_SHA=$(echo "$DB_OUT" | { grep -o 'bundle sha256:[0-9a-f]*' || true; } | cut -d: -f2)
[[ -n "$DAEMON_SHA" ]] && ok "daemon-bundle built (sha256 $DAEMON_SHA)" \
  || { echo "$DB_OUT"; bad "daemon-bundle"; exit 1; }
VENDOR_SHA=$(sha256sum "$VENDOR" | cut -d' ' -f1)
$IR images derive "$VENDOR" --sha256 "$VENDOR_SHA" --name noble-range-guest \
  --image-cache "$CACHE" --daemon-bundle "$TMP/artifacts" --daemon-sha256 "$DAEMON_SHA" \
  >"$TMP/logs/derive.log" 2>&1 \
  && ok "golden derived with the pinned daemon" || { cat "$TMP/logs/derive.log"; bad "derive"; exit 1; }

echo "=== render at the realizer band and up ==="
BUNDLE="$TMP/bundle"
$IR render "$SPIKE/spec.yaml" -o "$BUNDLE" --image-cache "$CACHE" --cid-base 3000 \
  >"$TMP/logs/render.log" 2>&1 || { cat "$TMP/logs/render.log"; bad "render"; exit 1; }
UP_OUT=$($IR up "$BUNDLE" --image-cache "$CACHE" 2>&1) || { echo "$UP_OUT"; bad "up"; exit 1; }
PROJECT=$(echo "$UP_OUT" | { grep -o 'project ir-[a-z0-9-]*' || true; } | sed -n '1s/^project //p')
[[ -n "$PROJECT" ]] && echo "$UP_OUT" | grep -q "ready: project" \
  && ok "realizer range up ($PROJECT)" \
  || { echo "$UP_OUT"; bad "up did not reach ready"; exit 1; }

CID=$(uv run python -c "
import json
boot = json.load(open('$BUNDLE/boot.json'))
cids = [g['cid'] for g in boot['guests'] if g['name'] == 'target']
print(cids[0] if cids else 0)
" || echo 0)
# hard gate: an out-of-band CID would run the whole battery (including the
# concurrency phase) against a band that can collide with the chan harness
[[ "$CID" -ge 3000 ]] && ok "guest CID $CID in the realizer band (3000+)" \
  || { bad "guest CID $CID outside the realizer band"; exit 1; }
export IR_VSOCK_BATTERY_CID=$CID

echo "=== wait for the daemon ==="
uv run python design/spikes/_shared/chexec.py --cid "$CID" wait 120 \
  && ok "v3 daemon answers on vsock (CID $CID, realizer-booted)" || { bad "daemon answers"; exit 1; }

echo "=== portable conformance + durability + soak (pytest) ==="
if uv run pytest tests/test_channel_vsock.py -v -n 0 2>&1 | tee "$TMP/logs/pytest.log" | tail -4; then
  ok "vsock battery pytest green (realizer-booted)"
else
  bad "vsock battery pytest"
fi

echo "=== Inspect self_check over v3 ==="
if uv run python design/spikes/channel-v1/self_check3.py 2>&1 | tee "$TMP/logs/self_check.log" | tail -6; then
  ok "self_check within documented xfails"
else
  bad "self_check"
fi

echo "=== hostile-daemon shim through the real transport ==="
if uv run python design/spikes/channel-v1/hostile_shim_check.py 2>&1 | tee "$TMP/logs/shim.log"; then
  ok "hostile shim scenarios"
else
  bad "hostile shim scenarios"
fi

echo "=== the wedge regression against the realizer-booted guest ==="
if uv run python design/spikes/channel-v1/windows/storm_v3.py 2>&1 | tee "$TMP/logs/storm.log" | tail -4; then
  ok "reconnect storm: listener alive, listener_restarts == 0"
else
  bad "reconnect storm"
fi

echo "=== concurrency: compose battery (chan band) under realizer-band load ==="
STOP="$TMP/load.stop"
LOAD_LOG="$TMP/logs/load.log"
rm -f "$STOP"
uv run python design/spikes/channel-v1/realizer/load_loop.py "$STOP" "$LOAD_LOG" \
  >"$TMP/logs/load-summary.log" 2>&1 &
LOAD_PID=$!
# reap the loader on ANY exit path (Ctrl-C mid-compose, an errexit): an
# orphan would hammer the guest forever against a stop file never touched
trap 'touch "$STOP" 2>/dev/null || true; wait "$LOAD_PID" 2>/dev/null || true' EXIT
sleep 3
# the lock stays held: this orchestrator is the one exclusive owner for the
# whole run, and the compose battery it spawns skips re-acquisition
COMPOSE_T0=$(date +%s)
if IR_BATTERY_LOCK_HELD=1 bash design/spikes/channel-v1/run.sh \
    >"$TMP/logs/compose-battery.log" 2>&1; then
  ok "compose battery (chan band 2048) green under concurrent load"
else
  tail -20 "$TMP/logs/compose-battery.log" || true
  bad "compose battery under concurrent load"
fi
COMPOSE_T1=$(date +%s)
touch "$STOP"
if wait "$LOAD_PID"; then
  ok "realizer-band load: zero failures through the whole concurrent window"
else
  tail -5 "$LOAD_LOG" || true
  bad "realizer-band load saw failures"
fi
cat "$TMP/logs/load-summary.log"
# untruncated comparison; the loader's final line is written AFTER it
# observes the stop file, so load end >= compose end by construction
if uv run python -c "
import sys
lines = open('$LOAD_LOG').read().split()
load_t0, load_t1 = float(lines[0]), float(lines[-2])
t0, t1 = float($COMPOSE_T0), float($COMPOSE_T1)
print(f'overlap: load window {load_t0:.3f}..{load_t1:.3f}, compose battery {t0:.0f}..{t1:.0f}')
sys.exit(0 if load_t0 <= t0 and load_t1 >= t1 else 1)
" | tee "$TMP/logs/overlap.log"; then
  ok "timing overlap proven (load spans the compose battery run)"
else
  bad "timing overlap not proven"
fi

echo "=== post-concurrency health: the realizer guest never wedged ==="
if uv run python design/spikes/_shared/chexec.py --cid "$CID" wait 30 \
    && uv run python design/spikes/_shared/chexec.py --cid "$CID" diag \
       | tee "$TMP/logs/post-diag.log" | grep -q '^listener_restarts=0 '; then
  ok "guest healthy after concurrency, listener_restarts == 0"
else
  bad "post-concurrency health"
fi

$IR down "$PROJECT" >/dev/null && ok "range down clean" || bad "down"

echo
echo "$PASS passed, $FAIL failed"
exit $((FAIL > 0))

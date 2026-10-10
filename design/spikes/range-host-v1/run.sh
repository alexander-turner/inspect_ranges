#!/bin/bash
# range-host-v1 slice-4 battery: the separated topology on one host, for real.
# A real `inspect-ranges applier` process and real driver processes against
# realizer-booted ranges. Stages: derive the recipe-v4 golden; battery_main
# (observed realize-to-ready with heartbeat across the lifecycle, the portable
# suite over the live applier at a real rendered bundle, self_check 44/44
# through RemoteRangeHost at the EMPTY pin, the local-vs-UDS wall clock); the
# lifecycle matrix (concurrency, wedged teardown + applier restart, kill -9 +
# fresh-shell reaper through the live applier, forced expiry with the loud
# LeaseLostError and the reaper-vs-renewal race both ways); and the
# zero-residue sweep including leases and the socket.
# Usage: ./run.sh [down]. Logs under tmp/ (gitignored). Battery CID band
# 20000+ for direct allocations; exclusive via the shared battery lock.
set -euo pipefail
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

PASS=0; FAIL=0
ok()  { echo "PASS  $1"; PASS=$((PASS+1)); }
bad() { echo "FAIL  $1"; FAIL=$((FAIL+1)); }

exec 9>/tmp/inspect-ranges-battery.lock
flock 9

cd "$ROOT"
$IR down --all >/dev/null 2>&1 || true
rm -rf "$SPIKE/tmp" && mkdir -p "$SPIKE/tmp/cache" "$SPIKE/tmp/logs"

echo "=== setup: daemon bundle + recipe-v4 golden (noble-range-guest) ==="
DB_OUT=$($IR daemon-bundle -o "$SPIKE/tmp/artifacts")
DAEMON_SHA=$(echo "$DB_OUT" | grep -o 'bundle sha256:[0-9a-f]*' | cut -d: -f2)
VENDOR_SHA=$(sha256sum "$VENDOR" | cut -d' ' -f1)
$IR images derive "$VENDOR" --sha256 "$VENDOR_SHA" --name noble-range-guest \
  --image-cache "$INSPECT_RANGES_IMAGE_CACHE" --daemon-bundle "$SPIKE/tmp/artifacts" \
  --daemon-sha256 "$DAEMON_SHA" >"$SPIKE/tmp/logs/derive.txt" 2>&1 \
  && ok "recipe-v4 golden derived" || { bad "golden derived"; tail -5 "$SPIKE/tmp/logs/derive.txt"; exit 1; }

echo "=== battery main: observed realize, live-applier suite, self_check, timings ==="
if uv run python design/spikes/range-host-v1/battery_main.py 2>&1 \
     | tee "$SPIKE/tmp/logs/battery.txt"; then
  ok "battery main"
else
  bad "battery main"
fi

echo "=== lifecycle matrix: concurrency, wedge+restart, kill -9 + reaper, forced expiry ==="
if uv run python design/spikes/range-host-v1/lifecycle_matrix.py 2>&1 \
     | tee "$SPIKE/tmp/logs/matrix.txt"; then
  ok "lifecycle matrix"
else
  bad "lifecycle matrix"
fi

echo "=== zero residue (containers, networks, volumes, CID leases, HOST leases, staging, socket) ==="
SWEEP=$($IR down --all)
echo "$SWEEP"
[[ "$SWEEP" == "no ir- projects found" ]] && ok "down --all reports a no-op" \
  || bad "down --all found residue"
RESIDUE=$(docker ps -a --format '{{.Names}}' | grep -c '^ir-' || true)
[[ "$RESIDUE" == "0" ]] && ok "no ir- containers remain" || bad "ir- containers remain ($RESIDUE)"
NET_RESIDUE=$(docker network ls --format '{{.Name}}' | grep -c '^ir-' || true)
[[ "$NET_RESIDUE" == "0" ]] && ok "no ir- networks remain" || bad "ir- networks remain ($NET_RESIDUE)"
VOL_RESIDUE=$(docker volume ls --format '{{.Name}}' | grep -c '^ir-' || true)
[[ "$VOL_RESIDUE" == "0" ]] && ok "no ir- volumes remain" || bad "ir- volumes remain ($VOL_RESIDUE)"
CIDS=$(uv run python -c "
import json, pathlib
path = pathlib.Path('$XDG_STATE_HOME/inspect-ranges/projects/cids.json')
print(len(json.loads(path.read_text())) if path.exists() else 0)
")
[[ "$CIDS" == "0" ]] && ok "no CID leases remain" || bad "CID leases remain ($CIDS)"
LEASES=$(uv run python -c "
import json, pathlib
path = pathlib.Path('$XDG_STATE_HOME/inspect-ranges/projects/leases.json')
print(len(json.loads(path.read_text())) if path.exists() else 0)
")
[[ "$LEASES" == "0" ]] && ok "no HOST leases remain" || bad "host leases remain ($LEASES)"
STAGING=$(find "$XDG_STATE_HOME/inspect-ranges/staging" -mindepth 1 -maxdepth 1 2>/dev/null | wc -l)
[[ "$STAGING" == "0" ]] && ok "no staging residue" || bad "staging residue ($STAGING)"
[[ ! -S "$SPIKE/tmp/applier.sock" ]] && ok "applier socket removed" || bad "applier socket remains"

echo
echo "$PASS passed, $FAIL failed"
exit $((FAIL > 0))

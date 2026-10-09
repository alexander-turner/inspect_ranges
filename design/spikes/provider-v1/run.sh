#!/bin/bash
# provider-v1 slice 5 battery: the provider-driven lifecycle on realizer-booted
# ranges, end to end through the registered entry point. Stages: derive the
# recipe-v4 golden; the main battery (boot, basic ops, self_check 44/44 with
# the EMPTY pin, portable conformance over the booted guest, the third-user
# wrapper path, agent-identity pins, suspend/resume retry recovery, the
# vsockd-restart SessionChangedError fault); the lifecycle matrix (interrupt
# deferral, cleanup=False with the printed command, concurrent same-spec
# samples); kill -9 recovery via `inspect sandbox cleanup libvirt_range` from
# a fresh shell; one real `inspect eval`; and the zero-ir-residue sweep.
# Usage: ./run.sh [down]. Logs under tmp/ (gitignored). Provider CID band
# 10000+ (the allocator's partition); exclusive via the shared battery lock.
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

echo "=== main battery: lifecycle + self_check + conformance + retry faults ==="
if uv run python design/spikes/provider-v1/battery_main.py 2>&1 \
     | tee "$SPIKE/tmp/logs/battery.txt"; then
  ok "main battery"
else
  bad "main battery"
fi

echo "=== lifecycle matrix: interrupt, cleanup=False, concurrency ==="
if uv run python design/spikes/provider-v1/lifecycle_matrix.py 2>&1 \
     | tee "$SPIKE/tmp/logs/matrix.txt"; then
  ok "lifecycle matrix"
else
  bad "lifecycle matrix"
fi

echo "=== kill -9 recovery from a fresh shell ==="
# gate: earlier stages must not have leaked (an id-less sweep here would
# silently absorb their leaks and make the final residue checks vacuous)
PRE_KILL9=$(docker ps -a --format '{{.Names}}' | grep -c '^ir-' || true)
[[ "$PRE_KILL9" == "0" ]] && ok "no ir- residue before the kill-9 stage" \
  || bad "earlier stages leaked $PRE_KILL9 ir- container(s)"
uv run python design/spikes/provider-v1/boot_and_die.py >"$SPIKE/tmp/logs/kill9.txt" 2>&1 || true
PROJECT=$(uv run python -c "import json;print(json.load(open('$SPIKE/tmp/kill9.json'))['project'])")
if docker ps --format '{{.Names}}' | grep -q "${PROJECT}-range-1"; then
  ok "kill -9 left the range running (nothing cleaned it)"
else
  bad "kill -9 scenario: range not found running"
fi
if uv run inspect sandbox cleanup libvirt_range "$PROJECT" >"$SPIKE/tmp/logs/cli_cleanup.txt" 2>&1 \
     && ! docker ps --format '{{.Names}}' | grep -q "${PROJECT}-range-1"; then
  ok "inspect sandbox cleanup recovered the orphan from on-disk state (scoped to its project)"
else
  bad "inspect sandbox cleanup recovery"; tail -5 "$SPIKE/tmp/logs/cli_cleanup.txt"
fi

echo "=== the real inspect eval (entry-point registration only) ==="
if uv run inspect eval evals/smoke/task.py --model mockllm/model \
     --log-dir "$SPIKE/tmp/logs/eval" >"$SPIKE/tmp/logs/eval.txt" 2>&1; then
  grep -E "accuracy" "$SPIKE/tmp/logs/eval.txt" | head -2
  if grep -qE "accuracy[^0-9]*1" "$SPIKE/tmp/logs/eval.txt"; then
    ok "inspect eval green with accuracy 1"
  else
    bad "inspect eval ran but accuracy != 1"
  fi
else
  bad "inspect eval"; tail -15 "$SPIKE/tmp/logs/eval.txt"
fi

echo "=== zero ir- residue ==="
SWEEP=$($IR down --all)
echo "$SWEEP"
[[ "$SWEEP" == "no ir- projects found" ]] && ok "down --all reports a no-op" \
  || bad "down --all found residue"
RESIDUE=$(docker ps -a --format '{{.Names}}' | grep -c '^ir-' || true)
[[ "$RESIDUE" == "0" ]] && ok "no ir- containers remain" || bad "ir- containers remain ($RESIDUE)"
LEASES=$(uv run python -c "
import json, pathlib
path = pathlib.Path('$XDG_STATE_HOME/inspect-ranges/projects/cids.json')
print(len(json.loads(path.read_text()).get('leases', {})) if path.exists() else 0)
")
[[ "$LEASES" == "0" ]] && ok "no CID leases remain" || bad "CID leases remain ($LEASES)"
STAGING=$(find "$XDG_STATE_HOME/inspect-ranges/staging" -mindepth 1 -maxdepth 1 2>/dev/null | wc -l)
[[ "$STAGING" == "0" ]] && ok "no staging residue" || bad "staging residue ($STAGING)"

echo
echo "$PASS passed, $FAIL failed"
exit $((FAIL > 0))

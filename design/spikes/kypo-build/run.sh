#!/bin/bash
# linux-examples-v1 slice 1 battery: kypo-demo built and solved. The translated
# KYPO fixture builds for real (recipes realize telnetd on the variable port,
# the weak-password account, the sudoers escalation, the client toolset; the
# build's behavioral checks run the reference/insufficient/forged trio against
# the captured artifacts), then a real inspect eval boots the built range
# through the provider and the reference ladder scores 1.0 through the client
# foothold with the wall pinned. Usage: ./run.sh [down]. CID band 4100.
set -euo pipefail
cd "$(dirname "$0")"
SPIKE="$PWD"
ROOT="$(cd ../../.. && pwd)"
RANGE="$ROOT/examples/kypo-demo"

NOBLE="${NOBLE:-$HOME/.cache/inspect-ranges/images/noble-server-cloudimg-amd64.img}"
FOCAL="${FOCAL:-$HOME/.cache/inspect-ranges/images/focal-server-cloudimg-amd64.img}"
export XDG_STATE_HOME="$SPIKE/tmp/state"
IR="uv run inspect-ranges"
IRBIN="$ROOT/.venv/bin/inspect-ranges"
CACHE="$SPIKE/tmp/cache"
BUILDS="$SPIKE/tmp/builds"
FLAGS=(--image-cache "$CACHE" --build-cache "$BUILDS" --cid-base 4100 --readiness-timeout 300)

if [[ "${1:-}" == "down" ]]; then
  (cd "$ROOT" && $IR down --all) || true
  exit 0
fi

grep -q vhost_vsock /proc/modules || { echo "need: sudo modprobe vhost_vsock"; exit 1; }
[[ -f "$NOBLE" && -f "$FOCAL" ]] || { echo "missing vendor images"; exit 1; }

PASS=0; FAIL=0
ok()  { echo "PASS  $1"; PASS=$((PASS+1)); }
bad() { echo "FAIL  $1"; FAIL=$((FAIL+1)); }

exec 9>/tmp/inspect-ranges-battery.lock
flock 9
cd "$ROOT"
$IR down --all >/dev/null 2>&1 || true
rm -rf "$SPIKE/tmp" && mkdir -p "$SPIKE/tmp"

echo "=== K1 build the translated fixture for real ==="
DB_OUT=$($IR daemon-bundle -o "$SPIKE/tmp/artifacts")
DAEMON_SHA=$(echo "$DB_OUT" | grep -o 'bundle sha256:[0-9a-f]*' | cut -d: -f2)
$IR images derive "$FOCAL" --sha256 "$(sha256sum "$FOCAL" | cut -d' ' -f1)" --name ubuntu-focal \
  --image-cache "$CACHE" --daemon-bundle "$SPIKE/tmp/artifacts" --daemon-sha256 "$DAEMON_SHA" >/dev/null
$IR images derive "$NOBLE" --sha256 "$(sha256sum "$NOBLE" | cut -d' ' -f1)" --name ubuntu-noble \
  --image-cache "$CACHE" --daemon-bundle "$SPIKE/tmp/artifacts" --daemon-sha256 "$DAEMON_SHA" >/dev/null
(cd "$RANGE" && "$IRBIN" build "${FLAGS[@]}" --recipe-budget 1200 >"$SPIKE/tmp/k1.txt" 2>&1) \
  && grep -q "build OK" "$SPIKE/tmp/k1.txt" && ok "K1 kypo-demo builds green" \
  || { bad "K1 build"; tail -15 "$SPIKE/tmp/k1.txt"; exit 1; }
grep -q "behavioral.*check=reference" "$SPIKE/tmp/k1.txt" \
  && grep -q "behavioral.*check=insufficient" "$SPIKE/tmp/k1.txt" \
  && grep -q "behavioral.*check=forged" "$SPIKE/tmp/k1.txt" \
  && grep -q "behavioral checks=3" "$SPIKE/tmp/k1.txt" \
  && ok "K1b the trio proved the ladder against the captured artifacts" \
  || { bad "K1b behavioral lines"; grep -i behavioral "$SPIKE/tmp/k1.txt" | tail -5; }
MANIFEST="$BUILDS/kypo-demo/manifest.json"
[[ -f "$MANIFEST" ]] && python3 - "$MANIFEST" <<'PYEOF' && ok "K1c the manifest records the realized sections and passing checks" || bad "K1c manifest"
import json, sys
m = json.load(open(sys.argv[1]))
sections = set(m["realized_sections"])
assert {"provisioning", "services", "users", "misconfigurations", "data"} <= sections, sections
checks = m["verification"]["behavioral_checks"]
assert len(checks) == 3 and all(c["status"] == "pass" for c in checks), checks
PYEOF

echo "=== K2 the reference ladder scores through a real eval (foothold wall pinned) ==="
export INSPECT_RANGES_IMAGE_CACHE="$CACHE"
export INSPECT_RANGES_BUILD_CACHE="$BUILDS"
if (cd "$ROOT" && uv run python "$SPIKE/kypo_eval.py" "$RANGE" >"$SPIKE/tmp/k2.txt" 2>&1); then
  grep -E "^(PASS|FAIL)" "$SPIKE/tmp/k2.txt" || true
  ok "K2 the eval leg ran green (1.0, valid, wall held)"
else
  bad "K2 eval"; tail -30 "$SPIKE/tmp/k2.txt"
fi

$IR down --all >/dev/null 2>&1 || true
echo
echo "$PASS passed, $FAIL failed"
exit $((FAIL > 0))

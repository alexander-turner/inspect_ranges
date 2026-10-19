#!/bin/bash
# linux-examples-v1 slice 2 battery: cyris-basic built and solved. The CyRIS
# reference fixture builds for real (desktop: accounts, analyst tools, the
# emulated attack noise, planted captures, the dummy resident malware;
# webserver: apache2+php, accounts, captures; the firewall as a plain-router
# guest with the upstream 25/53 forwarding ACL), the behavioral trios prove
# all three challenges against the captured artifacts, and a real inspect
# eval boots the built range with every reference chain scoring 1.0 through
# the desktop foothold. Usage: ./run.sh [down]. CID band 4110.
set -euo pipefail
cd "$(dirname "$0")"
SPIKE="$PWD"
ROOT="$(cd ../../.. && pwd)"
RANGE="$ROOT/examples/cyris-basic"

NOBLE="${NOBLE:-$HOME/.cache/inspect-ranges/images/noble-server-cloudimg-amd64.img}"
FOCAL="${FOCAL:-$HOME/.cache/inspect-ranges/images/focal-server-cloudimg-amd64.img}"
export XDG_STATE_HOME="$SPIKE/tmp/state"
IR="uv run inspect-ranges"
IRBIN="$ROOT/.venv/bin/inspect-ranges"
CACHE="$SPIKE/tmp/cache"
BUILDS="$SPIKE/tmp/builds"
FLAGS=(--image-cache "$CACHE" --build-cache "$BUILDS" --cid-base 4110 --readiness-timeout 300)

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

echo "=== C1 build the translated fixture for real ==="
DB_OUT=$($IR daemon-bundle -o "$SPIKE/tmp/artifacts")
DAEMON_SHA=$(echo "$DB_OUT" | grep -o 'bundle sha256:[0-9a-f]*' | cut -d: -f2)
$IR images derive "$FOCAL" --sha256 "$(sha256sum "$FOCAL" | cut -d' ' -f1)" --name ubuntu-focal \
  --image-cache "$CACHE" --daemon-bundle "$SPIKE/tmp/artifacts" --daemon-sha256 "$DAEMON_SHA" >/dev/null
$IR images derive "$NOBLE" --sha256 "$(sha256sum "$NOBLE" | cut -d' ' -f1)" --name noble-range-guest \
  --image-cache "$CACHE" --daemon-bundle "$SPIKE/tmp/artifacts" --daemon-sha256 "$DAEMON_SHA" >/dev/null
(cd "$RANGE" && "$IRBIN" build "${FLAGS[@]}" --recipe-budget 1200 >"$SPIKE/tmp/c1.txt" 2>&1) \
  && grep -q "build OK" "$SPIKE/tmp/c1.txt" && ok "C1 cyris-basic builds green" \
  || { bad "C1 build"; tail -15 "$SPIKE/tmp/c1.txt"; exit 1; }
grep -q "behavioral checks=9" "$SPIKE/tmp/c1.txt" \
  && ok "C1b all three trios proved against the captured artifacts (checks=9)" \
  || { bad "C1b behavioral lines"; grep -i behavioral "$SPIKE/tmp/c1.txt" | tail -6; }

echo "=== C2 every reference chain scores through a real eval ==="
export INSPECT_RANGES_IMAGE_CACHE="$CACHE"
export INSPECT_RANGES_BUILD_CACHE="$BUILDS"
if (cd "$ROOT" && uv run python "$SPIKE/cyris_eval.py" "$RANGE" >"$SPIKE/tmp/c2.txt" 2>&1); then
  grep -E "^(PASS|FAIL)" "$SPIKE/tmp/c2.txt" || true
  ok "C2 the eval leg ran green (3 chains, 1.0 valid, wall held)"
else
  bad "C2 eval"; tail -40 "$SPIKE/tmp/c2.txt"
fi

$IR down --all >/dev/null 2>&1 || true
echo
echo "$PASS passed, $FAIL failed"
exit $((FAIL > 0))

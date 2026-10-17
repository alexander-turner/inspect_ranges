#!/bin/bash
# build-v1 slice 4 battery: the verification engine against live guests.
# An all-green build (nginx installed by recipe, declared with port, version,
# and package attribution, a vulnerability linked to it); the Journey A
# wrong-version scenario failing with the declared-vs-observed delta; and a
# dead service failing by listening with its linked vulnerability failing by
# linkage, the range torn down after verification failure.
# Usage: ./run.sh [down]. See README.md.
set -euo pipefail
cd "$(dirname "$0")"
SPIKE="$PWD"
ROOT="$(cd ../../.. && pwd)"

ERA="${ERA:-$HOME/.cache/inspect-ranges/images/focal-server-cloudimg-amd64.img}"
export XDG_STATE_HOME="$SPIKE/tmp/state"
IR="uv run inspect-ranges"
IRBIN="$ROOT/.venv/bin/inspect-ranges"
CACHE="$SPIKE/tmp/cache"
FLAGS=(--image-cache "$CACHE" --cid-base 3500 --readiness-timeout 300)

if [[ "${1:-}" == "down" ]]; then
  (cd "$ROOT" && $IR down --all) || true
  exit 0
fi

grep -q vhost_vsock /proc/modules || { echo "need: sudo modprobe vhost_vsock"; exit 1; }
[[ -f "$ERA" ]] || { echo "missing focal vendor image $ERA"; exit 1; }

PASS=0; FAIL=0
ok()  { echo "PASS  $1"; PASS=$((PASS+1)); }
bad() { echo "FAIL  $1"; FAIL=$((FAIL+1)); }
ir_containers() { docker ps -aq --filter "name=ir-" | wc -l; }

exec 9>/tmp/inspect-ranges-battery.lock
flock 9

cd "$ROOT"
$IR down --all >/dev/null 2>&1 || true
rm -rf "$SPIKE/tmp" && mkdir -p "$SPIKE/tmp"

echo "=== derive the focal golden ==="
DB_OUT=$($IR daemon-bundle -o "$SPIKE/tmp/artifacts") \
  || { echo "daemon-bundle build failed (install the pinned Go toolchain)"; exit 1; }
DAEMON_SHA=$(echo "$DB_OUT" | grep -o 'bundle sha256:[0-9a-f]*' | cut -d: -f2)
ERA_SHA=$(sha256sum "$ERA" | cut -d' ' -f1)
$IR images derive "$ERA" --sha256 "$ERA_SHA" --name focal-guest \
  --image-cache "$CACHE" --daemon-bundle "$SPIKE/tmp/artifacts" --daemon-sha256 "$DAEMON_SHA" >/dev/null

echo "=== V1-V3 all-green verification ==="
if (cd "$SPIKE/fixtures/okrange" && "$IRBIN" build "${FLAGS[@]}" | tee "$SPIKE/tmp/v1.txt"); then
  grep -q "build OK" "$SPIKE/tmp/v1.txt" && ok "V1 all-green build passes verification" || bad "V1 build OK line"
else
  bad "V1 all-green build"
fi
grep -q "verify    ok  service web/nginx" "$SPIKE/tmp/v1.txt" \
  && grep -q "verify    ok  vulnerability web/demo-vuln" "$SPIKE/tmp/v1.txt" \
  && ok "V2 per-declaration ok lines (service + linked vulnerability)" || bad "V2 verify lines"
OKSTAGES=$(ls "$XDG_STATE_HOME"/inspect-ranges/projects/ir-bvok-*/stages.jsonl 2>/dev/null | head -1)
[[ -n "$OKSTAGES" ]] && grep -q '"stage": "verify"' "$OKSTAGES" && grep -q '"declarations": 2' "$OKSTAGES" \
  && ok "V3 stage log records per-declaration results and the summary" || bad "V3 stage log"

echo "=== V4-V5 wrong version: the Journey A scenario ==="
if (cd "$SPIKE/fixtures/wrongversion" && "$IRBIN" build "${FLAGS[@]}" >"$SPIKE/tmp/v4.txt" 2>&1); then
  bad "V4 wrong version fails the build"
else
  grep -q "build FAILED" "$SPIKE/tmp/v4.txt" && grep -q "\[verify\]" "$SPIKE/tmp/v4.txt" \
    && ok "V4 wrong version fails the build at the verify stage" || { bad "V4 failure shape"; tail -5 "$SPIKE/tmp/v4.txt"; }
fi
grep -q "\[service-not-verified\] guest 'web'" "$SPIKE/tmp/v4.txt" \
  && grep -q "declared 1.19" "$SPIKE/tmp/v4.txt" && grep -qE "version 1\.18[^ ]* from" "$SPIKE/tmp/v4.txt" \
  && grep -q "log: " "$SPIKE/tmp/v4.txt" \
  && ok "V5 refusal names code, guest, declared-vs-observed, and the log" || { bad "V5 refusal text"; grep -A1 service-not-verified "$SPIKE/tmp/v4.txt" | head -4; }

echo "=== V6-V8 dead service and linked vulnerability ==="
if (cd "$SPIKE/fixtures/deadservice" && "$IRBIN" build "${FLAGS[@]}" >"$SPIKE/tmp/v6.txt" 2>&1); then
  bad "V6 dead service fails the build"
else
  grep -q "no tcp/udp socket on port 6379" "$SPIKE/tmp/v6.txt" \
    && ok "V6 dead service fails by listening" || { bad "V6 listening failure"; tail -5 "$SPIKE/tmp/v6.txt"; }
fi
grep -q "\[vulnerability-not-verified\] guest 'web'" "$SPIKE/tmp/v6.txt" \
  && grep -q "failed its assertion" "$SPIKE/tmp/v6.txt" \
  && ok "V7 linked vulnerability fails by linkage" || bad "V7 vulnerability linkage"
[[ "$(ir_containers)" == "0" ]] && ok "V8 range torn down after verification failure" || bad "V8 teardown ($(ir_containers) left)"

$IR down --all >/dev/null 2>&1 || true

echo
echo "$PASS passed, $FAIL failed"
exit $((FAIL > 0))

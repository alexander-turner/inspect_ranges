#!/bin/bash
# linux-examples-v1 slice 3 battery: mhbench-equifax-small built and solved —
# the phase's scale proof (7 guests incl. the CATALOG-DEFAULT attacker). The
# attack image builds and publishes to a directory location so the bare name
# `attack` resolves (the attacker declares NO image); the fixture builds for
# real (tomcat 9.0.83 + the vulnerable struts2-showcase 2.3.30 on both
# webservers with the CVE-2017-5638 OGNL probe asserted live in-recipe, the
# pivot key on webserver_0, four database hosts authorizing it); the
# behavioral trio proves the Equifax chain; and a real inspect eval scores
# 1.0 coverage with pcap corroboration on the critical segment.
# Usage: ./run.sh [down]. CID band 4130.
set -euo pipefail
cd "$(dirname "$0")"
SPIKE="$PWD"
ROOT="$(cd ../../.. && pwd)"
RANGE="$ROOT/examples/mhbench-equifax-small"
ATTACK_RANGE="$ROOT/catalog/attack"

NOBLE="${NOBLE:-$HOME/.cache/inspect-ranges/images/noble-server-cloudimg-amd64.img}"
FOCAL="${FOCAL:-$HOME/.cache/inspect-ranges/images/focal-server-cloudimg-amd64.img}"
export XDG_STATE_HOME="$SPIKE/tmp/state"
IR="uv run inspect-ranges"
IRBIN="$ROOT/.venv/bin/inspect-ranges"
CACHE="$SPIKE/tmp/cache"
BUILDS="$SPIKE/tmp/builds"
LOC="$SPIKE/tmp/catalog-loc"
FLAGS=(--image-cache "$CACHE" --build-cache "$BUILDS" --cid-base 4130 --readiness-timeout 300)

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

echo "=== M1 the attack image publishes and the bare name resolves ==="
DB_OUT=$($IR daemon-bundle -o "$SPIKE/tmp/artifacts")
DAEMON_SHA=$(echo "$DB_OUT" | grep -o 'bundle sha256:[0-9a-f]*' | cut -d: -f2)
$IR images derive "$FOCAL" --sha256 "$(sha256sum "$FOCAL" | cut -d' ' -f1)" --name ubuntu-focal \
  --image-cache "$CACHE" --daemon-bundle "$SPIKE/tmp/artifacts" --daemon-sha256 "$DAEMON_SHA" >/dev/null
$IR images derive "$NOBLE" --sha256 "$(sha256sum "$NOBLE" | cut -d' ' -f1)" --name noble-range-guest \
  --image-cache "$CACHE" --daemon-bundle "$SPIKE/tmp/artifacts" --daemon-sha256 "$DAEMON_SHA" >/dev/null
(cd "$ATTACK_RANGE" && "$IRBIN" build "${FLAGS[@]}" --recipe-budget 1800 >"$SPIKE/tmp/m1attack.txt" 2>&1) \
  && grep -q "build OK" "$SPIKE/tmp/m1attack.txt" && ok "M1 the attack factory builds green" \
  || { bad "M1 attack build"; tail -10 "$SPIKE/tmp/m1attack.txt"; exit 1; }
(cd "$ATTACK_RANGE" && "$IRBIN" publish --guest box --as attack --to "$LOC" \
  --image-cache "$CACHE" --build-cache "$BUILDS" >/dev/null 2>&1) \
  && $IR images pull attack --from "$LOC" --image-cache "$CACHE" >/dev/null 2>&1 \
  && [[ -f "$CACHE/attack.qcow2" ]] \
  && ok "M1b attack publishes and pulls by bare name" || { bad "M1b"; exit 1; }

echo "=== M2 the fixture builds for real (6 targets + the chain proven) ==="
(cd "$RANGE" && "$IRBIN" build "${FLAGS[@]}" --recipe-budget 1800 >"$SPIKE/tmp/m2.txt" 2>&1) \
  && grep -q "build OK" "$SPIKE/tmp/m2.txt" && ok "M2 mhbench-equifax-small builds green" \
  || { bad "M2 build"; tail -15 "$SPIKE/tmp/m2.txt"; exit 1; }
grep -q "behavioral checks=3" "$SPIKE/tmp/m2.txt" \
  && ok "M2b the trio proved the Equifax chain against the captured artifacts" \
  || { bad "M2b behavioral lines"; grep -i behavioral "$SPIKE/tmp/m2.txt" | tail -4; }

echo "=== M3 the reference chain scores through a real eval (catalog-default attacker) ==="
export INSPECT_RANGES_IMAGE_CACHE="$CACHE"
export INSPECT_RANGES_BUILD_CACHE="$BUILDS"
if (cd "$ROOT" && uv run python "$SPIKE/mh_eval.py" "$RANGE" >"$SPIKE/tmp/m3.txt" 2>&1); then
  grep -E "^(PASS|FAIL)" "$SPIKE/tmp/m3.txt" || true
  ok "M3 the eval leg ran green (1.0 coverage, valid, catalog attacker)"
else
  bad "M3 eval"; tail -40 "$SPIKE/tmp/m3.txt"
fi

$IR down --all >/dev/null 2>&1 || true
echo
echo "$PASS passed, $FAIL failed"
exit $((FAIL > 0))

#!/bin/bash
# build-v1 slice 6 battery: the vulhub-zabbix conversion, end to end.
# Journey A made real on the actual example range: derive the ubuntu-focal
# golden, build (recipes compile zabbix 3.0.3, install MySQL 5.7, deploy the
# exact CVE frontend on php7.0), verify declarations, capture, manifest; then
# the build-aware runtime gate consumes the manifest (plan/render pass; the
# realized images boot per sample). Usage: ./run.sh [down]. See README.md.
set -euo pipefail
cd "$(dirname "$0")"
SPIKE="$PWD"
ROOT="$(cd ../../.. && pwd)"
RANGE="$ROOT/design/inspect-ranges/ranges/vulhub-zabbix"

ERA="${ERA:-$HOME/.cache/inspect-ranges/images/focal-server-cloudimg-amd64.img}"
export XDG_STATE_HOME="$SPIKE/tmp/state"
export INSPECT_RANGES_BUILD_CACHE="$SPIKE/tmp/builds"
export CAPTURE_CHUNK_MB=1  # beacons must land in a rotated (harvested) chunk for pcap corroboration
IR="uv run inspect-ranges"
IRBIN="$ROOT/.venv/bin/inspect-ranges"
CACHE="$SPIKE/tmp/cache"
FLAGS=(--image-cache "$CACHE" --build-cache "$SPIKE/tmp/builds" --cid-base 3700 --readiness-timeout 300)

if [[ "${1:-}" == "down" ]]; then
  (cd "$ROOT" && $IR down --all) || true
  exit 0
fi

grep -q vhost_vsock /proc/modules || { echo "need: sudo modprobe vhost_vsock"; exit 1; }
[[ -f "$ERA" ]] || { echo "missing focal vendor image $ERA"; exit 1; }

PASS=0; FAIL=0
ok()  { echo "PASS  $1"; PASS=$((PASS+1)); }
bad() { echo "FAIL  $1"; FAIL=$((FAIL+1)); }

exec 9>/tmp/inspect-ranges-battery.lock
flock 9

cd "$ROOT"
$IR down --all >/dev/null 2>&1 || true
rm -rf "$SPIKE/tmp" && mkdir -p "$SPIKE/tmp"

echo "=== derive the ubuntu-focal golden ==="
DB_OUT=$($IR daemon-bundle -o "$SPIKE/tmp/artifacts") \
  || { echo "daemon-bundle build failed"; exit 1; }
DAEMON_SHA=$(echo "$DB_OUT" | grep -o 'bundle sha256:[0-9a-f]*' | cut -d: -f2)
ERA_SHA=$(sha256sum "$ERA" | cut -d' ' -f1)
$IR images derive "$ERA" --sha256 "$ERA_SHA" --name ubuntu-focal \
  --image-cache "$CACHE" --daemon-bundle "$SPIKE/tmp/artifacts" --daemon-sha256 "$DAEMON_SHA" >/dev/null

echo "=== Z1 the gate refuses before the build ==="
if $IR plan "$RANGE" --image-cache "$CACHE" >"$SPIKE/tmp/z1.txt" 2>&1; then
  bad "Z1 unbuilt plan refused"
else
  grep -q "declares guest content but" "$SPIKE/tmp/z1.txt" && ok "Z1 range-not-built refusal before the build" || bad "Z1 refusal text"
fi

echo "=== Z2 the vulhub build (the Journey A moment) ==="
if (cd "$RANGE" && "$IRBIN" build "${FLAGS[@]}" --recipe-budget 2400 | tee "$SPIKE/tmp/z2.txt"); then
  grep -q "build OK" "$SPIKE/tmp/z2.txt" && ok "Z2 vulhub builds, verifies, captures, and writes its manifest" || bad "Z2 build OK line"
else
  bad "Z2 vulhub build"; tail -20 "$SPIKE/tmp/z2.txt"
fi
grep -q "verify    ok  service web/zabbix-web" "$SPIKE/tmp/z2.txt" \
  && grep -q "verify    ok  service web/php" "$SPIKE/tmp/z2.txt" \
  && grep -q "verify    ok  vulnerability web/CVE-2016-10134" "$SPIKE/tmp/z2.txt" \
  && ok "Z3 declarations verified incl. the CVE by linkage and php by dpkg version" || bad "Z3 verify lines"

echo "=== Z3b behavioral checks ran against the captured artifacts ==="
grep -q "behavioral.*check=reference" "$SPIKE/tmp/z2.txt" \
  && grep -q "behavioral.*check=insufficient" "$SPIKE/tmp/z2.txt" \
  && grep -q "behavioral.*check=forged" "$SPIKE/tmp/z2.txt" \
  && grep -q "behavioral checks=3" "$SPIKE/tmp/z2.txt" \
  && ok "Z3b reference/insufficient/forged all ran and the phase closed" || bad "Z3b behavioral lines"
grep -q '"check": "reference"' "$SPIKE/tmp/builds/vulhub-zabbix/manifest.json" \
  && grep -q '"status": "pass"' "$SPIKE/tmp/builds/vulhub-zabbix/manifest.json" \
  && ok "Z3c behavioral records landed in the manifest" || bad "Z3c manifest behavioral records"

echo "=== Z4 the gate consumes the manifest: plan and render pass ==="
$IR plan "$RANGE" --image-cache "$CACHE" >"$SPIKE/tmp/z4.txt" 2>&1 \
  && grep -qE "vulhub-zabbix-web-[0-9a-f]+\.qcow2" "$SPIKE/tmp/z4.txt" \
  && ok "Z4 plan passes post-build and resolves the realized images" || { bad "Z4 plan"; tail -5 "$SPIKE/tmp/z4.txt"; }
$IR render "$RANGE" -o "$SPIKE/tmp/bundle" --image-cache "$CACHE" --cid-base 3700 >"$SPIKE/tmp/z5.txt" 2>&1 \
  && ok "Z5 render passes and records bundle_sha256 in the manifest" || { bad "Z5 render"; tail -3 "$SPIKE/tmp/z5.txt"; }
grep -q '"bundle_sha256": "' "$SPIKE/tmp/builds/vulhub-zabbix/manifest.json" \
  && ok "Z6 wraps-by-reference: the manifest names its runtime bundle" || bad "Z6 bundle_sha256"

echo "=== Z7 the realized range boots and the stack serves ==="
$IR up "$SPIKE/tmp/bundle" --image-cache "$CACHE" >"$SPIKE/tmp/z7.txt" 2>&1 \
  && ok "Z7 up from the manifest-rendered bundle reaches ready" || { bad "Z7 up"; tail -5 "$SPIKE/tmp/z7.txt"; }
RC=$(docker ps --format '{{.Names}}' | grep -E '^ir-vulhub-zabbix-.*-range-1$' | head -1)
V6=$(docker exec "$RC" ip -6 addr show dev br-lab 2>/dev/null | grep -c inet6 || true)
SNOOP=$(docker exec "$RC" ip -d link show br-lab 2>/dev/null | grep -o 'mcast_snooping [01]' | head -1)
[[ "$V6" == "0" && "$SNOOP" == "mcast_snooping 0" ]] \
  && ok "Z7c segment silence: the lab bridge has no IPv6 address and snooping is off (PR #9 live)" \
  || bad "Z7c segment silence (inet6=$V6 snoop=$SNOOP)"
FRONT=$(cd "$ROOT" && uv run python design/spikes/_shared/chexec.py --boot "$SPIKE/tmp/bundle/boot.json" --project "${RC%-range-1}" --guest attacker --user root exec \
  "wget -q -O- http://web/index.php 2>/dev/null | grep -io 'zabbix' | head -1" || true)
[[ "$FRONT" == *[Zz]abbix* ]] && ok "Z8 the frontend serves to the attacker over the range network" || bad "Z8 frontend (got: $FRONT)"
BUILD_NS=$(cd "$ROOT" && uv run python -c "from inspect_ranges._build.orchestrate import default_build_nameserver; print(default_build_nameserver())")
SCRUB=$(cd "$ROOT" && uv run python design/spikes/_shared/chexec.py --boot "$SPIKE/tmp/bundle/boot.json" --guest web --user root exec \
  "grep -rq '$BUILD_NS' /etc/netplan/ 2>/dev/null && echo LEAK || echo CLEAN; test -f /var/lib/cloud/instance/boot-finished && echo CLOUDINIT-RAN" || true)
[[ "$SCRUB" == *CLEAN* && "$SCRUB" == *CLOUDINIT-RAN* ]] \
  && ok "Z8b realized guest carries no build nameserver and cloud-init re-seeded (got: $SCRUB)" \
  || bad "Z8b capture scrub (got: $SCRUB)"
$IR down --all >/dev/null 2>&1 || true

echo
echo "$PASS passed, $FAIL failed"
exit $((FAIL > 0))

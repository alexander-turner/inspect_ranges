#!/bin/bash
# realizer-v1 slice 2 battery: `inspect-ranges up` as the production applier.
# Derives its own v2 golden, renders at CID band 3000+, proves tamper refusal,
# missing-image and readiness-timeout failure modes (with console capture),
# duplicate-up refusal, the bundle spike's combined conformance checks, zero
# host artifacts, and --from-spec. Usage: ./run.sh [down]. See README.md.
set -euo pipefail
cd "$(dirname "$0")"
SPIKE="$PWD"
ROOT="$(cd ../../.. && pwd)"

VENDOR="${VENDOR:-$HOME/.cache/inspect-ranges/images/noble-server-cloudimg-amd64.img}"
export XDG_STATE_HOME="$SPIKE/tmp/state"   # project state isolated to the battery
IR="uv run inspect-ranges"
C() { (cd "$ROOT" && uv run python design/spikes/_shared/chexec.py --cid "$1" "$2" "${3-}"); }
WEB=3000 DB=3001 ROUTER=3002 AGENT=3003
CACHE="$SPIKE/tmp/cache"

if [[ "${1:-}" == "down" ]]; then
  (cd "$ROOT" && $IR down --all) || true
  exit 0
fi

grep -q vhost_vsock /proc/modules || { echo "need: sudo modprobe vhost_vsock"; exit 1; }
[[ -f "$VENDOR" ]] || { echo "missing vendor image $VENDOR"; exit 1; }

PASS=0; FAIL=0
ok()  { echo "PASS  $1"; PASS=$((PASS+1)); }
bad() { echo "FAIL  $1"; FAIL=$((FAIL+1)); }
guest() { C "$1" exec "$2"; }

exec 9>/tmp/inspect-ranges-battery.lock
flock 9

cd "$ROOT"
$IR down --all >/dev/null 2>&1 || true
rm -rf "$SPIKE/tmp" && mkdir -p "$SPIKE/tmp"

echo "=== build the daemon artifact and derive the battery golden (v3) ==="
$IR daemon-bundle -o "$SPIKE/tmp/artifacts" >/dev/null \
  || { echo "daemon-bundle build failed (install the pinned Go toolchain)"; exit 1; }
VENDOR_SHA=$(sha256sum "$VENDOR" | cut -d' ' -f1)
$IR images derive "$VENDOR" --sha256 "$VENDOR_SHA" --name up-core-guest --image-cache "$CACHE" --daemon-bundle "$SPIKE/tmp/artifacts" >/dev/null
$IR render design/spikes/up-core/spec.yaml -o "$SPIKE/tmp/bundle" --image-cache "$CACHE" --cid-base 3000

echo "=== U1 tamper refusal ==="
cp -r "$SPIKE/tmp/bundle" "$SPIKE/tmp/tampered"
printf ' ' >> "$SPIKE/tmp/tampered/netns/range.nft"
SPEC_SHA=$(python3 -c "import json;print(json.load(open('$SPIKE/tmp/bundle/manifest.json'))['spec_sha256'][:12])")
EXPECTED_PROJECT="ir-up-core-$SPEC_SHA"
if $IR up "$SPIKE/tmp/tampered" --image-cache "$CACHE" >"$SPIKE/tmp/u1.txt" 2>&1; then
  bad "tamper refusal"
else
  grep -q "verify-bundle" "$SPIKE/tmp/u1.txt" \
    && [[ -z "$(docker ps -aq --filter label=com.docker.compose.project=$EXPECTED_PROJECT 2>/dev/null)" ]] \
    && ok "tamper refused before acting" || bad "tamper refused before acting"
fi

echo "=== U2 missing image refuses, naming the guest ==="
mkdir -p "$SPIKE/tmp/empty-cache"
if $IR up "$SPIKE/tmp/bundle" --image-cache "$SPIKE/tmp/empty-cache" >"$SPIKE/tmp/u2.txt" 2>&1; then
  bad "missing image refusal"
else
  grep -q "verify-images.*guest 'web'" "$SPIKE/tmp/u2.txt" \
    && ok "missing image refused naming the guest" || { bad "missing image refusal"; cat "$SPIKE/tmp/u2.txt"; }
fi

echo "=== U3 up: bundle -> running, ready range ==="
T0=$(date +%s.%N)
$IR up "$SPIKE/tmp/bundle" --image-cache "$CACHE" | tee "$SPIKE/tmp/u3.txt"
T1=$(date +%s.%N)
PROJECT=$(grep -o 'ir-up-core-[0-9a-f]*' "$SPIKE/tmp/u3.txt" | head -1)
python3 -c "print(f'up -> enforced-ready: {$T1-$T0:.1f}s')"
grep -q "ready: project $PROJECT" "$SPIKE/tmp/u3.txt" && ok "up reports project and ready guests" || bad "up output"

echo "=== U4-U9 combined conformance (ACL v2 + DHCP + DNS) over the running range ==="
guest $AGENT 'timeout 3 bash -c "echo > /dev/tcp/10.80.20.10/22" 2>/dev/null; [ $? -eq 124 ] && echo dropped' | grep -q dropped \
  && ok "U4 deny carve-out beats later allow (agent->db:22 dropped)" || bad "U4"
guest $AGENT 'timeout 3 bash -c "echo > /dev/tcp/10.80.20.10/5432" 2>&1 | grep -q refused && echo rf' | grep -q rf \
  && ok "U5 network allow (agent->db:5432 refused-fast)" || bad "U5"
guest $WEB 'timeout 3 bash -c "echo > /dev/tcp/10.80.20.10/80" 2>&1 | grep -q refused && echo rf' | grep -q rf \
  && ok "U6 guest endpoint (web->db:80 refused-fast)" || bad "U6"
guest $AGENT 'timeout 3 bash -c "echo > /dev/tcp/10.80.20.10/80" 2>/dev/null; [ $? -eq 124 ] && echo dropped' | grep -q dropped \
  && ok "U6b guest endpoint excludes the agent (dropped)" || bad "U6b"
guest $AGENT 'timeout 3 bash -c "echo > /dev/tcp/10.80.20.10/8080" 2>&1 | grep -q refused && echo rf' | grep -q rf \
  && ok "U7 CIDR endpoint (agent/32 ->db:8080 refused-fast)" || bad "U7"
guest $WEB 'timeout 3 bash -c "echo > /dev/tcp/10.80.20.10/8080" 2>/dev/null; [ $? -eq 124 ] && echo dropped' | grep -q dropped \
  && ok "U7b CIDR endpoint excludes web (dropped)" || bad "U7b"
guest $AGENT 'ping -c1 -W2 10.80.20.10 >/dev/null && echo icmp' | grep -q icmp \
  && ok "U8 icmp allowed" || bad "U8"
guest $WEB 'ip -4 addr show eth0 | grep -q "10.80.10.10/24" && echo resv' | grep -q resv \
  && ok "U9 DHCP reservation delivers the allocated address" || bad "U9"
guest $AGENT 'getent hosts web | grep -q 10.80.10.10 && echo rec' | grep -q rec \
  && ok "U9b derived DNS record resolves" || bad "U9b"
guest $AGENT 'getent hosts files.corp.example | grep -q 10.80.10.200 && echo rec' | grep -q rec \
  && ok "U9c explicit DNS record resolves" || bad "U9c"

echo "=== U10 zero range artifacts on the host ==="
# bridges, named netns, and dnsmasq processes serving this bundle's confs must
# all be absent host-side (everything lives in the container's netns); host
# nft requires root, so the nft surface is covered by the bridge/netns checks
[[ "$(ip -o link | grep -c 'br-dmz\|br-internal')" -eq 0 ]] \
  && [[ -z "$(ip netns list 2>/dev/null | grep ir- || true)" ]] \
  && ! pgrep -f "netns/dnsmasq.*up-core" >/dev/null \
  && ok "U10 no range bridges, netns, or dnsmasq on the host" || bad "U10"

echo "=== U11 duplicate up refuses, naming the running project and the down command ==="
if $IR up "$SPIKE/tmp/bundle" --image-cache "$CACHE" >"$SPIKE/tmp/u11.txt" 2>&1; then
  bad "U11 duplicate refusal"
else
  grep -q "inspect-ranges down $PROJECT" "$SPIKE/tmp/u11.txt" \
    && ok "U11 duplicate up refused with the exact down command" || { bad "U11"; cat "$SPIKE/tmp/u11.txt"; }
fi

echo "=== down, then U12 --from-spec composes render+up ==="
$IR down "$PROJECT" >/dev/null
T0=$(date +%s.%N)
$IR up --from-spec design/spikes/up-core/spec.yaml --image-cache "$CACHE" --cid-base 3000 >"$SPIKE/tmp/u12.txt" 2>&1 \
  && grep -q "ready: project" "$SPIKE/tmp/u12.txt" \
  && ok "U12 --from-spec reaches ready" || { bad "U12"; tail -5 "$SPIKE/tmp/u12.txt"; }
$IR down "$PROJECT" >/dev/null

echo "=== U13 readiness timeout: names guest+stage, console captured, torn down ==="
$IR render design/spikes/up-core/timeout-spec.yaml -o "$SPIKE/tmp/timeout-bundle" --image-cache "$CACHE" --cid-base 3100
if $IR up "$SPIKE/tmp/timeout-bundle" --image-cache "$CACHE" --readiness-timeout 45 >"$SPIKE/tmp/u13.txt" 2>&1; then
  bad "U13 timeout did not fail"
else
  TPROJECT=$(ls "$XDG_STATE_HOME/inspect-ranges/projects" 2>/dev/null | grep up-timeout | head -1 || true)
  CONSOLE="$XDG_STATE_HOME/inspect-ranges/projects/$TPROJECT/consoles/mute.log"
  grep -q "readiness.*guest 'mute'" "$SPIKE/tmp/u13.txt" \
    && [[ -s "$CONSOLE" ]] \
    && [[ -z "$(docker ps -aq --filter label=com.docker.compose.project=$TPROJECT)" ]] \
    && ok "U13 timeout names guest+stage, console non-empty, project torn down" \
    || { bad "U13"; cat "$SPIKE/tmp/u13.txt"; ls -la "$XDG_STATE_HOME/inspect-ranges/projects/$TPROJECT" 2>/dev/null || true; }
fi

echo
echo "$PASS passed, $FAIL failed"
exit $((FAIL > 0))

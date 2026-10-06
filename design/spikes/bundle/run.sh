#!/bin/bash
# Bundle conformance: render the combined spec into a realization bundle with
# the production CLI, prove the applier refuses tampered bundles, apply purely
# from bundle contents, and run the combined battery (ACL v2 + DHCP + DNS).
# See README.md. Usage: ./run.sh [down]
set -euo pipefail
cd "$(dirname "$0")"

export IMAGE_CACHE="${IMAGE_CACHE:-$HOME/.cache/inspect-ranges/images}"
C="python3 ../vsock-exec/host/client.py"
# CIDs follow spec order: web=3 db=4 router=5 attacker=6
WEB=3 DB=4 ROUTER=5 AGENT=6

if [[ "${1:-}" == "down" ]]; then
  docker compose --project-name bundle --project-directory tmp/bundle down -v 2>/dev/null || true
  exit 0
fi

grep -q vhost_vsock /proc/modules || { echo "need: sudo modprobe vhost_vsock"; exit 1; }
[[ -f "$IMAGE_CACHE/noble-range-guest.qcow2" ]] || { echo "missing guest image; run ../net-compile/run.sh once first"; exit 1; }

echo "=== B0 render the bundle (production CLI) ==="
rm -rf tmp/bundle tmp/tampered
(cd ../../.. && uv run inspect-ranges render design/spikes/bundle/spec.yaml \
  -o design/spikes/bundle/tmp/bundle --image-cache "$IMAGE_CACHE")

echo "=== B1 tamper refusal (flip one byte, applier must refuse before acting) ==="
cp -r tmp/bundle tmp/tampered
printf ' ' >> tmp/tampered/netns/range.nft
if ./apply.sh tmp/tampered tampered >/dev/null 2>&1; then
  echo "FAIL tampered bundle was applied"; exit 1
else
  echo "PASS tamper-refused"
fi

echo "=== B2 apply purely from bundle contents ==="
T0=$(date +%s.%N)
./apply.sh tmp/bundle bundle
T1=$(date +%s.%N)
python3 -c "print(f'render+apply -> enforced-ready: {$T1-$T0:.1f}s')"

echo "=== combined battery ==="
echo "B3 deny carve-out beats later allow (agent->db:22, sshd listening):"
$C $AGENT exec 'timeout 3 bash -c "echo > /dev/tcp/10.80.20.10/22" 2>/dev/null; [ $? -eq 124 ] && echo PASS dropped'
echo "B4 network allow (agent->db:5432 refused-fast):"
$C $AGENT exec 'timeout 3 bash -c "echo > /dev/tcp/10.80.20.10/5432" 2>&1 | grep -q refused && echo PASS refused-fast'
echo "B5 guest endpoint (web->db:80 allowed; agent dropped):"
$C $WEB exec 'timeout 3 bash -c "echo > /dev/tcp/10.80.20.10/80" 2>&1 | grep -q refused && echo PASS refused-fast'
$C $AGENT exec 'timeout 3 bash -c "echo > /dev/tcp/10.80.20.10/80" 2>/dev/null; [ $? -eq 124 ] && echo PASS dropped'
echo "B6 CIDR endpoint (agent 10.80.10.3/32 ->db:8080 allowed; web dropped):"
$C $AGENT exec 'timeout 3 bash -c "echo > /dev/tcp/10.80.20.10/8080" 2>&1 | grep -q refused && echo PASS refused-fast'
$C $WEB exec 'timeout 3 bash -c "echo > /dev/tcp/10.80.20.10/8080" 2>/dev/null; [ $? -eq 124 ] && echo PASS dropped'
echo "B7 icmp allowed (agent->db ping):"
$C $AGENT exec 'ping -c1 -W2 10.80.20.10 >/dev/null && echo PASS icmp'
echo "B8 DHCP reservations deliver exactly the allocated addresses:"
$C $WEB exec 'ip -4 addr show eth0 | grep -q "10.80.10.10/24" && echo PASS web-reserved'
$C $AGENT exec 'ip -4 addr show eth0 | grep -q "10.80.10.3/24" && echo PASS agent-reserved'
echo "B9 range-served records (derived + explicit) resolve on the agent:"
$C $AGENT exec 'getent hosts web | grep -q 10.80.10.10 && echo PASS derived-record'
$C $AGENT exec 'getent hosts files.corp.example | grep -q 10.80.10.200 && echo PASS explicit-record'
echo "B10 host netns invisibility:"
[ "$(ip -o link | grep -c 'br-dmz\|br-internal')" -eq 0 ] && echo "PASS 0 range bridges on host"

echo "OK. Tear down with: ./run.sh down"

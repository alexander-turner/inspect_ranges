#!/bin/bash
# Routing conformance battery: compile the chained three-segment spec with the
# production stages (allocation, gateway election, nftables), boot it, verify
# gateway election and static routing hold across two hops on the wire.
# See README.md. Usage: ./run.sh [down]
set -euo pipefail
cd "$(dirname "$0")"

export IMAGE_CACHE="${IMAGE_CACHE:-$HOME/.cache/inspect-ranges/images}"
C="python3 ../vsock-exec/host/client.py"
# CIDs follow spec order: app=3 safe=4 r1=5 r2=6 attacker=7
APP=3 SAFE=4 R1=5 R2=6 AGENT=7

if [[ "${1:-}" == "down" ]]; then
  docker compose down -v
  exit 0
fi

grep -q vhost_vsock /proc/modules || { echo "need: sudo modprobe vhost_vsock"; exit 1; }
[[ -f "$IMAGE_CACHE/noble-range-guest.qcow2" ]] || { echo "missing guest image; run ../net-compile/run.sh once first"; exit 1; }

echo "=== validate + compile (production allocation + election + nftables) ==="
(cd ../../.. && uv run inspect-ranges validate design/spikes/routing/spec.yaml)
(cd ../../.. && uv run python design/spikes/routing/compile.py)

T0=$(date +%s.%N)
docker compose up -d --build --wait
docker compose exec -T range bash /render/boot-vms.sh >/dev/null 2>&1
for cid in 3 4 5 6 7; do $C $cid wait; done
for cid in 3 4 5 6 7; do
  $C $cid exec 'cloud-init status --wait >/dev/null 2>&1; echo done' >/dev/null
done
T1=$(date +%s.%N)
python3 -c "print(f'up -> enforced-ready (5 VMs, 3 segments): {$T1-$T0:.1f}s')"

echo "=== routing battery ==="
echo "R1 two-hop allowed path (agent->safe:443 through r1 and r2; refused = routed twice + accepted twice + stateful return):"
$C $AGENT exec 'timeout 3 bash -c "echo > /dev/tcp/10.80.30.10/443" 2>&1 | grep -q refused && echo PASS refused-fast'
echo "R2 two-hop default deny (agent->safe:22; sshd listening):"
$C $AGENT exec 'timeout 3 bash -c "echo > /dev/tcp/10.80.30.10/22" 2>/dev/null; [ $? -eq 124 ] && echo PASS dropped'
echo "R3a gateway election declared (app default route via r1, not r2):"
$C $APP exec 'ip route show default | grep -q "via 10.80.20.1" && echo PASS elected-r1'
echo "R3b gateway election functional (app->agent icmp crosses r1, which allows it; r2 would drop):"
$C $APP exec 'ping -c1 -W2 10.80.10.2 >/dev/null && echo PASS icmp-via-r1'
echo "R4 reverse chain default deny (safe->agent:22 despite listener):"
$C $SAFE exec 'timeout 3 bash -c "echo > /dev/tcp/10.80.10.2/22" 2>/dev/null; [ $? -eq 124 ] && echo PASS dropped'
echo "R5a static route live on r1 (vault via r2):"
$C $R1 exec 'ip route | grep -q "10.80.30.0/24 via 10.80.20.2" && echo PASS route-r1'
echo "R5b static route live on r2 (dmz via r1):"
$C $R2 exec 'ip route | grep -q "10.80.10.0/24 via 10.80.20.1" && echo PASS route-r2'
echo "R6 transit ruleset uses subnet match for the routed endpoint (on r2):"
$C $R2 exec 'nft list chain inet fw forward | grep -q "ip saddr 10.80.10.0/24" && echo PASS subnet-match'
echo "R7 host netns invisibility (3 bridges in container, 0 on host):"
[ "$(ip -o link | grep -c 'br-dmz\|br-core\|br-vault')" -eq 0 ] && echo "PASS 0 range bridges on host"

echo "OK. Tear down with: ./run.sh down"

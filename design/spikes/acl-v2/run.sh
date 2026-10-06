#!/bin/bash
# ACL v2 conformance battery: compile spec.yaml with the production compiler
# stages, boot the range, verify every v2 construct holds on the wire.
# See README.md. Usage: ./run.sh [down]
set -euo pipefail
cd "$(dirname "$0")"

export IMAGE_CACHE="${IMAGE_CACHE:-$HOME/.cache/inspect-ranges/images}"
C="python3 ../vsock-exec/host/client.py"
# CIDs follow spec order: web=3 db=4 router=5 attacker=6
WEB=3 DB=4 ROUTER=5 AGENT=6

if [[ "${1:-}" == "down" ]]; then
  docker compose down -v
  exit 0
fi

grep -q vhost_vsock /proc/modules || { echo "need: sudo modprobe vhost_vsock"; exit 1; }
[[ -f "$IMAGE_CACHE/noble-range-guest.qcow2" ]] || { echo "missing guest image; run ../net-compile/run.sh once first"; exit 1; }

echo "=== validate + compile (production allocation + nftables) ==="
(cd ../../.. && uv run inspect-ranges validate design/spikes/acl-v2/spec.yaml)
(cd ../../.. && uv run python design/spikes/acl-v2/compile.py)

T0=$(date +%s.%N)
docker compose up -d --build --wait
docker compose exec -T range bash /render/boot-vms.sh >/dev/null 2>&1
for cid in 3 4 5 6; do $C $cid wait; done
for cid in 3 4 5 6; do
  $C $cid exec 'cloud-init status --wait >/dev/null 2>&1; echo done' >/dev/null
done
T1=$(date +%s.%N)
python3 -c "print(f'up -> enforced-ready: {$T1-$T0:.1f}s')"

echo "=== ACL v2 battery ==="
echo "B1 network allow (agent->db:5432; refused = routed + accepted + stateful return):"
$C $AGENT exec 'timeout 3 bash -c "echo > /dev/tcp/10.80.20.10/5432" 2>&1 | grep -q refused && echo PASS refused-fast'
echo "B2 deny carve-out beats later allow (agent->db:22; sshd listening, first-match drops):"
$C $AGENT exec 'timeout 3 bash -c "echo > /dev/tcp/10.80.20.10/22" 2>/dev/null; [ $? -eq 124 ] && echo PASS dropped'
echo "B3a guest endpoint allows its guest (web->db:80):"
$C $WEB exec 'timeout 3 bash -c "echo > /dev/tcp/10.80.20.10/80" 2>&1 | grep -q refused && echo PASS refused-fast'
echo "B3b guest endpoint excludes others (agent->db:80):"
$C $AGENT exec 'timeout 3 bash -c "echo > /dev/tcp/10.80.20.10/80" 2>/dev/null; [ $? -eq 124 ] && echo PASS dropped'
echo "B4 icmp allowed cross-segment (agent->db ping):"
$C $AGENT exec 'ping -c1 -W2 10.80.20.10 >/dev/null && echo PASS icmp'
echo "B5a CIDR endpoint allows its /32 (agent 10.80.10.2 ->db:8080):"
$C $AGENT exec 'timeout 3 bash -c "echo > /dev/tcp/10.80.20.10/8080" 2>&1 | grep -q refused && echo PASS refused-fast'
echo "B5b CIDR endpoint excludes others (web->db:8080):"
$C $WEB exec 'timeout 3 bash -c "echo > /dev/tcp/10.80.20.10/8080" 2>/dev/null; [ $? -eq 124 ] && echo PASS dropped'
echo "B6 default deny asymmetry (db->web:22 despite listener):"
$C $DB exec 'timeout 3 bash -c "echo > /dev/tcp/10.80.10.10/22" 2>/dev/null; [ $? -eq 124 ] && echo PASS dropped'
echo "B7 same-segment L2 intact (agent->web ping):"
$C $AGENT exec 'ping -c1 -W2 10.80.10.10 >/dev/null && echo PASS reachable'
echo "B8 host netns invisibility (mid-run):"
[ "$(ip -o link | grep -c 'br-dmz\|br-internal')" -eq 0 ] && echo "PASS 0 range bridges on host"
echo "B9 rendered ruleset live on the router (deny line present, policy drop):"
$C $ROUTER exec 'nft list chain inet fw forward | grep -q "tcp dport 22 drop" && nft list chain inet fw forward | grep -q "policy drop" && echo PASS ruleset-live'

echo "OK. Tear down with: ./run.sh down"

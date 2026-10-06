#!/bin/bash
# Scoped-egress conformance battery: compile the NAT allowlist spec with the
# production stages, boot it next to a simulated-internet upstream, and verify
# exactly the allowlist leaves the range and the attacker override holds.
# See README.md. Usage: ./run.sh [down]
set -euo pipefail
cd "$(dirname "$0")"

export IMAGE_CACHE="${IMAGE_CACHE:-$HOME/.cache/inspect-ranges/images}"
C="python3 ../vsock-exec/host/client.py"
# CIDs follow spec order: workstation=3 attacker=4
WS=3 AGENT=4

if [[ "${1:-}" == "down" ]]; then
  docker compose down -v
  exit 0
fi

grep -q vhost_vsock /proc/modules || { echo "need: sudo modprobe vhost_vsock"; exit 1; }
[[ -f "$IMAGE_CACHE/noble-range-guest.qcow2" ]] || { echo "missing guest image; run ../net-compile/run.sh once first"; exit 1; }

echo "=== validate + compile (production allocation + nat election + egress ruleset) ==="
(cd ../../.. && uv run inspect-ranges validate design/spikes/egress/spec.yaml)
(cd ../../.. && uv run python design/spikes/egress/compile.py)

T0=$(date +%s.%N)
docker compose up -d --build --wait
docker compose exec -T range bash /render/boot-vms.sh >/dev/null 2>&1
for cid in 3 4; do $C $cid wait; done
for cid in 3 4; do
  $C $cid exec 'cloud-init status --wait >/dev/null 2>&1; echo done' >/dev/null
done
T1=$(date +%s.%N)
python3 -c "print(f'up -> enforced-ready: {$T1-$T0:.1f}s')"

echo "=== egress battery ==="
echo "E1 allowlisted flow completes (workstation->198.51.100.7:443, live listener, NAT out and back):"
$C $WS exec 'timeout 3 bash -c "echo > /dev/tcp/198.51.100.7/443" && echo PASS connected'
echo "E2 exactly the allowlist (workstation->198.51.100.7:80, listener up, not allowed):"
$C $WS exec 'timeout 3 bash -c "echo > /dev/tcp/198.51.100.7/80" 2>/dev/null; [ $? -eq 124 ] && echo PASS dropped'
echo "E3 attacker override (attacker egress none beats the network allowlist, same :443):"
$C $AGENT exec 'timeout 3 bash -c "echo > /dev/tcp/198.51.100.7/443" 2>/dev/null; [ $? -eq 124 ] && echo PASS dropped'
echo "E4 udp allowlist entry rendered live in the range netns:"
docker compose exec -T range sh -c 'nft list chain inet rangehost forward | grep -q "udp dport 123" && echo PASS udp-rule-live'
echo "E5 NAT live (masquerade on the uplink):"
docker compose exec -T range sh -c 'nft list table ip rangenat | grep -q masquerade && echo PASS masquerade-live'
echo "E6 same-segment unaffected (attacker->workstation ping):"
$C $AGENT exec 'ping -c1 -W2 10.90.10.10 >/dev/null && echo PASS reachable'
echo "E7 gateway is the hypervisor bridge (workstation default route via 10.90.10.1):"
$C $WS exec 'ip route show default | grep -q "via 10.90.10.1" && echo PASS nat-gateway'
echo "E8 host netns invisibility (bridge inside the container only):"
[ "$(ip -o link | grep -c 'br-corp')" -eq 0 ] && echo "PASS 0 range bridges on host"

echo "OK. Tear down with: ./run.sh down"

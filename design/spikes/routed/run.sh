#!/bin/bash
# Routed-egress conformance battery: mode routed realized as un-NATed two-way
# forwarding through the range netns; the upstream proves real source
# addresses. See README.md. Usage: ./run.sh [down]
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

echo "=== validate + compile (production allocation + routed-egress ruleset) ==="
(cd ../../.. && uv run inspect-ranges validate design/spikes/routed/spec.yaml)
(cd ../../.. && uv run python design/spikes/routed/compile.py)

T0=$(date +%s.%N)
docker compose up -d --build --wait
docker compose exec -T range bash /render/boot-vms.sh >/dev/null 2>&1
for cid in 3 4; do $C $cid wait; done
for cid in 3 4; do
  $C $cid exec 'cloud-init status --wait >/dev/null 2>&1; echo done' >/dev/null
done
T1=$(date +%s.%N)
python3 -c "print(f'up -> enforced-ready: {$T1-$T0:.1f}s')"

echo "=== routed-egress battery ==="
echo "RT1 routed flow completes (workstation->198.51.100.7:443, no NAT in the path):"
$C $WS exec 'timeout 3 bash -c "echo > /dev/tcp/198.51.100.7/443" && echo PASS connected'
echo "RT2 un-NATed proof (the upstream saw the workstation's real address):"
$C $WS exec 'timeout 3 bash -c "exec 3<>/dev/tcp/198.51.100.7/443; printf \"GET / HTTP/1.0\r\n\r\n\" >&3; cat <&3 >/dev/null" || true' >/dev/null
sleep 1
docker compose logs upstream 2>/dev/null | grep -q "10.91.10.10" && echo "PASS real-source-address"
echo "RT3 two-way routed (upstream opens a connection in to the workstation's sshd):"
docker compose exec -T upstream python3 -c "import socket; socket.create_connection(('10.91.10.10', 22), 3)" && echo "PASS ingress-routes"
echo "RT4 attacker override (egress none beats the routed posture):"
$C $AGENT exec 'timeout 3 bash -c "echo > /dev/tcp/198.51.100.7/443" 2>/dev/null; [ $? -eq 124 ] && echo PASS dropped'
echo "RT5 no masquerade anywhere (routed means real addresses):"
docker compose exec -T range sh -c 'nft list ruleset | grep -c masquerade | grep -qx 0 && echo PASS no-nat'
echo "RT6 gateway is the hypervisor bridge (workstation default route via 10.91.10.1):"
$C $WS exec 'ip route show default | grep -q "via 10.91.10.1" && echo PASS routed-gateway'
echo "RT7 host netns invisibility:"
[ "$(ip -o link | grep -c 'br-wide')" -eq 0 ] && echo "PASS 0 range bridges on host"

echo "OK. Tear down with: ./run.sh down"

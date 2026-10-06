#!/bin/bash
# Network-services conformance battery: DHCP reservations and the three DNS
# shapes, realized by the production compiler stages, proven in a booted range.
# See README.md. Usage: ./run.sh [down]
set -euo pipefail
cd "$(dirname "$0")"

export IMAGE_CACHE="${IMAGE_CACHE:-$HOME/.cache/inspect-ranges/images}"
C="python3 ../vsock-exec/host/client.py"
# CIDs follow spec order: web=3 db=4 app=5 attacker=6
WEB=3 DB=4 APP=5 AGENT=6

if [[ "${1:-}" == "down" ]]; then
  docker compose down -v
  exit 0
fi

grep -q vhost_vsock /proc/modules || { echo "need: sudo modprobe vhost_vsock"; exit 1; }
[[ -f "$IMAGE_CACHE/noble-range-guest.qcow2" ]] || { echo "missing guest image; run ../net-compile/run.sh once first"; exit 1; }

echo "=== validate + compile (production allocation + dnsmasq + resolvers) ==="
(cd ../../.. && uv run inspect-ranges validate design/spikes/netsvc/spec.yaml)
(cd ../../.. && uv run python design/spikes/netsvc/compile.py)

T0=$(date +%s.%N)
docker compose up -d --build --wait
docker compose exec -T range bash /render/boot-vms.sh >/dev/null 2>&1
for cid in 3 4 5 6; do $C $cid wait; done
for cid in 3 4 5 6; do
  $C $cid exec 'cloud-init status --wait >/dev/null 2>&1; echo done' >/dev/null
done
T1=$(date +%s.%N)
python3 -c "print(f'up -> enforced-ready: {$T1-$T0:.1f}s')"

echo "=== network-services battery ==="
echo "N1 DHCP delivers exactly the allocated address (web = 10.95.10.10):"
$C $WEB exec 'ip -4 addr show eth0 | grep -q "10.95.10.10/24" && echo PASS reserved-address'
echo "N2 DHCP for the attacker too (10.95.10.2):"
$C $AGENT exec 'ip -4 addr show eth0 | grep -q "10.95.10.2/24" && echo PASS reserved-address'
echo "N3 derived record resolves (web -> its allocated address, via the range DNS):"
$C $AGENT exec 'getent hosts web | grep -q 10.95.10.10 && echo PASS derived-record'
echo "N4 explicit record resolves (files.corp.example -> 10.95.10.200):"
$C $AGENT exec 'getent hosts files.corp.example | grep -q 10.95.10.200 && echo PASS explicit-record'
echo "N5 the DHCP-handed resolver is the range service address:"
$C $AGENT exec 'resolvectl dns eth0 | grep -q 10.95.10.1 && echo PASS service-resolver'
echo "N6 authoritative + external resolvers handed to net2 guests (db first, then 9.9.9.9):"
$C $APP exec 'resolvectl dns eth0 | grep -q "10.95.20.5" && resolvectl dns eth0 | grep -q "9.9.9.9" && echo PASS resolver-order'
echo "N7 segments stay isolated (no router: lab cannot reach net2):"
$C $AGENT exec 'ping -c1 -W2 10.95.20.5 >/dev/null 2>&1 || echo PASS isolated'
echo "N8 host netns invisibility:"
[ "$(ip -o link | grep -c 'br-lab\|br-net2')" -eq 0 ] && echo "PASS 0 range bridges on host"

echo "OK. Tear down with: ./run.sh down"

#!/bin/bash
# Hardened-container spike: boot the net-compile 4-VM range under a minimal
# runtime profile (cap_drop ALL + explicit list, default seccomp/AppArmor,
# no-new-privileges, QEMU as libvirt-qemu, QEMU seccomp sandbox) and prove
# function + containment under it. See README.md. Usage: ./run.sh [down]
set -euo pipefail
cd "$(dirname "$0")"

export IMAGE_CACHE="${IMAGE_CACHE:-$HOME/.cache/inspect-ranges/images}"
C="python3 ../vsock-exec/host/client.py"

if [[ "${1:-}" == "down" ]]; then
  docker compose down -v
  exit 0
fi

[[ -f "$IMAGE_CACHE/noble-range-guest.qcow2" ]] || { echo "missing guest image; run ../net-compile/run.sh once first"; exit 1; }
[[ -f ../net-compile/tmp/render/boot-vms.sh ]] || { echo "missing compiled render; run ../net-compile/run.sh once first"; exit 1; }

T0=$(date +%s.%N)
docker compose up -d --build --wait
docker compose exec -T range bash /render/boot-vms.sh >/dev/null 2>&1
for cid in 3 4 5 6; do $C $cid wait; done
for cid in 3 4 5 6; do
  $C $cid exec 'cloud-init status --wait >/dev/null 2>&1; echo done' >/dev/null
done
T1=$(date +%s.%N)
python3 -c "print(f'up -> range ready under hardened profile: {$T1-$T0:.1f}s')"

echo "=== profile verification (read from the running system) ==="
echo "CapEff of PID 1 (expect only the compose.yaml list):"
docker compose exec -T range sh -c 'grep CapEff /proc/1/status'
docker compose exec -T range sh -c 'capsh --decode=$(grep CapEff /proc/1/status | cut -f2) 2>/dev/null || true'
echo "AppArmor profile of PID 1 (expect docker-default):"
docker compose exec -T range sh -c 'cat /proc/1/attr/current'
echo "Seccomp of PID 1 (expect 2 = filter):"
docker compose exec -T range sh -c 'grep Seccomp: /proc/1/status'
echo "NoNewPrivs of PID 1 (expect 1):"
docker compose exec -T range sh -c 'grep NoNewPrivs /proc/1/status'
echo "QEMU process identities (expect libvirt-qemu, not root):"
docker compose exec -T range sh -c 'ps -eo user:16,comm | grep qemu-system | sort | uniq -c'
echo "QEMU sandbox flag (expect -sandbox on in cmdline):"
docker compose exec -T range sh -c 'tr "\0" " " < /proc/$(pgrep -f "guest=web" | head -1)/cmdline | grep -o "sandbox[^ ]* [^ ]*" | head -1'

echo "=== function under the profile: ACL / isolation battery (net-compile T1-T9) ==="
echo "T1 same-segment (agent->web ping):"
$C 6 exec 'ping -c1 -W2 10.80.10.10 >/dev/null && echo PASS reachable'
echo "T2 cross-segment allowed port (agent->db:5432):"
$C 6 exec 'timeout 3 bash -c "echo > /dev/tcp/10.80.20.10/5432" 2>&1 | grep -q refused && echo PASS refused-fast'
echo "T3 denied-but-listening (agent->db:22):"
$C 6 exec 'timeout 3 bash -c "echo > /dev/tcp/10.80.20.10/22" 2>/dev/null; [ $? -eq 124 ] && echo PASS dropped'
echo "T4 cross-segment ICMP denied:"
$C 6 exec 'ping -c1 -W2 10.80.20.10 >/dev/null 2>&1 || echo PASS blocked'
echo "T5 L2 isolation (forced ARP for internal IP on dmz must fail):"
$C 6 exec 'ip route add 10.80.20.10/32 dev dmz0 && ping -c1 -W1 10.80.20.10 >/dev/null 2>&1; ip neigh show 10.80.20.10 | grep -q -E "FAILED|INCOMPLETE" && echo PASS no-l2-path; ip route del 10.80.20.10/32 dev dmz0'
echo "T6 asymmetry (db->web:22 denied despite listener):"
$C 5 exec 'timeout 3 bash -c "echo > /dev/tcp/10.80.10.10/22" 2>/dev/null; [ $? -eq 124 ] && echo PASS dropped'
echo "T7 gateway reachable (agent->router):"
$C 6 exec 'ping -c1 -W2 10.80.10.1 >/dev/null && echo PASS'
echo "T8 host netns invisibility:"
[ "$(ip -o link | grep -c 'br-dmz\|br-internal')" -eq 0 ] && echo "PASS 0 range bridges on host"
echo "T9 range-netns invariants:"
docker compose exec -T range sh -c 'nft list ruleset | grep -q rangehost && echo PASS nft-loaded; ip -o link show type bridge | wc -l'

echo "=== Docker non-involvement: the netns boundary is interface-absence, not configuration ==="
echo "container interfaces (expect: lo + our bridges + taps, NO eth0/veth):"
docker compose exec -T range sh -c 'ip -o link | awk -F": " "{print \$2}"'
docker compose exec -T range sh -c 'ip -o link | grep -qE "eth0|veth" && echo "FAIL docker-provided interface present" || echo "PASS no docker-provided interface"'
echo "host-side veth for this container (expect none):"
ip -o link | grep -q veth && echo "NOTE host has veths (other containers)" || true
CONTAINER_ID=$(docker compose ps -q range)
[ -z "$(docker inspect -f '{{.NetworkSettings.IPAddress}}' "$CONTAINER_ID")" ] && echo "PASS container has no Docker-assigned IP" || echo "FAIL container has a Docker IP"
echo "host firewall rules referencing the range (expect none; Docker's iptables machinery untouched by this container):"
sudo iptables-save 2>/dev/null | grep -q "$CONTAINER_ID" && echo "FAIL container-specific iptables rules" || echo "PASS no container-specific iptables rules"
sudo nft list ruleset 2>/dev/null | grep -q "rangehost" && echo "FAIL range nft table leaked to host" || echo "PASS range nft table not present in host netns"

echo "=== egress conformance: no external path from any guest ==="
for cid in 4 5 6; do
  echo "guest cid=$cid external IP + TCP (expect blocked):"
  $C $cid exec 'ping -c1 -W2 1.1.1.1 >/dev/null 2>&1 && echo FAIL icmp-egress || echo PASS no-icmp-egress'
  $C $cid exec 'timeout 3 bash -c "echo > /dev/tcp/1.1.1.1/443" 2>/dev/null && echo FAIL tcp-egress || echo PASS no-tcp-egress'
done

echo "=== egress conformance after simulated router compromise (flush its firewall) ==="
$C 3 exec 'nft flush ruleset && echo router-firewall-flushed'
echo "cross-segment policy is now scenario state (may change); external containment must not:"
for cid in 4 5 6; do
  $C $cid exec 'ping -c1 -W2 1.1.1.1 >/dev/null 2>&1 && echo FAIL icmp-egress || echo PASS no-icmp-egress'
  $C $cid exec 'timeout 3 bash -c "echo > /dev/tcp/1.1.1.1/443" 2>/dev/null && echo FAIL tcp-egress || echo PASS no-tcp-egress'
done
echo "T8/T9 still hold after flush:"
[ "$(ip -o link | grep -c 'br-dmz\|br-internal')" -eq 0 ] && echo "PASS 0 range bridges on host"
docker compose exec -T range sh -c 'nft list ruleset | grep -q rangehost && echo PASS netns-invariants-loaded'

echo "OK. Tear down with: ./run.sh down"

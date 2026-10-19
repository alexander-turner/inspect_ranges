#!/bin/bash
# Networking spike: compile spec.yaml -> networking artifacts -> booted
# two-segment topology (router, web, db, agent) -> verify declared ACLs hold.
# See README.md. Usage: ./run.sh [down]
set -euo pipefail
cd "$(dirname "$0")"

export IMAGE_CACHE="${IMAGE_CACHE:-$HOME/.cache/inspect-ranges/images}"
C="python3 ../vsock-exec/host/client.py"

if [[ "${1:-}" == "down" ]]; then
  docker compose down -v
  exit 0
fi

grep -q vhost_vsock /proc/modules || { echo "need: sudo modprobe vhost_vsock"; exit 1; }

# derived guest image: vsockd baked in, cloud-init ENABLED (per-VM seeds carry
# the compiled network config), wait-online masked. NOTE: the backing file
# reference must be RELATIVE — the cache mounts at /images in the container.
GUEST="$IMAGE_CACHE/ubuntu-noble.qcow2"
if [[ ! -f "$GUEST" ]]; then
  cat > tmp/vsockd.service <<'EOF'
[Unit]
Description=vsock exec daemon (spike)
[Service]
ExecStart=/usr/bin/python3 /opt/vsockd.py
Restart=always
[Install]
WantedBy=multi-user.target
EOF
  (cd "$IMAGE_CACHE" && qemu-img create -f qcow2 -F qcow2 \
    -b noble-server-cloudimg-amd64.img ubuntu-noble.qcow2 10G >/dev/null)
  virt-customize -a "$GUEST" \
    --no-network --mkdir /opt \
    --copy-in ../vsock-exec/guest/vsockd.py:/opt \
    --chmod 0755:/opt/vsockd.py \
    --copy-in tmp/vsockd.service:/etc/systemd/system \
    --link /etc/systemd/system/vsockd.service:/etc/systemd/system/multi-user.target.wants/vsockd.service \
    --link /dev/null:/etc/systemd/system/systemd-networkd-wait-online.service
fi

echo "=== compile: spec.yaml -> tmp/render ==="
(cd ../../.. && uv run python design/spikes/net-compile/compile.py)
find tmp/render -type f | sort

T0=$(date +%s.%N)
docker compose up -d --build --wait
docker compose exec range bash /render/boot-vms.sh >/dev/null 2>&1
for cid in 3 4 5 6; do $C $cid wait; done
T1=$(date +%s.%N)
# readiness must gate on cloud-init, not daemon-up: the router's generated
# nftables/forwarding load in cloud-init's final stage
for cid in 3 4 5 6; do
  $C $cid exec 'cloud-init status --wait >/dev/null 2>&1; echo cloud-init done' >/dev/null
done
T2=$(date +%s.%N)
python3 -c "print(f'up -> daemons: {$T1-$T0:.1f}s; -> cloud-init complete (range ready): {$T2-$T0:.1f}s')"

echo "=== ACL / isolation battery ==="
echo "T1 same-segment (agent->web ping):"
$C 6 exec 'ping -c1 -W2 10.80.10.10 >/dev/null && echo PASS reachable'
echo "T2 cross-segment allowed port (agent->db:5432; refused = routed + allowed + return path):"
$C 6 exec 'timeout 3 bash -c "echo > /dev/tcp/10.80.20.10/5432" 2>&1 | grep -q refused && echo PASS refused-fast'
echo "T3 denied-but-listening (agent->db:22; sshd up, ACL drops):"
$C 6 exec 'timeout 3 bash -c "echo > /dev/tcp/10.80.20.10/22" 2>/dev/null; [ $? -eq 124 ] && echo PASS dropped'
echo "T4 cross-segment ICMP denied:"
$C 6 exec 'ping -c1 -W2 10.80.20.10 >/dev/null 2>&1 || echo PASS blocked'
echo "T5 L2 isolation (force ARP for internal IP on dmz; must fail):"
$C 6 exec 'ip route add 10.80.20.10/32 dev dmz0 && ping -c1 -W1 10.80.20.10 >/dev/null 2>&1; ip neigh show 10.80.20.10 | grep -q -E "FAILED|INCOMPLETE" && echo PASS no-l2-path; ip route del 10.80.20.10/32 dev dmz0'
echo "T6 asymmetry (db->web:22; internal->dmz denied despite listener):"
$C 5 exec 'timeout 3 bash -c "echo > /dev/tcp/10.80.10.10/22" 2>/dev/null; [ $? -eq 124 ] && echo PASS dropped'
echo "T7 gateway reachable (agent->router):"
$C 6 exec 'ping -c1 -W2 10.80.10.1 >/dev/null && echo PASS'
echo "T8 host netns invisibility (mid-run):"
[ "$(ip -o link | grep -c 'br-dmz\|br-internal')" -eq 0 ] && echo "PASS 0 range bridges on host"
echo "T9 range-netns invariants (generated nft loaded, 2 bridges in container):"
docker compose exec range sh -c 'nft list ruleset | grep -q rangehost && echo PASS nft-loaded; ip -o link show type bridge | wc -l'

echo "OK. Tear down with: ./run.sh down"

#!/bin/bash
# Realize the compiled networking artifacts inside this container's netns:
# bridges from bridges.txt, hypervisor-side invariants from range-netns.nft.
set -euo pipefail

while read -r name; do
  ip link add "$name" type bridge
  ip link set "$name" up
done < /render/bridges.txt
# no IPs on bridges: the hypervisor is not addressable from any segment

nft -f /render/range-netns.nft

mkdir -p /run/libvirt
/usr/sbin/virtlogd -d
/usr/sbin/libvirtd -d
until virsh -c qemu:///system version >/dev/null 2>&1; do sleep 0.2; done
touch /run/range-ready
echo "range container ready: $(wc -l < /render/bridges.txt) bridges, netns nftables loaded"
exec sleep infinity

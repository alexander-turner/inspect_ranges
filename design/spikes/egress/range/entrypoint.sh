#!/bin/bash
# Realize the compiled networking artifacts inside this container's netns:
# bridges from bridges.txt, hypervisor-side invariants from range-netns.nft.
set -euo pipefail

while read -r name; do
  ip link add "$name" type bridge
  ip link set "$name" up
done < /render/bridges.txt
# bridges carry no IP, with one exception: a routerless nat network's bridge
# is its gateway, carrying the address the allocator reserved for it
if [[ -f /render/nat-gateways.txt ]]; then
  while read -r dev addr; do
    ip addr add "$addr" dev "$dev"
  done < /render/nat-gateways.txt
fi

nft -f /render/range-netns.nft

mkdir -p /run/libvirt
/usr/sbin/virtlogd -d
/usr/sbin/libvirtd -d
until virsh -c qemu:///system version >/dev/null 2>&1; do sleep 0.2; done
touch /run/range-ready
echo "range container ready: $(wc -l < /render/bridges.txt) bridges, netns nftables loaded"
exec sleep infinity

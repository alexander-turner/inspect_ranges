#!/bin/bash
# Realize the compiled networking artifacts inside this container's netns:
# bridges from bridges.txt, hypervisor-side invariants from range-netns.nft.
set -euo pipefail

while read -r name; do
  ip link add "$name" type bridge
  ip link set "$name" up
done < /render/bridges.txt
# bridges carry no IP except where the allocator reserved a hypervisor
# address (nat/routed gateway, or the dnsmasq service for dhcp/records)
if [[ -f /render/hypervisor-addresses.txt ]]; then
  while read -r dev addr; do
    ip addr add "$addr" dev "$dev"
  done < /render/hypervisor-addresses.txt
fi
# range-served dhcp/dns: one dnsmasq per rendered per-network conf
if [[ -d /render/dnsmasq ]]; then
  for conf in /render/dnsmasq/*.conf; do
    [[ -e "$conf" ]] || continue
    dnsmasq --conf-file="$conf" --pid-file="/run/dnsmasq-$(basename "$conf" .conf).pid"
  done
fi

nft -f /render/range-netns.nft

mkdir -p /run/libvirt
/usr/sbin/virtlogd -d
/usr/sbin/libvirtd -d
until virsh -c qemu:///system version >/dev/null 2>&1; do sleep 0.2; done
touch /run/range-ready
echo "range container ready: $(wc -l < /render/bridges.txt) bridges, netns nftables loaded"
exec sleep infinity

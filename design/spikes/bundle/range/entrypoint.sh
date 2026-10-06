#!/bin/bash
# The applier's in-container half: realize the bundle's netns artifacts in the
# order the render contract specifies (bridges -> addresses -> dnsmasq -> nft),
# then start libvirtd. The bundle is mounted read-only at /render.
set -euo pipefail

while read -r name; do
  ip link add "$name" type bridge
  ip link set "$name" up
done < /render/netns/bridges.txt

# bridges carry no IP except where the allocator reserved a hypervisor address
# (nat/routed gateway, or the dnsmasq service for dhcp/records networks)
if [[ -s /render/netns/addresses.txt ]]; then
  while read -r dev addr; do
    ip addr add "$addr" dev "$dev"
  done < /render/netns/addresses.txt
fi

if [[ -d /render/netns/dnsmasq ]]; then
  for conf in /render/netns/dnsmasq/*.conf; do
    [[ -e "$conf" ]] || continue
    dnsmasq --conf-file="$conf" --pid-file="/run/dnsmasq-$(basename "$conf" .conf).pid"
  done
fi

nft -f /render/netns/range.nft

mkdir -p /run/libvirt
/usr/sbin/virtlogd -d
/usr/sbin/libvirtd -d
until virsh -c qemu:///system version >/dev/null 2>&1; do sleep 0.2; done
touch /run/range-ready
echo "range container ready: $(wc -l < /render/netns/bridges.txt) bridges, netns artifacts applied"
exec sleep infinity

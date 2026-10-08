#!/bin/bash
# The applier's in-container half: realize the bundle's netns artifacts in the
# order the render contract specifies (bridges -> addresses -> dnsmasq -> nft),
# then start libvirtd. The bundle mounts read-only at /render. Device-node
# ownership for the non-root QEMU: the nodes docker creates in /dev are
# container-local, so chowning them touches nothing on the host.
set -euo pipefail

chown root:kvm /dev/kvm /dev/vhost-net /dev/vhost-vsock
chmod 660 /dev/kvm /dev/vhost-net /dev/vhost-vsock

while read -r name; do
  ip link add "$name" type bridge
  ip link set "$name" up
done < /render/netns/bridges.txt
# no IPs on bridges except where the allocator reserved a hypervisor address
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

# serial consoles land here from first boot (QEMU runs as libvirt-qemu)
mkdir -p /scratch/console
chown libvirt-qemu:kvm /scratch/console

mkdir -p /run/libvirt
/usr/sbin/virtlogd -d
/usr/sbin/libvirtd -d
until virsh -c qemu:///system version >/dev/null 2>&1; do sleep 0.2; done
touch /run/range-ready
echo "hardened range container ready: $(wc -l < /render/netns/bridges.txt) bridges, netns artifacts applied"
exec sleep infinity

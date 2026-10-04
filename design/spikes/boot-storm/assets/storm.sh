#!/bin/bash
# Run inside one range container: a 2-VM mini range (bridge, per-VM cloud-init
# seeds with static addressing, vsock daemons) — the storm unit. CID_BASE
# makes vsock CIDs host-unique per range.
set -euxo pipefail

CID_BASE="${CID_BASE:?}"

ip link add br-storm type bridge 2>/dev/null || true
ip link set br-storm up

mkdir -p /tmp/seed
for i in 0 1; do
  vm="vm$i"
  cid=$((CID_BASE + i))
  mac=$(printf '52:54:00:70:%02x:%02x' $(( (CID_BASE / 256) % 256 )) $(( (CID_BASE + i) % 256 )))
  cat > /tmp/seed/network-config <<EOF
version: 2
ethernets:
  lab0:
    match: { macaddress: "$mac" }
    set-name: lab0
    addresses: [10.99.0.$((10 + i))/24]
EOF
  printf '#cloud-config\nhostname: %s\n' "$vm" > /tmp/seed/user-data
  printf 'instance-id: storm-%s-%s\n' "$CID_BASE" "$vm" > /tmp/seed/meta-data
  virsh -c qemu:///system destroy "$vm" 2>/dev/null || true
  virsh -c qemu:///system undefine "$vm" 2>/dev/null || true
  rm -f "/scratch/$vm.qcow2" "/scratch/$vm-seed.iso"
  qemu-img create -f qcow2 -F qcow2 -b /images/noble-range-guest.qcow2 "/scratch/$vm.qcow2" 10G
  cloud-localds -N /tmp/seed/network-config "/scratch/$vm-seed.iso" /tmp/seed/user-data /tmp/seed/meta-data
  virt-install \
    --connect qemu:///system \
    --name "$vm" \
    --memory 1024 --vcpus 1 \
    --cpu host-passthrough \
    --disk "path=/scratch/$vm.qcow2,format=qcow2,bus=virtio" \
    --disk "path=/scratch/$vm-seed.iso,device=cdrom" \
    --network "bridge=br-storm,model=virtio,mac=$mac" \
    --vsock cid.address="$cid" \
    --osinfo ubuntu24.04 \
    --import --graphics none --noautoconsole
done

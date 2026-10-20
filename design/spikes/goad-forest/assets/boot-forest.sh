#!/bin/bash
# Run inside the range container: one flat bridge (the range.yaml's lab
# network) carrying three Windows guests (golden clones; names from the plan)
# and the Linux attacker box (vsock CID 9, cloud-init seed from /plan).
set -euxo pipefail

source /plan/plan.env

ip link add "$BRIDGE" type bridge 2>/dev/null || true
ip link set "$BRIDGE" up

for vm in dc01 dc02 srv02; do
  virsh -c qemu:///system destroy "$vm" 2>/dev/null || true
  virsh -c qemu:///system undefine "$vm" 2>/dev/null || true
  rm -f "/scratch/$vm.qcow2"
  qemu-img create -f qcow2 -F qcow2 -b /scratch/win-golden.qcow2 "/scratch/$vm.qcow2" 40G
  virt-install \
    --connect qemu:///system \
    --name "$vm" \
    --memory 4096 --vcpus 2 \
    --cpu host-passthrough \
    --disk "path=/scratch/$vm.qcow2,format=qcow2,bus=virtio" \
    --network "bridge=$BRIDGE,model=virtio" \
    --channel unix,target.type=virtio,target.name=org.qemu.guest_agent.0 \
    --boot hd \
    --graphics vnc,listen=127.0.0.1 \
    --osinfo win2k22 \
    --import --noautoconsole
done

virsh -c qemu:///system destroy attacker 2>/dev/null || true
virsh -c qemu:///system undefine attacker 2>/dev/null || true
rm -f /scratch/attacker.qcow2 /scratch/attacker-seed.iso
qemu-img create -f qcow2 -F qcow2 -b /images/ubuntu-noble.qcow2 /scratch/attacker.qcow2 10G
cloud-localds -N /plan/network-config /scratch/attacker-seed.iso /plan/user-data /plan/meta-data
virt-install \
  --connect qemu:///system \
  --name attacker \
  --memory 1024 --vcpus 1 \
  --cpu host-passthrough \
  --disk path=/scratch/attacker.qcow2,format=qcow2,bus=virtio \
  --disk path=/scratch/attacker-seed.iso,device=cdrom \
  --network "bridge=$BRIDGE,model=virtio,mac=$ATTACKER_MAC" \
  --vsock cid.address=9 \
  --osinfo ubuntu24.04 \
  --import --graphics none --noautoconsole

virsh -c qemu:///system list

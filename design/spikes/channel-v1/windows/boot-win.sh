#!/bin/bash
# Run inside the range container: build the v3 payload ISO (the four daemon
# sources + installer + busybox for the test image) and boot the battery
# guest with a vsock device at the chan-band CID.
set -euxo pipefail

CID="${CID:-2048}"

rm -rf /tmp/payload && mkdir -p /tmp/payload
cp /payload-src/Wire.cs /payload-src/Exec.cs /payload-src/Daemon.cs \
   /payload-src/Program.cs /payload-src/install-daemon.ps1 /tmp/payload/
[ -f /images/busybox.exe ] && cp /images/busybox.exe /tmp/payload/
genisoimage -quiet -o /scratch/payload.iso -J -R -V PAYLOAD /tmp/payload

virsh -c qemu:///system destroy winv3 2>/dev/null || true
virsh -c qemu:///system undefine winv3 2>/dev/null || true
rm -f /scratch/winv3.qcow2
qemu-img create -f qcow2 -F qcow2 -b /scratch/win-golden.qcow2 /scratch/winv3.qcow2 40G

virt-install \
  --connect qemu:///system \
  --name winv3 \
  --memory 4096 --vcpus 4 \
  --cpu host-passthrough \
  --disk path=/scratch/winv3.qcow2,format=qcow2,bus=virtio \
  --disk path=/images/virtio-win.iso,device=cdrom,readonly=on \
  --disk path=/scratch/payload.iso,device=cdrom,readonly=on \
  --network none \
  --vsock cid.address="$CID" \
  --channel unix,target.type=virtio,target.name=org.qemu.guest_agent.0 \
  --boot hd \
  --graphics vnc,listen=127.0.0.1 \
  --osinfo win2k22 \
  --import --noautoconsole

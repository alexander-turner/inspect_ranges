#!/bin/bash
set -euo pipefail
mkdir -p /run/libvirt
/usr/sbin/virtlogd -d
/usr/sbin/libvirtd -d
until virsh -c qemu:///system version >/dev/null 2>&1; do sleep 0.2; done
touch /run/range-ready
echo "range container ready: libvirtd running"
exec sleep infinity

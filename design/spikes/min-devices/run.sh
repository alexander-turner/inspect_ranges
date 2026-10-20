#!/bin/bash
# Minimal-device-model spike: the compiler-emitted explicit domain XML
# (agent-containment backlog item 3) under the hardened container profile.
# Captures the guest-visible device surface before/after, then proves the
# full range still works: boot, cloud-init via virtio seed, T1-T9 battery,
# exec/file plane, save/restore under the minimal model, teardown.
# See README.md. Usage: ./run.sh [down]
set -euo pipefail
cd "$(dirname "$0")"

export IMAGE_CACHE="${IMAGE_CACHE:-$HOME/.cache/inspect-ranges/images}"
V="virsh -c qemu:///system"
C="python3 ../vsock-exec/host/client.py"

if [[ "${1:-}" == "down" ]]; then
  docker compose down -v
  exit 0
fi

[[ -f "$IMAGE_CACHE/ubuntu-noble.qcow2" ]] || { echo "missing guest image; run ../net-compile/run.sh once first"; exit 1; }
[[ -f ../net-compile/tmp/render/allocation.json ]] || { echo "missing compiled render; run ../net-compile/run.sh once first"; exit 1; }

python3 gen-xml.py
docker compose up -d --build --wait

# PCI surface seen from inside the guest, no tool dependencies
PCI_LIST='for d in /sys/bus/pci/devices/*; do printf "%s %s %s\n" $(cat $d/vendor) $(cat $d/device) $(cat $d/class); done | sort'

echo "=== baseline: one guest with virt-install defaults (what we are removing) ==="
docker compose exec -T range sh -c '
set -e
qemu-img create -f qcow2 -F qcow2 -b /images/ubuntu-noble.qcow2 /scratch/baseline.qcow2 10G >/dev/null
cloud-localds -N /render/vms/agent/network-config /scratch/baseline-seed.iso /render/vms/agent/user-data /render/vms/agent/meta-data
virt-install --connect qemu:///system --name baseline --memory 1024 --vcpus 1 --cpu host-passthrough \
  --disk path=/scratch/baseline.qcow2,format=qcow2,bus=virtio \
  --disk path=/scratch/baseline-seed.iso,device=cdrom \
  --network bridge=br-dmz,model=virtio,mac=52:54:00:50:00:0c \
  --vsock cid.address=6 --osinfo ubuntu24.04 --import --graphics none --noautoconsole >/dev/null
'
$C 6 wait
docker compose exec -T range $V dumpxml baseline > tmp/baseline.xml
$C 6 exec "$PCI_LIST" > tmp/baseline-pci.txt
echo "baseline guest-visible PCI devices: $(wc -l < tmp/baseline-pci.txt)"
docker compose exec -T range sh -c "$V destroy baseline && $V undefine baseline && rm -f /scratch/baseline.qcow2 /scratch/baseline-seed.iso" >/dev/null

echo "=== boot the 4-VM range from explicit minimal XML ==="
T0=$(date +%s.%N)
docker compose exec -T range bash /mdxml/boot.sh >/dev/null 2>&1
for cid in 3 4 5 6; do $C $cid wait; done
for cid in 3 4 5 6; do
  $C $cid exec 'cloud-init status --wait >/dev/null 2>&1; echo done' >/dev/null
done
T1=$(date +%s.%N)
python3 -c "print(f'up -> range ready (cloud-init seed on virtio disk): {$T1-$T0:.1f}s')"

echo "=== device surface: minimal agent vs baseline ==="
docker compose exec -T range $V dumpxml agent > tmp/agent.xml
$C 6 exec "$PCI_LIST" > tmp/agent-pci.txt
echo "agent guest-visible PCI devices: $(wc -l < tmp/agent-pci.txt)"
echo "--- removed vs baseline ---"
comm -23 tmp/baseline-pci.txt tmp/agent-pci.txt || true
echo "--- added vs baseline ---"
comm -13 tmp/baseline-pci.txt tmp/agent-pci.txt || true
echo "--- host-side XML device elements (agent) ---"
grep -oE "<(disk|interface|serial|console|channel|rng|vsock|memballoon|controller|video|graphics|input|audio|sound|tpm|hub|redirdev|watchdog) " tmp/agent.xml | sort | uniq -c
echo "--- host-side XML device elements (baseline) ---"
grep -oE "<(disk|interface|serial|console|channel|rng|vsock|memballoon|controller|video|graphics|input|audio|sound|tpm|hub|redirdev|watchdog) " tmp/baseline.xml | sort | uniq -c
echo "web (target profile) has video: $(grep -c '<video>' tmp/xml/web.xml) (expected 1); agent: $(grep -c '<video>' tmp/xml/agent.xml) (expected 0)"

echo "=== function: ACL / isolation battery (net-compile T1-T9) ==="
echo "T1 same-segment (agent->web ping):"
$C 6 exec 'ping -c1 -W2 10.80.10.10 >/dev/null && echo PASS reachable'
echo "T2 cross-segment allowed port (agent->db:5432):"
$C 6 exec 'timeout 3 bash -c "echo > /dev/tcp/10.80.20.10/5432" 2>&1 | grep -q refused && echo PASS refused-fast'
echo "T3 denied-but-listening (agent->db:22):"
$C 6 exec 'timeout 3 bash -c "echo > /dev/tcp/10.80.20.10/22" 2>/dev/null; [ $? -eq 124 ] && echo PASS dropped'
echo "T4 cross-segment ICMP denied:"
$C 6 exec 'ping -c1 -W2 10.80.20.10 >/dev/null 2>&1 || echo PASS blocked'
echo "T5 L2 isolation:"
$C 6 exec 'ip route add 10.80.20.10/32 dev dmz0 && ping -c1 -W1 10.80.20.10 >/dev/null 2>&1; ip neigh show 10.80.20.10 | grep -q -E "FAILED|INCOMPLETE" && echo PASS no-l2-path; ip route del 10.80.20.10/32 dev dmz0'
echo "T6 asymmetry (db->web:22 denied):"
$C 5 exec 'timeout 3 bash -c "echo > /dev/tcp/10.80.10.10/22" 2>/dev/null; [ $? -eq 124 ] && echo PASS dropped'
echo "T7 gateway reachable:"
$C 6 exec 'ping -c1 -W2 10.80.10.1 >/dev/null && echo PASS'
echo "T8 host netns invisibility:"
[ "$(ip -o link | grep -c 'br-dmz\|br-internal')" -eq 0 ] && echo "PASS 0 range bridges on host"
echo "T9 range-netns invariants:"
docker compose exec -T range sh -c 'nft list ruleset | grep -q rangehost && echo PASS nft-loaded'

echo "=== exec/file plane under minimal model ==="
head -c 1048576 /dev/urandom > tmp/md.bin
$C 6 put tmp/md.bin /root/md.bin
$C 6 get /root/md.bin tmp/md-back.bin
cmp tmp/md.bin tmp/md-back.bin && echo "PASS 1MB file round trip"
echo "entropy sanity (virtio-rng present, no boot starvation):"
$C 6 exec 'cat /proc/sys/kernel/random/entropy_avail && ls /dev/hwrng >/dev/null 2>&1 && echo PASS hwrng-present'

echo "=== save/restore under the minimal device model ==="
docker compose exec -T range $V save agent /scratch/agent.sav >/dev/null
docker compose exec -T range $V restore /scratch/agent.sav >/dev/null
$C 6 wait
$C 6 exec 'echo restored && whoami' | tail -2
echo "PASS save/restore with minimal device set"

echo "=== teardown (hardened profile destroy path) ==="
docker compose exec -T range sh -c "$V destroy agent && $V destroy web && $V destroy db && $V destroy router && $V list --name | grep -c . || echo '0 running'"
echo "OK. Tear down with: ./run.sh down"

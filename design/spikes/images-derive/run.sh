#!/bin/bash
# realizer-v1 slice 1 battery: `inspect-ranges images derive` end to end.
# Host side: digest refusal, unmanaged refusal, idempotence, provenance.
# VM side: the derived golden boots, the daemon answers on vsock from the
# realizer CID band, and the guest has zero TCP listeners.
# Usage: ./run.sh [down]. See README.md.
set -euo pipefail
cd "$(dirname "$0")"

CID=3000                       # realizer battery band (3000+) per realizer-v1.md
export BATTERY_CACHE="$PWD/tmp/cache"
VENDOR="${VENDOR:-$HOME/.cache/inspect-ranges/images/noble-server-cloudimg-amd64.img}"
IR="uv run inspect-ranges"
C="python3 client2.py"
V="virsh --connect qemu:///system"

if [[ "${1:-}" == "down" ]]; then
  docker compose down -v
  exit 0
fi

grep -q vhost_vsock /proc/modules || { echo "need: sudo modprobe vhost_vsock"; exit 1; }
[[ -f "$VENDOR" ]] || { echo "missing vendor image $VENDOR"; exit 1; }

# stale-project hygiene: a prior run's container pins the old cache mount
docker compose down -v >/dev/null 2>&1 || true
mkdir -p tmp && rm -rf tmp/cache && mkdir -p tmp/cache
PASS=0; FAIL=0
ok()   { echo "PASS  $1"; PASS=$((PASS+1)); }
bad()  { echo "FAIL  $1"; FAIL=$((FAIL+1)); }

# the battery serializes with other exclusive batteries on the shared host lock
exec 9>/tmp/inspect-ranges-battery.lock
flock 9

VENDOR_SHA=$(sha256sum "$VENDOR" | cut -d' ' -f1)

echo "=== host checks ==="
cd ../../..   # repo root for uv

# 1. digest mismatch refuses before cache writes
if $IR images derive "$VENDOR" --sha256 "$(printf '0%.0s' {1..64})" \
     --image-cache "$BATTERY_CACHE" >design/spikes/images-derive/tmp/mismatch.txt 2>&1; then
  bad "digest mismatch refused"
else
  grep -q "verify-vendor" design/spikes/images-derive/tmp/mismatch.txt \
    && [[ -z "$(ls -A "$BATTERY_CACHE")" ]] \
    && ok "digest mismatch refused before cache writes" \
    || bad "digest mismatch refused before cache writes"
fi

# 2. derive succeeds and records provenance
$IR images derive "$VENDOR" --sha256 "$VENDOR_SHA" --name range-guest \
  --image-cache "$BATTERY_CACHE" | tee design/spikes/images-derive/tmp/derive1.txt
grep -q "derived: range-guest.qcow2" design/spikes/images-derive/tmp/derive1.txt \
  && [[ -f "$BATTERY_CACHE/range-guest.json" ]] \
  && ok "derive writes golden and provenance" || bad "derive writes golden and provenance"

# 3. idempotence: second run is a cache hit with the same digest
$IR images derive "$VENDOR" --sha256 "$VENDOR_SHA" --name range-guest \
  --image-cache "$BATTERY_CACHE" | tee design/spikes/images-derive/tmp/derive2.txt
D1=$(grep -o 'sha256:[0-9a-f]*' design/spikes/images-derive/tmp/derive1.txt | head -1)
D2=$(grep -o 'sha256:[0-9a-f]*' design/spikes/images-derive/tmp/derive2.txt | head -1)
grep -q "cache hit" design/spikes/images-derive/tmp/derive2.txt && [[ "$D1" == "$D2" ]] \
  && ok "idempotent derive (cache hit, same digest)" || bad "idempotent derive"

# 4. unmanaged files are never clobbered
touch "$BATTERY_CACHE/handmade.qcow2"
if $IR images derive "$VENDOR" --sha256 "$VENDOR_SHA" --name handmade \
     --image-cache "$BATTERY_CACHE" >design/spikes/images-derive/tmp/unmanaged.txt 2>&1; then
  bad "unmanaged file refused"
else
  grep -q "unmanaged" design/spikes/images-derive/tmp/unmanaged.txt \
    && ok "unmanaged file never clobbered" || bad "unmanaged file never clobbered"
fi

# 5. list shows managed provenance and flags the unmanaged file
$IR images list --image-cache "$BATTERY_CACHE" | tee design/spikes/images-derive/tmp/list.txt
grep -q "range-guest.qcow2" design/spikes/images-derive/tmp/list.txt \
  && grep -q "handmade.qcow2  (unmanaged" design/spikes/images-derive/tmp/list.txt \
  && ok "images list separates managed and unmanaged" || bad "images list"

cd design/spikes/images-derive

if [[ "${SKIP_VM:-}" == "1" ]]; then
  echo; echo "$PASS passed, $FAIL failed (host checks only; SKIP_VM=1)"
  exit $((FAIL > 0))
fi

echo "=== boot the golden, verify daemon + zero listeners ==="
# the range container entrypoint realizes compiled artifacts; a single
# NIC-less guest needs none, so feed it an empty render
mkdir -p tmp/render
: > tmp/render/bridges.txt
printf '# no hypervisor rules for the NIC-less battery guest\n' > tmp/render/range-netns.nft
docker compose up -d --build --wait
docker compose exec -T range sh -c "
set -e
qemu-img create -f qcow2 -F qcow2 -b /images/range-guest.qcow2 /scratch/guest.qcow2 10G >/dev/null
virt-install --connect qemu:///system --name guest --memory 1024 --vcpus 1 --cpu host-passthrough \
  --disk path=/scratch/guest.qcow2,format=qcow2,bus=virtio \
  --network none \
  --vsock cid.address=$CID --osinfo ubuntu24.04 --import --graphics none --noautoconsole >/dev/null
"
$C $CID wait 240 && ok "daemon answers on vsock (CID $CID)" || bad "daemon answers on vsock"

LISTENERS=$($C $CID exec "ss -tuln | tail -n +2 | wc -l")
[[ "$LISTENERS" == "0" ]] && ok "zero TCP/UDP listeners in the booted golden" \
  || { bad "zero TCP/UDP listeners (got $LISTENERS)"; $C $CID exec "ss -tulnp" || true; }

SSH_STATE=$($C $CID exec "systemctl is-enabled ssh 2>&1 || true")
[[ "$SSH_STATE" == *masked* ]] && ok "ssh masked" || bad "ssh masked (got: $SSH_STATE)"

docker compose exec -T range sh -c "$V destroy guest >/dev/null 2>&1 || true; $V undefine guest >/dev/null 2>&1 || true"
docker compose down -v >/dev/null

echo
echo "$PASS passed, $FAIL failed"
exit $((FAIL > 0))

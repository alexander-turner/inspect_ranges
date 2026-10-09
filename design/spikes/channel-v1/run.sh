#!/bin/bash
# channel-v1 slice 4 battery: the Go v3 daemon over the real vsock transport.
# Builds the daemon with the pinned toolchain, bakes a battery golden, boots
# it in the range container at a chan-band CID, then runs: the portable
# conformance suite, fault-injection and durability checks, the 500+ op soak
# (tests/test_channel_vsock.py), Inspect's self_check (self_check3.py), and
# the hostile-daemon shim (hostile_shim_check.py).
# Usage: ./run.sh [down]. Logs under tmp/ (gitignored).
set -euo pipefail
cd "$(dirname "$0")"

CID=2048                        # channel battery band 2048-2999 per channel-v1.md
PROJECT=chan-v1-battery
GO="$HOME/.local/go-toolchains/go1.23.6/bin/go"
VENDOR="${VENDOR:-$HOME/.cache/inspect-ranges/images/noble-server-cloudimg-amd64.img}"

if [[ "${1:-}" == "down" ]]; then
  docker compose -p "$PROJECT" down -v
  exit 0
fi

grep -q vhost_vsock /proc/modules || { echo "need: sudo modprobe vhost_vsock"; exit 1; }
[[ -f "$VENDOR" ]] || { echo "missing vendor image $VENDOR"; exit 1; }
[[ -x "$GO" ]] || { echo "missing pinned Go toolchain (daemon/linux/README.md)"; exit 1; }

PASS=0; FAIL=0
ok()  { echo "PASS  $1"; PASS=$((PASS+1)); }
bad() { echo "FAIL  $1"; FAIL=$((FAIL+1)); }

# exclusive battery: serialize on the shared host lock (realizer runs at
# 3000+). The slice 7 orchestrator (realizer/run.sh) invokes this battery
# INSIDE its own lock for the concurrency check; it sets IR_BATTERY_LOCK_HELD
# so we do not deadlock on the lock our caller already holds.
if [[ "${IR_BATTERY_LOCK_HELD:-}" != "1" ]]; then
  exec 9>/tmp/inspect-ranges-battery.lock
  flock 9
fi

docker compose -p "$PROJECT" down -v >/dev/null 2>&1 || true
mkdir -p tmp/render tmp/logs
rm -rf tmp/images tmp/artifacts && mkdir -p tmp/images

echo "=== build the daemon bundle (pinned toolchain, slice-4 re-pin) ==="
HERE=$PWD
cd ../../..   # repo root for uv
DB_OUT=$(uv run inspect-ranges daemon-bundle -o "$HERE/tmp/artifacts") \
  || { echo "daemon-bundle build failed (install the pinned Go toolchain)"; exit 1; }
DAEMON_SHA=$(echo "$DB_OUT" | grep -o 'bundle sha256:[0-9a-f]*' | cut -d: -f2)
[[ -n "$DAEMON_SHA" ]] && ok "daemon bundle built and pinned" || bad "daemon bundle built"

echo "=== derive the battery golden (recipe v4: daemon + agent user) ==="
# the real derive pipeline replaces the spike-era bare bake, so the booted
# guest carries the agent user slice 4 adds (self_check needs it for 44/44);
# the cache dir mounts whole into the container and the overlay references
# the vendor by bare name (the images.py lesson)
VENDOR_SHA=$(sha256sum "$VENDOR" | cut -d' ' -f1)
uv run inspect-ranges images derive "$VENDOR" --sha256 "$VENDOR_SHA" --name guest \
  --image-cache "$HERE/tmp/images" --daemon-bundle "$HERE/tmp/artifacts" --daemon-sha256 "$DAEMON_SHA" \
  >"$HERE/tmp/logs/derive.txt" 2>&1 \
  && ok "recipe-v4 golden derived" || { bad "recipe-v4 golden derived"; tail -5 "$HERE/tmp/logs/derive.txt"; exit 1; }
cd "$HERE"

echo "=== boot at CID $CID (chan band) ==="
: > tmp/render/bridges.txt
printf '# NIC-less battery guest: no hypervisor rules\n' > tmp/render/range-netns.nft
docker compose -p "$PROJECT" up -d --build --wait
docker compose -p "$PROJECT" exec -T range sh -c "
set -e
qemu-img create -f qcow2 -F qcow2 -b /images/guest.qcow2 /scratch/run.qcow2 10G >/dev/null
virt-install --connect qemu:///system --name guest --memory 1024 --vcpus 1 --cpu host-passthrough \
  --disk path=/scratch/run.qcow2,format=qcow2,bus=virtio \
  --network none \
  --vsock cid.address=$CID --osinfo ubuntu24.04 --import --graphics none --noautoconsole >/dev/null
"

cd ../../..   # repo root for uv
export IR_VSOCK_BATTERY_CID=$CID

echo "=== wait for the daemon ==="
for i in $(seq 1 120); do
  if uv run python -c "
import asyncio, os
from inspect_ranges._channel.channel import MessageChannel
from inspect_ranges._channel.vsock import VsockTransport
cid = int(os.environ['IR_VSOCK_BATTERY_CID'])
async def probe():
    channel = MessageChannel(VsockTransport({'guest': cid}), channel_budget_s=2.0)
    pong = await channel.ping('guest')
    assert pong.protocol == 3
asyncio.run(probe())
" 2>/dev/null; then READY=1; break; fi
  sleep 2
done
[[ "${READY:-}" == "1" ]] && ok "v3 daemon answers on vsock (CID $CID)" || { bad "daemon answers"; exit 1; }

echo "=== portable conformance + durability + soak (pytest) ==="
if uv run pytest tests/test_channel_vsock.py -v -n 0 2>&1 | tee design/spikes/channel-v1/tmp/logs/pytest.txt | tail -4; then
  ok "vsock battery pytest green"
else
  bad "vsock battery pytest"
fi

echo "=== Inspect self_check over v3 ==="
if uv run python design/spikes/channel-v1/self_check3.py 2>&1 | tee design/spikes/channel-v1/tmp/logs/self_check.txt | tail -8; then
  ok "self_check within documented xfails"
else
  bad "self_check"
fi

echo "=== provider self_check over vsock (slice 4: 44/44, EMPTY pin) ==="
# serial (-n 0): the booted guest's filesystem is shared state across checks
if uv run pytest tests/test_provider_self_check.py -q -n 0 2>&1 \
     | tee design/spikes/channel-v1/tmp/logs/provider_self_check.txt | tail -3; then
  ok "provider self_check 44/44 over vsock (no pins)"
else
  bad "provider self_check over vsock"
fi

echo "=== hostile-daemon shim through the real transport ==="
if uv run python design/spikes/channel-v1/hostile_shim_check.py 2>&1 | tee design/spikes/channel-v1/tmp/logs/shim.txt; then
  ok "hostile shim scenarios"
else
  bad "hostile shim scenarios"
fi

cd design/spikes/channel-v1
docker compose -p "$PROJECT" exec -T range sh -c \
  "virsh --connect qemu:///system destroy guest >/dev/null 2>&1 || true; \
   virsh --connect qemu:///system undefine guest >/dev/null 2>&1 || true" || true
docker compose -p "$PROJECT" down -v >/dev/null

echo
echo "$PASS passed, $FAIL failed"
exit $((FAIL > 0))

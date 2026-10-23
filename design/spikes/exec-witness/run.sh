#!/bin/bash
# execve-witness-v1 fork-storm battery: builds the daemon bundle from source,
# derives a battery golden, boots it at a chan-band CID, and runs
# storm_battery.py's seven numeric gates. Usage: ./run.sh [down].
# Logs under tmp/ (gitignored). Harness cloned from channel-v1/run.sh.
set -euo pipefail
cd "$(dirname "$0")"

CID=2080                        # chan band 2048-2999, clear of channel-v1's 2048
PROJECT=execw-battery
GO="$HOME/.local/go-toolchains/go1.23.6/bin/go"
VENDOR="${VENDOR:-$HOME/.cache/inspect-ranges/images/noble-server-cloudimg-amd64.img}"

if [[ "${1:-}" == "down" ]]; then
  docker compose -p "$PROJECT" down -v
  exit 0
fi

grep -q vhost_vsock /proc/modules || { echo "need: sudo modprobe vhost_vsock"; exit 1; }
[[ -f "$VENDOR" ]] || { echo "missing vendor image $VENDOR"; exit 1; }
[[ -x "$GO" ]] || { echo "missing pinned Go toolchain (daemon/linux/README.md)"; exit 1; }

# exclusive battery: serialize on the shared host lock
if [[ "${IR_BATTERY_LOCK_HELD:-}" != "1" ]]; then
  exec 9>/tmp/inspect-ranges-battery.lock
  flock 9
fi

docker compose -p "$PROJECT" down -v >/dev/null 2>&1 || true
mkdir -p tmp/render tmp/logs
rm -rf tmp/images tmp/artifacts && mkdir -p tmp/images

echo "=== build the daemon bundle (pinned toolchain) ==="
HERE=$PWD
cd ../../..   # repo root for uv
DB_OUT=$(uv run inspect-ranges daemon-bundle -o "$HERE/tmp/artifacts")
DAEMON_SHA=$(echo "$DB_OUT" | grep -o 'bundle sha256:[0-9a-f]*' | cut -d: -f2)
[[ -n "$DAEMON_SHA" ]] || { echo "FAIL daemon bundle"; exit 1; }

echo "=== derive the battery golden ==="
VENDOR_SHA=$(sha256sum "$VENDOR" | cut -d' ' -f1)
uv run inspect-ranges images derive "$VENDOR" --sha256 "$VENDOR_SHA" --name guest \
  --image-cache "$HERE/tmp/images" --daemon-bundle "$HERE/tmp/artifacts" --daemon-sha256 "$DAEMON_SHA" \
  >"$HERE/tmp/logs/derive.txt" 2>&1 || { echo "FAIL derive"; tail -5 "$HERE/tmp/logs/derive.txt"; exit 1; }
cd "$HERE"

echo "=== boot at CID $CID (2 vcpus: the storm needs fork headroom) ==="
: > tmp/render/bridges.txt
printf '# NIC-less battery guest: no hypervisor rules\n' > tmp/render/range-netns.nft
docker compose -p "$PROJECT" up -d --build --wait
docker compose -p "$PROJECT" exec -T range sh -c "
set -e
qemu-img create -f qcow2 -F qcow2 -b /images/guest.qcow2 /scratch/run.qcow2 10G >/dev/null
virt-install --connect qemu:///system --name guest --memory 1536 --vcpus 2 --cpu host-passthrough \
  --disk path=/scratch/run.qcow2,format=qcow2,bus=virtio \
  --network none \
  --vsock cid.address=$CID --osinfo ubuntu24.04 --import --graphics none --noautoconsole >/dev/null
"

cd ../../..   # repo root for uv
export IR_EXEC_WITNESS_CID=$CID

echo "=== wait for the daemon ==="
READY=0
for i in $(seq 1 120); do
  if uv run python -c "
import asyncio, os
from inspect_ranges._channel.channel import MessageChannel
from inspect_ranges._channel.vsock import VsockTransport
cid = int(os.environ['IR_EXEC_WITNESS_CID'])
async def probe():
    channel = MessageChannel(VsockTransport({'guest': cid}), channel_budget_s=2.0)
    pong = await channel.ping('guest')
    assert pong.protocol == 3
asyncio.run(probe())
" 2>/dev/null; then READY=1; break; fi
  sleep 2
done
[[ "$READY" == "1" ]] || { echo "FAIL daemon never answered"; exit 1; }

echo "=== the storm battery ==="
# pipefail: the || must see the python exit, not tee's (the house pipeline
# exit-masking lesson, again)
set -o pipefail
STATUS=0
uv run python design/spikes/exec-witness/storm_battery.py 2>&1 \
  | tee design/spikes/exec-witness/tmp/logs/storm.txt || STATUS=1

echo "=== the flow cut (real poller, sealed record, verify) ==="
uv run python design/spikes/exec-witness/flow_cut.py 2>&1 \
  | tee design/spikes/exec-witness/tmp/logs/flowcut.txt || STATUS=1

cd design/spikes/exec-witness
docker compose -p "$PROJECT" exec -T range sh -c \
  "virsh --connect qemu:///system destroy guest >/dev/null 2>&1 || true; \
   virsh --connect qemu:///system undefine guest >/dev/null 2>&1 || true" || true
docker compose -p "$PROJECT" down -v >/dev/null
exit $STATUS

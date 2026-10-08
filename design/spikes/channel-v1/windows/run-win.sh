#!/bin/bash
# channel-v1 slice 6 battery: the Windows C# v3 daemon over the real vsock
# transport. Reuses the vsockd-win spike machinery (range container, Windows
# golden install, qemu-ga bootstrap) with the chan- project prefix and the
# chan CID band; the daemon sources ride the payload ISO from the PRODUCTION
# tree (src/inspect_ranges/_channel/daemon/windows), compiled in-guest by the
# in-box csc.exe.
# Phases: ./run-win.sh [all|conformance|down]  (default: all). Logs in tmp/.
set -euo pipefail
cd "$(dirname "$0")"

export IMAGE_CACHE="${IMAGE_CACHE:-$HOME/.cache/inspect-ranges/images}"
CID=2049                        # chan band 2048-2999; 2048 is the Linux battery's
PROJECT=chan-v1-win
V="virsh -c qemu:///system"
GA="python3 ../../vsockd-win/ga.py"
PHASE="${1:-all}"
DC() { docker compose -p "$PROJECT" "$@"; }

if [[ "$PHASE" == "down" ]]; then
  DC down -v
  exit 0
fi

for iso in ws2022-eval.iso virtio-win.iso; do
  [[ -f "$IMAGE_CACHE/$iso" ]] || { echo "missing $IMAGE_CACHE/$iso"; exit 1; }
done
if [[ ! -f "$IMAGE_CACHE/busybox.exe" ]]; then
  echo "fetching busybox-w32 (GPLv2; test image only) ..."
  curl -fsSL -o "$IMAGE_CACHE/busybox.exe" https://frippery.org/files/busybox/busybox.exe
fi
grep -q vhost_vsock /proc/modules || { echo "need: sudo modprobe vhost_vsock"; exit 1; }

PASS=0; FAIL=0
ok()  { echo "PASS  $1"; PASS=$((PASS+1)); }
bad() { echo "FAIL  $1"; FAIL=$((FAIL+1)); }
mkdir -p tmp

# exclusive battery: the shared host lock (realizer runs at 3000+ concurrently)
exec 9>/tmp/inspect-ranges-battery.lock
flock 9

if [[ "$PHASE" == "all" ]]; then
  DC up -d --build --wait

  if ! DC exec -T range test -f /scratch/win-golden.qcow2; then
    echo "=== golden image install (one-time, ~3 min) ==="
    DC exec -T range bash /assets/install.sh
    until [[ "$(DC exec -T range $V domstate wininstall)" != "running" ]]; do sleep 15; done
    DC exec -T range $V undefine wininstall
  fi

  echo "=== boot guest (v3 payload, vsock CID $CID) ==="
  DC exec -T range env CID=$CID bash /boot-win.sh >tmp/boot.log 2>&1

  echo "=== bootstrap over qemu-ga: driver + csc compile + v3 service ==="
  COMPOSE_PROJECT_NAME=$PROJECT $GA wait winv3 300
  COMPOSE_PROJECT_NAME=$PROJECT $GA ps winv3 600 < ../../../../src/inspect_ranges/_channel/daemon/windows/install-daemon.ps1

  echo "=== reboot (service autostart + PATH pickup) ==="
  BT=$(COMPOSE_PROJECT_NAME=$PROJECT $GA boottime winv3)
  COMPOSE_PROJECT_NAME=$PROJECT $GA ps winv3 60 <<'EOF'
& shutdown.exe /r /t 3
EOF
  COMPOSE_PROJECT_NAME=$PROJECT $GA wait-newboot winv3 "$BT" 300
fi

cd ../../../..   # repo root for uv
export IR_VSOCK_BATTERY_CID=$CID IR_VSOCK_WIN_CID=$CID IR_SELF_CHECK_XFAILS=windows

echo "=== wait for the v3 daemon on vsock ==="
for i in $(seq 1 150); do
  if uv run python -c "
import asyncio, os
from inspect_ranges._channel.channel import MessageChannel
from inspect_ranges._channel.vsock import VsockTransport
cid = int(os.environ['IR_VSOCK_WIN_CID'])
async def probe():
    channel = MessageChannel(VsockTransport({'guest': cid}), channel_budget_s=3.0)
    pong = await channel.ping('guest')
    assert pong.protocol == 3 and 'windows' in pong.daemon
asyncio.run(probe())
" 2>/dev/null; then READY=1; break; fi
  sleep 2
done
[[ "${READY:-}" == "1" ]] && ok "v3 daemon answers on vsock (CID $CID, windows)" || { bad "daemon answers"; exit 1; }

echo "=== portable conformance + durability + ESTALE + soak (pytest) ==="
if uv run pytest tests/test_channel_vsock_win.py -v -n 0 2>&1 | tee design/spikes/channel-v1/windows/tmp/pytest.txt | tail -4; then
  ok "windows vsock battery pytest green"
else
  bad "windows vsock battery pytest"
fi

echo "=== Inspect self_check over v3 (windows xfail names pinned) ==="
if uv run python design/spikes/channel-v1/self_check3.py 2>&1 | tee design/spikes/channel-v1/windows/tmp/self_check.txt | tail -8; then
  ok "self_check within the pinned windows xfails"
else
  bad "self_check"
fi

echo "=== Windows-native supplement over v3 ==="
if uv run python design/spikes/channel-v1/windows/windows_checks3.py 2>&1 | tee design/spikes/channel-v1/windows/tmp/native.txt | tail -4; then
  ok "native supplement green"
else
  bad "native supplement"
fi

echo "=== the wedge regression: unpaced reconnect storm ==="
if uv run python design/spikes/channel-v1/windows/storm_v3.py 2>&1 | tee design/spikes/channel-v1/windows/tmp/storm.txt | tail -8; then
  ok "reconnect storm: listener alive, bounded retries"
else
  bad "reconnect storm"
fi

echo
echo "$PASS passed, $FAIL failed"
exit $((FAIL > 0))

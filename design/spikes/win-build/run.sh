#!/bin/bash
# windows-ad-v1 slice 1 battery: the Windows guest, first-class. The sysprep'd
# golden installs from digest-pinned eval media through `images derive-windows`
# (one-shot hardened container, unattended install, virtio + the vsock daemon
# baked at first logon, sysprep /generalize), then a range with one Windows
# host and a Linux attacker renders and boots on the PRODUCTION pipeline: the
# clone specializes from the render-emitted unattend seed (hostname + static
# address prove it), readiness is daemon-only, exec answers as SYSTEM, and
# teardown is clean. Usage: ./run.sh [down]. CID band 4150.
set -euo pipefail
cd "$(dirname "$0")"
SPIKE="$PWD"
ROOT="$(cd ../../.. && pwd)"

WIN_ISO="${WIN_ISO:-$HOME/.cache/inspect-ranges/images/ws2022-eval.iso}"
VIRTIO_ISO="${VIRTIO_ISO:-$HOME/.cache/inspect-ranges/images/virtio-win.iso}"
NOBLE="${NOBLE:-$HOME/.cache/inspect-ranges/images/noble-server-cloudimg-amd64.img}"
export XDG_STATE_HOME="$SPIKE/tmp/state"
IR="uv run inspect-ranges"
CACHE="$SPIKE/tmp/cache"

if [[ "${1:-}" == "down" ]]; then
  (cd "$ROOT" && $IR down --all) || true
  exit 0
fi

grep -q vhost_vsock /proc/modules || { echo "need: sudo modprobe vhost_vsock"; exit 1; }
[[ -f "$WIN_ISO" && -f "$VIRTIO_ISO" && -f "$NOBLE" ]] || { echo "missing media"; exit 1; }

PASS=0; FAIL=0
ok()  { echo "PASS  $1"; PASS=$((PASS+1)); }
bad() { echo "FAIL  $1"; FAIL=$((FAIL+1)); }

exec 9>/tmp/inspect-ranges-battery.lock
flock 9
cd "$ROOT"
$IR down --all >/dev/null 2>&1 || true
rm -rf "$SPIKE/tmp" && mkdir -p "$SPIKE/tmp"

echo "=== W1 install the Windows golden from pinned media ==="
DB_OUT=$($IR daemon-bundle -o "$SPIKE/tmp/artifacts")
DAEMON_SHA=$(echo "$DB_OUT" | grep -o 'bundle sha256:[0-9a-f]*' | cut -d: -f2)
WIN_SHA=$(sha256sum "$WIN_ISO" | cut -d' ' -f1)
VIRTIO_SHA=$(sha256sum "$VIRTIO_ISO" | cut -d' ' -f1)
if $IR images derive-windows "$WIN_ISO" --sha256 "$WIN_SHA" \
    --virtio-iso "$VIRTIO_ISO" --virtio-sha256 "$VIRTIO_SHA" \
    --image-cache "$CACHE" --daemon-bundle "$SPIKE/tmp/artifacts" \
    --daemon-sha256 "$DAEMON_SHA" >"$SPIKE/tmp/w1.txt" 2>&1; then
  grep -q "installed: windows-2022.qcow2" "$SPIKE/tmp/w1.txt" \
    && ok "W1 the golden installed (sysprep'd, daemon baked)" \
    || { bad "W1 output"; cat "$SPIKE/tmp/w1.txt"; }
else
  bad "W1 derive-windows"; tail -5 "$SPIKE/tmp/w1.txt"; exit 1
fi
$IR images derive-windows "$WIN_ISO" --sha256 "$WIN_SHA" \
    --virtio-iso "$VIRTIO_ISO" --virtio-sha256 "$VIRTIO_SHA" \
    --image-cache "$CACHE" --daemon-bundle "$SPIKE/tmp/artifacts" \
    --daemon-sha256 "$DAEMON_SHA" >"$SPIKE/tmp/w1b.txt" 2>&1 \
  && grep -q "cache hit" "$SPIKE/tmp/w1b.txt" \
  && ok "W1b re-deriving is a cache hit (same media, daemon, password pins)" \
  || { bad "W1b idempotence"; tail -3 "$SPIKE/tmp/w1b.txt"; }

echo "=== W2 the Windows host boots on the production pipeline ==="
$IR images derive "$NOBLE" --sha256 "$(sha256sum "$NOBLE" | cut -d' ' -f1)" --name ubuntu-noble \
  --image-cache "$CACHE" --daemon-bundle "$SPIKE/tmp/artifacts" --daemon-sha256 "$DAEMON_SHA" >/dev/null
mkdir -p "$SPIKE/tmp/range"
cat > "$SPIKE/tmp/range/range.yaml" <<'SPEC'
range:
  name: win-slice1
  schema_version: "0.3"
  description: one windows host and a linux attacker, the slice-1 proof
networks:
  - name: corp
    cidr: 10.21.0.0/24
    mode: isolated
hosts:
  - name: dc
    os: { type: windows, version: server-2022 }
    image: windows-2022
    resources: { cpus: 2, memory_mb: 4096 }
    interfaces: [{ network: corp, ip: 10.21.0.10 }]
attacker:
  image: ubuntu-noble
  interfaces: [{ network: corp }]
  entry: external
SPEC
$IR render "$SPIKE/tmp/range" -o "$SPIKE/tmp/bundle" --image-cache "$CACHE" --cid-base 4150 >/dev/null 2>&1 \
  && ok "W2 render succeeds for the windows guest (seed/domain shape pinned by test_plan units)" || { bad "W2 render"; exit 1; }
if $IR up "$SPIKE/tmp/bundle" --image-cache "$CACHE" --readiness-timeout 600 >"$SPIKE/tmp/w2.txt" 2>&1; then
  ok "W2b up: the clone specialized and the daemon answered (daemon readiness)"
else
  bad "W2b up"; tail -8 "$SPIKE/tmp/w2.txt"; exit 1
fi

echo "=== W3 the specialize seed applied: hostname, address, SYSTEM exec ==="
BOOT="$SPIKE/tmp/bundle/boot.json"
PROJECT=$(docker ps --format '{{.Names}}' | grep -E '^ir-win-slice1-' | head -1 | sed 's/-range-1$//')
HOSTOUT=$(uv run python design/spikes/_shared/chexec.py --boot "$BOOT" --project "$PROJECT" --guest dc --shell cmd exec 'hostname' 2>&1 | tail -1 | tr -d '\r' | tr '[:upper:]' '[:lower:]')
[[ "$HOSTOUT" == "dc" ]] && ok "W3 the per-boot unattend set the hostname ($HOSTOUT)" || bad "W3 hostname (got: $HOSTOUT)"
IPOUT=$(uv run python design/spikes/_shared/chexec.py --boot "$BOOT" --project "$PROJECT" --guest dc --shell cmd exec 'ipconfig' 2>&1 | grep -c "10.21.0.10" || true)
[[ "$IPOUT" -ge 1 ]] && ok "W3b the MAC-keyed static address applied (10.21.0.10)" || bad "W3b static ip"
WHO=$(uv run python design/spikes/_shared/chexec.py --boot "$BOOT" --project "$PROJECT" --guest dc --shell cmd exec 'whoami' 2>&1 | tail -1 | tr -d '\r')
[[ "$WHO" == *"system"* ]] && ok "W3c exec runs as SYSTEM over vsock ($WHO)" || bad "W3c whoami (got: $WHO)"
# inbound ICMP is dropped by the Windows Firewall's default (realistic
# posture); the honest bidirectional L3 proof is the WINDOWS host pinging the
# attacker and getting replies back across the segment
ATT_IP=$(python3 -c "
import json
plan = json.load(open('$SPIKE/tmp/bundle/plan.json'))
guest = next(g for g in plan['guests'] if g['name'] == 'attacker')
print(guest['interfaces'][0]['ip'])
")
# cmd.exe's `echo WORD || ...` emits a trailing space; trim all whitespace
PING=$(uv run python design/spikes/_shared/chexec.py --boot "$BOOT" --project "$PROJECT" --guest dc --shell cmd exec "ping -n 2 -w 3000 $ATT_IP >nul && echo L3-OK || echo L3-DEAD" 2>&1 | tail -1 | tr -d ' \r')
[[ "$PING" == "L3-OK" ]] && ok "W3d bidirectional L3 across the segment (dc pinged the attacker at $ATT_IP)" || bad "W3d L3 (got: $PING)"

$IR down --all >/dev/null 2>&1 || true
docker ps --format '{{.Names}}' | grep -q '^ir-win-slice1-' && bad "W4 teardown left containers" || ok "W4 teardown clean"
echo
echo "$PASS passed, $FAIL failed"
exit $((FAIL > 0))

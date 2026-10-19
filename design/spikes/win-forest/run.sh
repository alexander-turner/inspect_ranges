#!/bin/bash
# windows-ad-v1 slice 3 battery: whole-range converged capture. A two-domain
# forest (root dc01 = corp.local, child dc02 = north.corp.local with DNS
# delegation, member srv02 joined to the child) builds on the production
# pipeline in CONVERGED mode: all three content hosts quiesce at ONE point
# before any disk is copied, the rebuild is all-or-nothing, and a consumer
# boots the captured forest with cross-domain auth intact (the member's
# secure channel, the child DC's trust channel to the parent, and
# cross-domain DC discovery through the delegated DNS chain). Usage:
# ./run.sh [down]. CID band 4180 (consumer render at 4190).
set -euo pipefail
cd "$(dirname "$0")"
SPIKE="$PWD"
ROOT="$(cd ../../.. && pwd)"
RANGE="$SPIKE/range"

WIN_ISO="${WIN_ISO:-$HOME/.cache/inspect-ranges/images/ws2022-eval.iso}"
VIRTIO_ISO="${VIRTIO_ISO:-$HOME/.cache/inspect-ranges/images/virtio-win.iso}"
NOBLE="${NOBLE:-$HOME/.cache/inspect-ranges/images/noble-server-cloudimg-amd64.img}"
export XDG_STATE_HOME="$SPIKE/tmp/state"
IR="uv run inspect-ranges"
IRBIN="$ROOT/.venv/bin/inspect-ranges"
CACHE="$SPIKE/tmp/cache"
BUILDS="$SPIKE/tmp/builds"
FLAGS=(--image-cache "$CACHE" --build-cache "$BUILDS" --cid-base 4180 --readiness-timeout 900)

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

echo "=== F1 goldens into the battery cache ==="
DB_OUT=$($IR daemon-bundle -o "$SPIKE/tmp/artifacts")
DAEMON_SHA=$(echo "$DB_OUT" | grep -o 'bundle sha256:[0-9a-f]*' | cut -d: -f2)
$IR images derive-windows "$WIN_ISO" --sha256 "$(sha256sum "$WIN_ISO" | cut -d' ' -f1)" \
  --virtio-iso "$VIRTIO_ISO" --virtio-sha256 "$(sha256sum "$VIRTIO_ISO" | cut -d' ' -f1)" \
  --image-cache "$CACHE" --daemon-bundle "$SPIKE/tmp/artifacts" \
  --daemon-sha256 "$DAEMON_SHA" >"$SPIKE/tmp/f1.txt" 2>&1 \
  && ok "F1 the windows golden installed" \
  || { bad "F1 derive-windows"; tail -5 "$SPIKE/tmp/f1.txt"; exit 1; }
$IR images derive "$NOBLE" --sha256 "$(sha256sum "$NOBLE" | cut -d' ' -f1)" --name ubuntu-noble \
  --image-cache "$CACHE" --daemon-bundle "$SPIKE/tmp/artifacts" --daemon-sha256 "$DAEMON_SHA" >/dev/null

echo "=== F2 the forest builds: root, child (serialized behind it), member ==="
if (cd "$RANGE" && "$IRBIN" build "${FLAGS[@]}" --recipe-budget 1800 >"$SPIKE/tmp/f2.txt" 2>&1); then
  grep -q "build OK" "$SPIKE/tmp/f2.txt" && ok "F2 win-forest builds green" \
    || { bad "F2 output"; tail -15 "$SPIKE/tmp/f2.txt"; }
else
  bad "F2 build"; tail -25 "$SPIKE/tmp/f2.txt"; exit 1
fi
QUIESCES=$(grep -c '^quiesce' "$SPIKE/tmp/f2.txt" || true)
[[ "$QUIESCES" -eq 3 ]] && ok "F2b all three guests quiesced at one point (converged capture)" \
  || { bad "F2b quiesce count (got: $QUIESCES)"; grep -i quiesce "$SPIKE/tmp/f2.txt" | tail -4; }
# every quiesce line precedes every capture line
LAST_QUIESCE=$(grep -n '^quiesce' "$SPIKE/tmp/f2.txt" | tail -1 | cut -d: -f1)
FIRST_CAPTURE=$(grep -n '^capture' "$SPIKE/tmp/f2.txt" | head -1 | cut -d: -f1)
[[ -n "$LAST_QUIESCE" && -n "$FIRST_CAPTURE" && "$LAST_QUIESCE" -lt "$FIRST_CAPTURE" ]] \
  && ok "F2c no disk copied before the quiesce point" \
  || bad "F2c ordering (last quiesce line $LAST_QUIESCE vs first capture line $FIRST_CAPTURE)"
REALIZED=$(ls "$CACHE" | grep -c '^win-forest-.*\.realized\.json$' || true)
[[ "$REALIZED" -eq 3 ]] && ok "F2d all three guests captured as realized images" \
  || bad "F2d realized sidecars (got: $REALIZED)"

echo "=== F3 the unchanged forest is a cached no-op ==="
(cd "$RANGE" && "$IRBIN" build "${FLAGS[@]}" >"$SPIKE/tmp/f3.txt" 2>&1) \
  && grep -q "build OK (cached" "$SPIKE/tmp/f3.txt" \
  && ok "F3 the unchanged forest is a cached no-op" \
  || { bad "F3 cached rebuild"; tail -5 "$SPIKE/tmp/f3.txt"; }

echo "=== F4 a consumer boots the captured forest: cross-domain auth intact ==="
export INSPECT_RANGES_BUILD_CACHE="$BUILDS"
$IR render "$RANGE" -o "$SPIKE/tmp/consumer" --image-cache "$CACHE" --cid-base 4190 >"$SPIKE/tmp/f4r.txt" 2>&1 \
  || { bad "F4 render"; tail -8 "$SPIKE/tmp/f4r.txt"; exit 1; }
if $IR up "$SPIKE/tmp/consumer" --image-cache "$CACHE" --readiness-timeout 900 >"$SPIKE/tmp/f4.txt" 2>&1; then
  ok "F4 the consumer boot is ready (all three captured guests)"
else
  bad "F4 up"; tail -8 "$SPIKE/tmp/f4.txt"; exit 1
fi
BOOT="$SPIKE/tmp/consumer/boot.json"
PROJECT=$(docker ps --format '{{.Names}}' | grep -E '^ir-win-forest-' | head -1 | sed 's/-range-1$//')
# probes must be pipe-free: --shell cmd wraps through cmd /c, which steals |
CHX() { uv run python design/spikes/_shared/chexec.py --boot "$BOOT" --project "$PROJECT" --guest "$1" --shell cmd exec "$2" 2>&1 | tr -d '\r' || true; }
DOMAIN=$(CHX srv02 "powershell -NoProfile -NonInteractive -Command (Get-CimInstance Win32_ComputerSystem).Domain" | tail -1)
[[ "$DOMAIN" == "north.corp.local" ]] && ok "F4b the member is still joined to the child domain ($DOMAIN)" \
  || bad "F4b member domain (got: $DOMAIN)"
# a parallel cold boot puts the member's netlogon into DISCOVERY BACKOFF
# while its DC is still coming up (measured: sc_query ERROR_NO_LOGON_SERVERS
# for 8+ min while the DC was long healthy); sc_verify FORCES rediscovery and
# re-establishment — exactly what a consumer's first authenticated operation
# does — and Test-ComputerSecureChannel then confirms the verified state
SCOK=0
for _ in $(seq 1 96); do
  SCOK=$(CHX srv02 "nltest /sc_verify:north.corp.local" | grep -c "NERR_Success" || true)
  [[ "$SCOK" -ge 1 ]] && break
  sleep 5
done
SC=$(CHX srv02 "powershell -NoProfile -NonInteractive -Command \$ok=Test-ComputerSecureChannel; Write-Output SC=\$ok" | tail -1)
[[ "$SCOK" -ge 1 && "$SC" == "SC=True" ]] && ok "F4c the member's secure channel survived the converged capture (sc_verify + TCSC)" \
  || { bad "F4c member secure channel (sc_verify=$SCOK, got: $SC)"; CHX srv02 "nltest /sc_query:north.corp.local" | tail -4; }
TRUST=""
for _ in $(seq 1 60); do
  TRUST=$(CHX dc02 "nltest /sc_verify:corp.local" | grep -c "NERR_Success" || true)
  [[ "$TRUST" -ge 1 ]] && break
  sleep 5
done
[[ "$TRUST" -ge 1 ]] && ok "F4d the child DC's trust channel to the parent verified (nltest sc_verify)" \
  || { bad "F4d trust channel"; CHX dc02 "nltest /sc_verify:corp.local" | tail -4; }
DISCOVER=$(CHX srv02 "nltest /dsgetdc:corp.local" | grep -c '\\\\dc01' || true)
[[ "$DISCOVER" -ge 1 ]] && ok "F4e cross-domain DC discovery through the delegated DNS chain (srv02 found dc01)" \
  || { bad "F4e dsgetdc"; CHX srv02 "nltest /dsgetdc:corp.local" | tail -4; }

$IR down --all >/dev/null 2>&1 || true
docker ps --format '{{.Names}}' | grep -q '^ir-win-forest-' && bad "F5 teardown left containers" || ok "F5 teardown clean"
echo
echo "$PASS passed, $FAIL failed"
exit $((FAIL > 0))

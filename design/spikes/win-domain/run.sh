#!/bin/bash
# windows-ad-v1 slice 2 battery: the Windows build pipeline. A two-guest
# domain builds for real on the production pipeline — the DC promotes a forest
# through a PowerShell recipe (detached reboot, LastBootUpTime barrier), the
# member joins WITHOUT any in-build sysprep (clones specialize from the
# generalized golden with fresh SIDs, so the ad-domain spike's
# sysprep-before-join step is free on this path), the verify engine attributes
# the DC's Windows listeners, both guests capture as realized images (scrubbed
# of build-only state), a rebuild is a cached no-op, and a CONSUMER boots the
# captured pair with the machine secure channel intact. Usage: ./run.sh [down].
# CID band 4160.
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
FLAGS=(--image-cache "$CACHE" --build-cache "$BUILDS" --cid-base 4160 --readiness-timeout 900)

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

echo "=== D1 goldens into the battery cache ==="
DB_OUT=$($IR daemon-bundle -o "$SPIKE/tmp/artifacts")
DAEMON_SHA=$(echo "$DB_OUT" | grep -o 'bundle sha256:[0-9a-f]*' | cut -d: -f2)
$IR images derive-windows "$WIN_ISO" --sha256 "$(sha256sum "$WIN_ISO" | cut -d' ' -f1)" \
  --virtio-iso "$VIRTIO_ISO" --virtio-sha256 "$(sha256sum "$VIRTIO_ISO" | cut -d' ' -f1)" \
  --image-cache "$CACHE" --daemon-bundle "$SPIKE/tmp/artifacts" \
  --daemon-sha256 "$DAEMON_SHA" >"$SPIKE/tmp/d1.txt" 2>&1 \
  && ok "D1 the windows golden installed" \
  || { bad "D1 derive-windows"; tail -5 "$SPIKE/tmp/d1.txt"; exit 1; }
$IR images derive "$NOBLE" --sha256 "$(sha256sum "$NOBLE" | cut -d' ' -f1)" --name ubuntu-noble \
  --image-cache "$CACHE" --daemon-bundle "$SPIKE/tmp/artifacts" --daemon-sha256 "$DAEMON_SHA" >/dev/null

echo "=== D2 the domain builds: promote, join, verify, capture ==="
if (cd "$RANGE" && "$IRBIN" build "${FLAGS[@]}" --recipe-budget 1800 >"$SPIKE/tmp/d2.txt" 2>&1); then
  grep -q "build OK" "$SPIKE/tmp/d2.txt" && ok "D2 win-domain builds green" \
    || { bad "D2 output"; tail -15 "$SPIKE/tmp/d2.txt"; }
else
  bad "D2 build"; tail -25 "$SPIKE/tmp/d2.txt"; exit 1
fi
grep -q "recipe=win.dc-promote" "$SPIKE/tmp/d2.txt" \
  && grep -q "recipe=win.domain-join" "$SPIKE/tmp/d2.txt" \
  && ok "D2b both domain recipes ran (promote before join, declaration order)" \
  || { bad "D2b recipe records"; grep -i recipe "$SPIKE/tmp/d2.txt" | tail -6; }
# the verify engine attributed the DC's Windows listeners (dns/ldap/kerberos/smb + srv's smb)
VOK=$(grep -c '^verify    ok' "$SPIKE/tmp/d2.txt" || true)
[[ "$VOK" -eq 5 ]] && ok "D2c verify attributed all 5 Windows listener declarations" \
  || { bad "D2c verify count (got: $VOK)"; grep -i verify "$SPIKE/tmp/d2.txt" | tail -8; }
REALIZED=$(ls "$CACHE" | grep -c '^win-domain-.*\.realized\.json$' || true)
[[ "$REALIZED" -eq 2 ]] && ok "D2d both guests captured as realized images" \
  || bad "D2d realized sidecars (got: $REALIZED)"

echo "=== D3 a rebuild is a cached no-op ==="
(cd "$RANGE" && "$IRBIN" build "${FLAGS[@]}" >"$SPIKE/tmp/d3.txt" 2>&1) \
  && grep -q "build OK (cached" "$SPIKE/tmp/d3.txt" \
  && ok "D3 the unchanged range is a cached no-op" \
  || { bad "D3 cached rebuild"; tail -5 "$SPIKE/tmp/d3.txt"; }

echo "=== D4 a consumer boots the captured pair: domain intact ==="
export INSPECT_RANGES_BUILD_CACHE="$BUILDS"
$IR render "$RANGE" -o "$SPIKE/tmp/consumer" --image-cache "$CACHE" --cid-base 4170 >"$SPIKE/tmp/d4r.txt" 2>&1 \
  || { bad "D4 render"; tail -8 "$SPIKE/tmp/d4r.txt"; exit 1; }
if $IR up "$SPIKE/tmp/consumer" --image-cache "$CACHE" --readiness-timeout 900 >"$SPIKE/tmp/d4.txt" 2>&1; then
  ok "D4 the consumer boot is ready (daemon readiness on both captured guests)"
else
  bad "D4 up"; tail -8 "$SPIKE/tmp/d4.txt"; exit 1
fi
BOOT="$SPIKE/tmp/consumer/boot.json"
PROJECT=$(docker ps --format '{{.Names}}' | grep -E '^ir-win-domain-' | head -1 | sed 's/-range-1$//')
# NOTE: --shell cmd wraps through cmd /c, which steals | & ^ < > before
# PowerShell sees them — probes here must be pipe-free (measured: a piped
# probe dies with "'Where-Object' is not recognized")
CHX() { uv run python design/spikes/_shared/chexec.py --boot "$BOOT" --project "$PROJECT" --guest "$1" --shell cmd exec "$2" 2>&1 | tr -d '\r' || true; }
DOMAIN=$(CHX srv "powershell -NoProfile -NonInteractive -Command (Get-CimInstance Win32_ComputerSystem).Domain" | tail -1)
[[ "$DOMAIN" == "range.local" ]] && ok "D4b the captured member is still domain-joined ($DOMAIN)" \
  || bad "D4b member domain (got: $DOMAIN)"
# the channel re-establishes AFTER readiness (netlogon re-validates lazily on
# a cold boot; measured: False at ready, True on re-query minutes later) —
# the proof is convergence-gated like every app-stack assertion
SC=""
for _ in $(seq 1 96); do
  SC=$(CHX srv "powershell -NoProfile -NonInteractive -Command \$ok=Test-ComputerSecureChannel; Write-Output SC=\$ok" | tail -1)
  [[ "$SC" == "SC=True" ]] && break
  sleep 5
done
[[ "$SC" == "SC=True" ]] && ok "D4c the machine secure channel survived capture and reboot" \
  || { bad "D4c secure channel (got: $SC)"; CHX srv "nltest /sc_query:range.local" | tail -4; }
DNSLIST=$(CHX srv "powershell -NoProfile -NonInteractive -Command \$ifx=(Get-NetIPAddress -IPAddress 10.30.0.20).InterfaceIndex; \$x=(Get-DnsClientServerAddress -InterfaceIndex \$ifx -AddressFamily IPv4).ServerAddresses; Write-Output (\$x -join ',')" | tail -1)
[[ "$DNSLIST" == "10.30.0.10" ]] && ok "D4d the scrub stripped the build resolver (DNS: $DNSLIST)" \
  || bad "D4d baked DNS (got: $DNSLIST)"
DCROLE=$(CHX dc "powershell -NoProfile -NonInteractive -Command (Get-CimInstance Win32_ComputerSystem).DomainRole" | tail -1)
[[ "$DCROLE" == "5" ]] && ok "D4e the captured DC boots as a primary domain controller (role $DCROLE)" \
  || bad "D4e dc role (got: $DCROLE)"

$IR down --all >/dev/null 2>&1 || true
docker ps --format '{{.Names}}' | grep -q '^ir-win-domain-' && bad "D5 teardown left containers" || ok "D5 teardown clean"
echo
echo "$PASS passed, $FAIL failed"
exit $((FAIL > 0))

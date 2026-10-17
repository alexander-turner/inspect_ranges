#!/bin/bash
# build-v1 slice 3 battery: the era-class (bionic) golden.
# Measured first: xenial GA cannot carry the daemon (kernel 4.4 has no
# virtio-vsock transport; only vmw_vsock_vmci), so the era class is bionic
# (4.15, vmw_vsock_virtio_transport present, cloud-init 23.1 backported).
# Proves: derive on bionic unchanged, noble+bionic coexisting in one cache
# under distinct keys, corrupted-vendor refusal, the full render/up path on a
# bionic guest (netplan v2, readiness, daemon on vsock, zero listeners, agent
# user), and the slice-1 executor against the era guest.
# Usage: ./run.sh [down]. See README.md.
set -euo pipefail
cd "$(dirname "$0")"
SPIKE="$PWD"
ROOT="$(cd ../../.. && pwd)"

NOBLE="${NOBLE:-$HOME/.cache/inspect-ranges/images/noble-server-cloudimg-amd64.img}"
ERA="${ERA:-$HOME/.cache/inspect-ranges/images/focal-server-cloudimg-amd64.img}"
export XDG_STATE_HOME="$SPIKE/tmp/state"
IR="uv run inspect-ranges"
IRBIN="$ROOT/.venv/bin/inspect-ranges"
C() { (cd "$ROOT" && uv run python design/spikes/_shared/chexec.py --cid 3400 --user "${2:-root}" exec "$1"); }
CACHE="$SPIKE/tmp/cache"

if [[ "${1:-}" == "down" ]]; then
  (cd "$ROOT" && $IR down --all) || true
  exit 0
fi

grep -q vhost_vsock /proc/modules || { echo "need: sudo modprobe vhost_vsock"; exit 1; }
[[ -f "$NOBLE" ]] || { echo "missing noble vendor image $NOBLE"; exit 1; }
[[ -f "$ERA" ]] || { echo "missing focal vendor image $ERA (cloud-images.ubuntu.com/focal/current/)"; exit 1; }

PASS=0; FAIL=0
ok()  { echo "PASS  $1"; PASS=$((PASS+1)); }
bad() { echo "FAIL  $1"; FAIL=$((FAIL+1)); }

exec 9>/tmp/inspect-ranges-battery.lock
flock 9

cd "$ROOT"
$IR down --all >/dev/null 2>&1 || true
rm -rf "$SPIKE/tmp" && mkdir -p "$SPIKE/tmp"

echo "=== derive both classes into one cache ==="
DB_OUT=$($IR daemon-bundle -o "$SPIKE/tmp/artifacts") \
  || { echo "daemon-bundle build failed (install the pinned Go toolchain)"; exit 1; }
DAEMON_SHA=$(echo "$DB_OUT" | grep -o 'bundle sha256:[0-9a-f]*' | cut -d: -f2)
ERA_SHA=$(sha256sum "$ERA" | cut -d' ' -f1)
NOBLE_SHA=$(sha256sum "$NOBLE" | cut -d' ' -f1)

if $IR images derive "$ERA" --sha256 "$ERA_SHA" --name era-guest \
     --image-cache "$CACHE" --daemon-bundle "$SPIKE/tmp/artifacts" --daemon-sha256 "$DAEMON_SHA" | tee "$SPIKE/tmp/e1.txt"; then
  grep -q "derived: era-guest.qcow2" "$SPIKE/tmp/e1.txt" && ok "E1 focal derive unchanged" || bad "E1 focal derive output"
else
  bad "E1 focal derive"
fi

$IR images derive "$NOBLE" --sha256 "$NOBLE_SHA" --name noble-guest \
  --image-cache "$CACHE" --daemon-bundle "$SPIKE/tmp/artifacts" --daemon-sha256 "$DAEMON_SHA" >/dev/null \
  && ok "E2a noble derives into the same cache" || bad "E2a noble derive"
K1=$(python3 -c "import json;print(json.load(open('$CACHE/era-guest.json'))['derivation_key'])")
K2=$(python3 -c "import json;print(json.load(open('$CACHE/noble-guest.json'))['derivation_key'])")
[[ -n "$K1" && -n "$K2" && "$K1" != "$K2" ]] && ok "E2b distinct derivation keys coexist" || bad "E2b keys (K1=$K1 K2=$K2)"
$IR images list --image-cache "$CACHE" | grep -q "era-guest.qcow2" \
  && $IR images list --image-cache "$CACHE" | grep -q "noble-guest.qcow2" \
  && ok "E2c images list shows both classes" || bad "E2c images list"

echo "=== E3 corrupted focal vendor refuses before cache writes ==="
CACHE2="$SPIKE/tmp/cache2"
if $IR images derive "$ERA" --sha256 "$(printf '0%.0s' {1..64})" --name era-guest \
     --image-cache "$CACHE2" --daemon-bundle "$SPIKE/tmp/artifacts" --daemon-sha256 "$DAEMON_SHA" >"$SPIKE/tmp/e3.txt" 2>&1; then
  bad "E3 vendor digest mismatch refused"
else
  grep -q "verify-vendor" "$SPIKE/tmp/e3.txt" && [[ ! -d "$CACHE2" || -z "$(ls -A "$CACHE2")" ]] \
    && ok "E3 vendor mismatch refused before cache writes" || bad "E3 refusal shape"
fi

echo "=== E4-E9 the era guest end to end (build verb, kept) ==="
if (cd "$SPIKE/fixtures/erarange" && "$IRBIN" build --keep --image-cache "$CACHE" --cid-base 3400 --readiness-timeout 300 | tee "$SPIKE/tmp/e4.txt"); then
  grep -q "build OK" "$SPIKE/tmp/e4.txt" && ok "E4 focal range builds (render, netplan v2, readiness, recipes)" || bad "E4 build OK line"
else
  bad "E4 focal build"
fi
PROJECT=$(basename "$(ls -d "$XDG_STATE_HOME"/inspect-ranges/projects/ir-era-* 2>/dev/null | head -1)")

WHOAMI=$(C "id -un")
[[ "$WHOAMI" == "root" ]] && ok "E5 daemon answers on vsock (root exec)" || bad "E5 daemon exec (got: $WHOAMI)"
AGENT=$(C "id -un agent" || true)
[[ "$AGENT" == *agent* ]] && ok "E6 agent user baked" || bad "E6 agent user (got: $AGENT)"
# the posture: no TCP listeners (ssh mask held), nothing on privileged ports
# (resolved stub off); ephemeral client sockets (timesyncd NTP) are not services
TCP_L=$(C "ss -tlnH | wc -l")
LOW=$(C "ss -tulnH | awk '{n=split(\$5,a,\":\"); if (a[n]+0 < 1024) print}' | wc -l")
[[ "$TCP_L" == "0" && "$LOW" == "0" ]] && ok "E7 no TCP listeners, no privileged-port sockets" \
  || { bad "E7 listeners (tcp=$TCP_L low=$LOW)"; C "ss -tulnp" || true; }
ERA_OK=$(C "cat /opt/era-ok" || true)
[[ "$ERA_OK" == "era-recipe-ran" ]] && ok "E8 slice-1 executor works against the era guest" || bad "E8 executor (got: $ERA_OK)"

RELEASE=$(C "grep VERSION_ID /etc/os-release")
[[ "$RELEASE" == *20.04* ]] && ok "E9 the guest really is focal ($RELEASE)" || bad "E9 release (got: $RELEASE)"

$IR down "$PROJECT" >/dev/null
$IR down --all >/dev/null 2>&1 || true

echo
echo "$PASS passed, $FAIL failed"
exit $((FAIL > 0))

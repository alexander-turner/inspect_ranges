#!/bin/bash
# standard-images-v1 slice 1 battery: the attack image factory, live. The
# kali-class toolset recipe builds over the noble golden (metasploit from its
# official apt repo, everything else distro apt, presence-asserted in the
# recipe), the capture is a realized image, and a consumer range whose
# ATTACKER boots that image answers tool probes over the channel: the
# dedicated attack box the schema has promised since v0.1, as bytes.
# Usage: ./run.sh [down]. CID band 4060.
set -euo pipefail
cd "$(dirname "$0")"
SPIKE="$PWD"
ROOT="$(cd ../../.. && pwd)"
RANGE="$ROOT/catalog/attack"

NOBLE="${NOBLE:-$HOME/.cache/inspect-ranges/images/noble-server-cloudimg-amd64.img}"
export XDG_STATE_HOME="$SPIKE/tmp/state"
IR="uv run inspect-ranges"
IRBIN="$ROOT/.venv/bin/inspect-ranges"
CACHE="$SPIKE/tmp/cache"
BUILDS="$SPIKE/tmp/builds"
FLAGS=(--image-cache "$CACHE" --build-cache "$BUILDS" --cid-base 4060 --readiness-timeout 300)

if [[ "${1:-}" == "down" ]]; then
  (cd "$ROOT" && $IR down --all) || true
  exit 0
fi

grep -q vhost_vsock /proc/modules || { echo "need: sudo modprobe vhost_vsock"; exit 1; }
[[ -f "$NOBLE" ]] || { echo "missing noble vendor image $NOBLE"; exit 1; }

PASS=0; FAIL=0
ok()  { echo "PASS  $1"; PASS=$((PASS+1)); }
bad() { echo "FAIL  $1"; FAIL=$((FAIL+1)); }

exec 9>/tmp/inspect-ranges-battery.lock
flock 9

cd "$ROOT"
$IR down --all >/dev/null 2>&1 || true
rm -rf "$SPIKE/tmp" && mkdir -p "$SPIKE/tmp"

echo "=== A1 build the attack factory (toolset recipe + presence assertions) ==="
DB_OUT=$($IR daemon-bundle -o "$SPIKE/tmp/artifacts")
DAEMON_SHA=$(echo "$DB_OUT" | grep -o 'bundle sha256:[0-9a-f]*' | cut -d: -f2)
NOBLE_SHA=$(sha256sum "$NOBLE" | cut -d' ' -f1)
$IR images derive "$NOBLE" --sha256 "$NOBLE_SHA" --name ubuntu-noble \
  --image-cache "$CACHE" --daemon-bundle "$SPIKE/tmp/artifacts" --daemon-sha256 "$DAEMON_SHA" >/dev/null
if (cd "$RANGE" && "$IRBIN" build "${FLAGS[@]}" --recipe-budget 1800 >"$SPIKE/tmp/a1.txt" 2>&1); then
  grep -q "build OK" "$SPIKE/tmp/a1.txt" && ok "A1 the attack image builds green (recipe assertions passed in-build)" || bad "A1 build OK line"
else
  bad "A1 build"; tail -15 "$SPIKE/tmp/a1.txt"; exit 1
fi
REALIZED=$(ls "$CACHE" | grep -E '^attack-box-[0-9a-f]+\.qcow2$' | head -1)
[[ -n "$REALIZED" ]] && ok "A2 the realized attack image is in the cache ($REALIZED)" || { bad "A2 realized file"; exit 1; }

echo "=== A3 a consumer range's ATTACKER boots the image and the toolset answers ==="
mkdir -p "$SPIKE/tmp/consumer"
cat > "$SPIKE/tmp/consumer/range.yaml" <<SPEC
range:
  name: attack-consumer
  schema_version: "0.3"
  description: slice-1 consumer; the attacker boots the realized attack image
networks:
  - name: lab
    cidr: 10.98.0.0/24
    mode: isolated
hosts:
  - name: web
    os: { type: linux }
    image: ubuntu-noble
    interfaces: [{ network: lab, ip: 10.98.0.10 }]
attacker:
  image: $REALIZED
  interfaces: [{ network: lab }]
  entry: external
SPEC
$IR render "$SPIKE/tmp/consumer" -o "$SPIKE/tmp/bundle" --image-cache "$CACHE" --cid-base 4061 >/dev/null 2>&1 \
  && ok "A3 render accepts the realized image as the attacker" || bad "A3 render"
$IR up "$SPIKE/tmp/bundle" --image-cache "$CACHE" >"$SPIKE/tmp/a3up.txt" 2>&1 \
  && ok "A3b the attack box boots (under cloud-hypervisor, the attacker default)" || { bad "A3b up"; tail -5 "$SPIKE/tmp/a3up.txt"; }
RC=$(docker ps --format '{{.Names}}' | grep -E '^ir-attack-consumer-.*-range-1$' | head -1)
TOOLS=$(cd "$ROOT" && uv run python design/spikes/_shared/chexec.py --boot "$SPIKE/tmp/bundle/boot.json" --project "${RC%-range-1}" --guest attacker --user root exec \
  'for t in nmap sqlmap hydra john msfconsole msfvenom ncat socat gobuster ffuf smbclient; do command -v $t >/dev/null && printf "%s " $t; done' || true)
WANT="nmap sqlmap hydra john msfconsole msfvenom ncat socat gobuster ffuf smbclient"
[[ "$TOOLS" == "$WANT " || "$TOOLS" == "$WANT" ]] \
  && ok "A3c every ratified tool answers on the booted attack box" || bad "A3c tools (got: $TOOLS)"
SCAN=$(cd "$ROOT" && uv run python design/spikes/_shared/chexec.py --boot "$SPIKE/tmp/bundle/boot.json" --project "${RC%-range-1}" --guest attacker --user root exec \
  'nmap -p 22 -Pn 10.98.0.10 2>/dev/null | grep -E "^22/tcp" | head -1' || true)
[[ "$SCAN" =~ (closed|open) ]] && ok "A3d nmap gets an L3 answer from the lab host (got: $SCAN)" || bad "A3d scan (got: $SCAN)"
MSF=$(cd "$ROOT" && uv run python design/spikes/_shared/chexec.py --boot "$SPIKE/tmp/bundle/boot.json" --project "${RC%-range-1}" --guest attacker --user root exec \
  'msfvenom --list formats 2>/dev/null | grep -ci "elf" || true' || true)
[[ "${MSF:-0}" -ge 1 ]] && ok "A3e the metasploit framework is functional (msfvenom enumerates formats)" || bad "A3e msf (got: $MSF)"
LISTEN=$(cd "$ROOT" && uv run python design/spikes/_shared/chexec.py --boot "$SPIKE/tmp/bundle/boot.json" --project "${RC%-range-1}" --guest attacker --user root exec \
  'ss -H -tuln | awk "{split(\$5,a,\":\"); port=a[length(a)]+0; if (\$5 ~ /^127\\./ || \$5 ~ /^\\[::1\\]/) next; if (\$1==\"udp\" && (port>=32768 || port==68)) next; print}" | head -3' || true)
[[ -z "$LISTEN" ]] && ok "A3f the booted attack box has ZERO non-loopback listeners (the containment invariant, live)" || bad "A3f listeners (got: $LISTEN)"
MANIFEST=$(cd "$ROOT" && uv run python design/spikes/_shared/chexec.py --boot "$SPIKE/tmp/bundle/boot.json" --project "${RC%-range-1}" --guest attacker --user root exec \
  'wc -l < /etc/attack-image.manifest' || true)
[[ "${MANIFEST:-0}" -ge 100 ]] && ok "A3g the image carries its recorded package manifest ($MANIFEST lines)" || bad "A3g manifest (got: $MANIFEST)"
$IR down --all >/dev/null 2>&1 || true

echo
echo "$PASS passed, $FAIL failed"
exit $((FAIL > 0))

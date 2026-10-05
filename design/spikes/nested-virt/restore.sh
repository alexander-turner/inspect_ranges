#!/bin/bash
# Rung 4 of the nested-virt battery: restore the AD checkpoint bundle built on
# the metal host (named CPU model Skylake-Server-noTSX-IBRS) on this nested
# host, then rerun checkpoint-clone's sample-independence verification against
# it (destructive sample A, pristine sample B). Reuses the checkpoint-clone
# compose project and ga.py. Expects fetch.sh to have populated the caches.
# Usage: ./restore.sh [down]
set -euo pipefail
cd "$(dirname "$0")"
mkdir -p tmp

export IMAGE_CACHE="${IMAGE_CACHE:-$HOME/.cache/inspect-ranges/images}"
CKPT="${CKPT_CACHE:-$HOME/.cache/inspect-ranges/checkpoints}/ad-pair"
V="virsh -c qemu:///system"
CC=../checkpoint-clone

if [[ "${1:-}" == "down" ]]; then
  (cd "$CC" && docker compose down -v)
  exit 0
fi

[[ -f "$CKPT/dc01.mem" ]] || { echo "missing $CKPT (run fetch.sh first)"; exit 1; }

cd "$CC"
docker compose up -d --build --wait

echo "=== host CPU vs bundle CPU model ==="
docker compose exec -T range sh -c "$V capabilities | grep -A1 '<cpu>' | grep model || true"
grep -o "<model[^>]*>[^<]*</model>" "$CKPT/dc01.xml" | head -1

echo "=== seed scratch: golden + bundle (one-time, not part of per-sample cost) ==="
TSEED=$(date +%s)
docker compose exec -T range sh -c "cp /images/win-golden.qcow2 /scratch/win-golden.qcow2 && mkdir -p /scratch/ckpt"
for f in dc01.xml ws01.xml dc01.mem ws01.mem dc01.qcow2 ws01.qcow2; do
  docker compose cp "$CKPT/$f" "range:/scratch/ckpt/$f"
done
echo "seed: $(( $(date +%s) - TSEED ))s"

instantiate() {  # fresh overlays on the bundle, restore, fix clocks
  docker compose exec -T range sh -c '
    set -e
    ip link add br-ad type bridge 2>/dev/null || true
    ip link set br-ad up
    qemu-img create -f qcow2 -F qcow2 -b /scratch/ckpt/dc01.qcow2 /scratch/dc01.qcow2 40G >/dev/null
    qemu-img create -f qcow2 -F qcow2 -b /scratch/ckpt/ws01.qcow2 /scratch/ws01.qcow2 40G >/dev/null
  '
  docker compose exec -T range $V restore /scratch/ckpt/dc01.mem >/dev/null
  docker compose exec -T range $V restore /scratch/ckpt/ws01.mem >/dev/null
  python3 ga.py wait dc01 180
  python3 ga.py wait ws01 180
  python3 ga.py settime dc01
  python3 ga.py settime ws01
}

discard() {
  docker compose exec -T range sh -c "$V destroy dc01; $V destroy ws01; rm -f /scratch/dc01.qcow2 /scratch/ws01.qcow2"
}

echo "=== sample A: cross-host instantiate, verify domain, then be destructive ==="
TA=$(date +%s)
instantiate
echo "sample A instantiate (overlays + restore pair + clocks): $(( $(date +%s) - TA ))s"
SECRET_A="FLAG{$(openssl rand -hex 8)}"
python3 ga.py ps dc01 300 <<EOF
\$ProgressPreference = 'SilentlyContinue'
\$ErrorActionPreference = 'Stop'
Set-Content -Path C:\\sample-secret.txt -Value '$SECRET_A'
Import-Module ActiveDirectory
Get-ADDomain range.lab | Out-Null
Resolve-DnsName -Type SRV _ldap._tcp.range.lab -Server 127.0.0.1 | Out-Null
'A: domain healthy (AD + DNS SRV), secret planted'
EOF
python3 ga.py ps ws01 300 <<'EOF'
$ProgressPreference = 'SilentlyContinue'
$ErrorActionPreference = 'Stop'
if (-not (Test-ComputerSecureChannel)) { exit 1 }
'A: secure channel OK across host migration'
EOF
python3 ga.py ps dc01 300 <<'EOF'
$ProgressPreference = 'SilentlyContinue'
$ErrorActionPreference = 'Stop'
Import-Module ActiveDirectory
Remove-ADUser tester -Confirm:$false
'A: destroyed - removed RANGE\tester'
EOF
python3 ga.py ps ws01 300 <<'EOF'
$ProgressPreference = 'SilentlyContinue'
$ErrorActionPreference = 'Stop'
Set-Content -Path C:\junk.txt -Value 'residue from sample A'
'A: destroyed - junk file on member'
EOF
discard >/dev/null

echo "=== sample B: fresh instantiation must show no trace of sample A ==="
TB=$(date +%s)
instantiate
echo "sample B instantiate: $(( $(date +%s) - TB ))s"
SECRET_B="FLAG{$(openssl rand -hex 8)}"
python3 ga.py ps dc01 300 <<EOF
\$ProgressPreference = 'SilentlyContinue'
\$ErrorActionPreference = 'Stop'
Import-Module ActiveDirectory
Get-ADDomain range.lab | Out-Null
if (-not (Get-ADUser -Filter "SamAccountName -eq 'tester'")) { 'B: FAIL tester missing'; exit 1 }
'B: tester present (sample A deletion did not persist)'
if (Test-Path C:\\sample-secret.txt) { 'B: FAIL sample A secret persisted'; exit 1 }
'B: sample A secret absent'
Set-Content -Path C:\\sample-secret.txt -Value '$SECRET_B'
if ((Get-Content C:\\sample-secret.txt) -ne '$SECRET_B') { exit 1 }
'B: fresh secret planted and read back'
EOF
python3 ga.py ps ws01 300 <<'EOF'
$ProgressPreference = 'SilentlyContinue'
$ErrorActionPreference = 'Stop'
if (Test-Path C:\junk.txt) { 'B: FAIL junk from sample A persisted'; exit 1 }
'B: no junk from sample A'
if (-not (Test-ComputerSecureChannel)) { exit 1 }
'B: secure channel OK'
EOF
discard >/dev/null

echo "OK: cross-host restore verified. Tear down with: ./restore.sh down"

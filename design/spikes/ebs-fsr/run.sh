#!/bin/bash
# EBS/FSR cold-start spike: measure the designed fleet image-distribution path
# (image cache as an EBS snapshot; volumes hydrate lazily from S3; FSR removes
# the first-touch penalty). Runs on the devbox itself: volumes are created
# from the snapshot and attached HERE, so no new instances are needed —
# hydration and FSR are volume properties, not instance properties.
#
# Needs: the EC2/EBS permissions in policy.json (the devbox role has none by
# default) and passwordless sudo (mkfs/mount/drop_caches).
#
# Costs (us-east-1, approximate): 3 x 10 GiB gp3 volumes for ~1 h = cents;
# ~6 GiB snapshot = cents/month while kept; FSR = $0.75/hour/AZ with a
# 1-hour minimum — enabled late, disabled in cleanup.
#
# Usage: ./run.sh [all|prepare|snapshot|measure-cold|enable-fsr|measure-fsr|baseline|cleanup]
set -euo pipefail
cd "$(dirname "$0")"

export IMAGE_CACHE="${IMAGE_CACHE:-$HOME/.cache/inspect-ranges/images}"
AZ=$(ec2metadata --availability-zone)
INSTANCE_ID=$(ec2metadata --instance-id)
STATE=tmp/state.env
mkdir -p tmp
[[ -f "$STATE" ]] && source "$STATE"

save_state() { printf '%s=%s\n' "$1" "$2" >> "$STATE"; eval "$1=$2"; }

wait_device() {  # $1 volume-id -> echoes device path
  local id="${1//-/}" dev=""
  for _ in $(seq 1 60); do
    dev=$(readlink -f "/dev/disk/by-id/nvme-Amazon_Elastic_Block_Store_${id}" 2>/dev/null || true)
    [[ -n "$dev" && -b "$dev" ]] && { echo "$dev"; return 0; }
    sleep 2
  done
  echo "device for $1 never appeared" >&2
  return 1
}

attach() {  # $1 volume-id, $2 device-letter -> echoes device path
  aws ec2 attach-volume --volume-id "$1" --instance-id "$INSTANCE_ID" --device "/dev/sd$2" >/dev/null
  wait_device "$1"
}

timed_read() {  # $1 mountpoint: direct-IO read of every file, prints MB/s
  local total_mb=0 t0 t1
  t0=$(date +%s.%N)
  for f in "$1"/*; do
    [[ -f "$f" ]] || continue
    local mb=$(( $(stat -c %s "$f") / 1048576 ))
    sudo dd if="$f" of=/dev/null bs=1M iflag=direct status=none
    total_mb=$((total_mb + mb))
  done
  t1=$(date +%s.%N)
  python3 -c "print(f'read {$total_mb} MB in {$t1-$t0:.1f}s = {$total_mb/($t1-$t0):.0f} MB/s')"
}

phase_prepare() {
  echo "=== prepare: cache volume (10 GiB gp3) with images + 5 GiB filler ==="
  VOL_SRC=$(aws ec2 create-volume --availability-zone "$AZ" --size 10 --volume-type gp3 \
    --tag-specifications 'ResourceType=volume,Tags=[{Key=Name,Value=inspect-ranges-fsr-spike-src}]' \
    --query VolumeId --output text)
  save_state VOL_SRC "$VOL_SRC"
  aws ec2 wait volume-available --volume-ids "$VOL_SRC"
  DEV=$(attach "$VOL_SRC" f)
  sudo mkfs.ext4 -q "$DEV"
  sudo mkdir -p /mnt/fsr-src && sudo mount "$DEV" /mnt/fsr-src
  sudo cp "$IMAGE_CACHE/noble-server-cloudimg-amd64.img" "$IMAGE_CACHE/noble-range-guest.qcow2" /mnt/fsr-src/
  sudo dd if=/dev/urandom of=/mnt/fsr-src/filler.bin bs=1M count=5120 status=none
  sudo chmod -R a+r /mnt/fsr-src
  df -h /mnt/fsr-src | tail -1
}

phase_snapshot() {
  echo "=== snapshot the cache volume ==="
  sudo umount /mnt/fsr-src
  SNAP=$(aws ec2 create-snapshot --volume-id "$VOL_SRC" \
    --tag-specifications 'ResourceType=snapshot,Tags=[{Key=Name,Value=inspect-ranges-fsr-spike}]' \
    --query SnapshotId --output text)
  save_state SNAP "$SNAP"
  echo "waiting for snapshot $SNAP to complete..."
  aws ec2 wait snapshot-completed --snapshot-ids "$SNAP"
  aws ec2 detach-volume --volume-id "$VOL_SRC" >/dev/null
  aws ec2 wait volume-available --volume-ids "$VOL_SRC"
  aws ec2 delete-volume --volume-id "$VOL_SRC"
  echo "snapshot complete: $SNAP"
}

measure_volume() {  # $1 label, $2 device-letter -> creates volume from SNAP, measures, deletes
  local label=$1 letter=$2 vol dev
  vol=$(aws ec2 create-volume --availability-zone "$AZ" --snapshot-id "$SNAP" --volume-type gp3 \
    --tag-specifications "ResourceType=volume,Tags=[{Key=Name,Value=inspect-ranges-fsr-spike-$label}]" \
    --query VolumeId --output text)
  aws ec2 wait volume-available --volume-ids "$vol"
  dev=$(attach "$vol" "$letter")
  sudo mkdir -p "/mnt/fsr-$label" && sudo mount -o ro "$dev" "/mnt/fsr-$label"
  echo "--- $label: cold sequential read (direct IO, first touch) ---"
  timed_read "/mnt/fsr-$label"
  echo "--- $label: second pass (volume now hydrated) ---"
  timed_read "/mnt/fsr-$label"
  sudo umount "/mnt/fsr-$label"
  aws ec2 detach-volume --volume-id "$vol" >/dev/null
  aws ec2 wait volume-available --volume-ids "$vol"
  aws ec2 delete-volume --volume-id "$vol"
}

phase_measure_cold() {
  echo "=== volume from snapshot WITHOUT FSR (lazy S3 hydration) ==="
  measure_volume cold g
}

phase_enable_fsr() {
  echo "=== enable FSR on $SNAP in $AZ (\$0.75/hr, 1-hour minimum; disabled in cleanup) ==="
  aws ec2 enable-fast-snapshot-restores --availability-zones "$AZ" --source-snapshot-ids "$SNAP" >/dev/null
  echo "waiting for FSR state=enabled (optimizing can take a few minutes)..."
  for _ in $(seq 1 120); do
    state=$(aws ec2 describe-fast-snapshot-restores \
      --filters "Name=snapshot-id,Values=$SNAP" "Name=availability-zone,Values=$AZ" \
      --query 'FastSnapshotRestores[0].State' --output text)
    echo "  fsr state: $state"
    [[ "$state" == "enabled" ]] && return 0
    sleep 30
  done
  echo "FSR never reached enabled"; return 1
}

phase_measure_fsr() {
  echo "=== volume from snapshot WITH FSR enabled ==="
  measure_volume fsr h
}

phase_baseline() {
  echo "=== baseline: same files from the local root volume (gp3), cold page cache ==="
  sudo sh -c 'sync; echo 3 > /proc/sys/vm/drop_caches'
  mkdir -p tmp/baseline-cache
  cp "$IMAGE_CACHE/noble-server-cloudimg-amd64.img" "$IMAGE_CACHE/noble-range-guest.qcow2" tmp/baseline-cache/ 2>/dev/null || true
  sudo sh -c 'sync; echo 3 > /proc/sys/vm/drop_caches'
  timed_read "$(pwd)/tmp/baseline-cache"
  rm -rf tmp/baseline-cache
}

phase_cleanup() {
  echo "=== cleanup: FSR off, volumes + snapshot deleted ==="
  if [[ -n "${SNAP:-}" ]]; then
    aws ec2 disable-fast-snapshot-restores --availability-zones "$AZ" --source-snapshot-ids "$SNAP" >/dev/null 2>&1 || true
  fi
  for v in $(aws ec2 describe-volumes --filters Name=tag:Name,Values='inspect-ranges-fsr-spike*' \
      --query 'Volumes[].VolumeId' --output text); do
    aws ec2 detach-volume --volume-id "$v" >/dev/null 2>&1 || true
    aws ec2 wait volume-available --volume-ids "$v" 2>/dev/null || true
    aws ec2 delete-volume --volume-id "$v" >/dev/null 2>&1 || true
    echo "deleted $v"
  done
  if [[ -n "${SNAP:-}" ]]; then
    aws ec2 delete-snapshot --snapshot-id "$SNAP" >/dev/null 2>&1 && echo "deleted $SNAP" || echo "snapshot $SNAP delete failed (FSR may still be disabling; re-run cleanup)"
  fi
  sudo umount /mnt/fsr-src /mnt/fsr-cold /mnt/fsr-fsr 2>/dev/null || true
}

case "${1:-all}" in
  prepare)      phase_prepare ;;
  snapshot)     phase_snapshot ;;
  measure-cold) phase_measure_cold ;;
  enable-fsr)   phase_enable_fsr ;;
  measure-fsr)  phase_measure_fsr ;;
  baseline)     phase_baseline ;;
  cleanup)      phase_cleanup ;;
  all)
    phase_prepare
    phase_snapshot
    phase_measure_cold
    phase_enable_fsr
    phase_measure_fsr
    phase_baseline
    phase_cleanup
    ;;
  *) echo "unknown phase: $1"; exit 1 ;;
esac
echo "OK ($1)"

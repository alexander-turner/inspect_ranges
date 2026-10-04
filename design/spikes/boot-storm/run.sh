#!/bin/bash
# Boot-storm density spike: N concurrent ranges (1 container + 2 Linux VMs
# each) launched simultaneously; per-range time from storm start to fully
# provisioned (both VMs cloud-init complete), plus host disk I/O deltas.
# See README.md. Usage: ./run.sh [down]
set -euo pipefail
cd "$(dirname "$0")"

export IMAGE_CACHE="${IMAGE_CACHE:-$HOME/.cache/inspect-ranges/images}"
C="python3 ../vsock-exec/host/client.py"
ROUNDS="${ROUNDS:-1 2 4 8 16 24}"
DISK="nvme0n1"

down_all() {
  # this compose version's `ls` lacks template output: enumerate via labels
  for p in $(docker ps -a --format '{{.Label "com.docker.compose.project"}}' | sort -u | grep '^storm-' || true); do
    docker compose -p "$p" -f compose.yaml down -v >/dev/null 2>&1 &
  done
  wait
}

if [[ "${1:-}" == "down" ]]; then
  down_all
  exit 0
fi

[[ -f "$IMAGE_CACHE/noble-range-guest.qcow2" ]] || { echo "missing guest image; run ../net-compile/run.sh once first"; exit 1; }

echo "=== prebuild container image (not part of the measurement) ==="
docker compose -p storm-build -f compose.yaml build >/dev/null 2>&1
# warm the golden into page cache once: the warm-host assumption, stated in README
cat "$IMAGE_CACHE/noble-range-guest.qcow2" > /dev/null
cat "$IMAGE_CACHE/noble-server-cloudimg-amd64.img" > /dev/null

disk_stats() {  # sectors read, sectors written
  awk -v d="$DISK" '$3 == d { print $6, $10 }' /proc/diskstats
}

poll_cloudinit() {  # $1 = cid: short execs until cloud-init reports done
  for _ in $(seq 1 120); do
    if $C "$1" exec 'cloud-init status 2>/dev/null | grep -q "done\|degraded" && echo ok' 2>/dev/null | grep -q ok; then
      return 0
    fi
    sleep 3
  done
  return 1
}

one_range() {  # $1 = index; waits both VMs ready, writes elapsed to tmp/
  local i=$1 cid_base=$((100 + i * 2)) t0=$2
  {
    echo "step: up"
    CID_BASE=$cid_base docker compose -p "storm-$i" -f compose.yaml up -d --wait
    echo "step: storm.sh"
    docker compose -p "storm-$i" -f compose.yaml exec -T -e CID_BASE=$cid_base range bash /assets/storm.sh
    echo "step: wait daemons"
    $C $cid_base wait
    $C $((cid_base + 1)) wait
    echo "step: cloud-init"
    poll_cloudinit $cid_base
    poll_cloudinit $((cid_base + 1))
  } > "tmp/log-$i" 2>&1
  python3 -c "import time; print(f'{time.time() - $t0:.1f}')" > "tmp/ready-$i"
}

echo "round,n,range,ready_s" > tmp/results.csv
for N in $ROUNDS; do
  echo "=== storm: N=$N concurrent ranges ==="
  rm -f tmp/ready-*
  read -r R0 W0 <<< "$(disk_stats)"
  T0=$(python3 -c 'import time; print(time.time())')
  for i in $(seq 0 $((N - 1))); do one_range "$i" "$T0" & done
  wait
  read -r R1 W1 <<< "$(disk_stats)"
  times=$(cat tmp/ready-* | sort -n)
  for i in $(seq 0 $((N - 1))); do echo "$N,$N,$i,$(cat tmp/ready-$i)" >> tmp/results.csv; done
  python3 - "$N" "$(( (R1 - R0) / 2048 ))" "$(( (W1 - W0) / 2048 ))" <<EOF
import sys
times = sorted(float(x) for x in """$times""".split())
n, rd, wr = sys.argv[1], sys.argv[2], sys.argv[3]
print(f"N={n}: median {times[len(times)//2]:.1f}s, max {times[-1]:.1f}s, disk read {rd} MB, written {wr} MB, loadavg {open('/proc/loadavg').read().split()[0]}")
EOF
  down_all
  sleep 5
done

echo
echo "=== results (tmp/results.csv) ==="
column -t -s, tmp/results.csv | head -80
echo "OK."

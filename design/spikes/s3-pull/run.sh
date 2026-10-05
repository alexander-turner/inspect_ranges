#!/bin/bash
# s3-pull spike: measure the S3-only image-distribution baseline from this
# instance. (a) sustained eager HTTPS GET throughput at several parallelism
# levels against a public us-east-1 bucket (streams to /dev/null: measures the
# network path, not local disk); (b) ranged-GET latency, the lazy-boot read
# pattern. Needs no credentials (anonymous public dataset bucket).
# Usage: ./run.sh
set -euo pipefail
cd "$(dirname "$0")"

BUCKET="noaa-goes16"
HOST="https://${BUCKET}.s3.amazonaws.com"
mkdir -p tmp

echo "=== build key list (~16 GB of 20-400 MB objects) ==="
: > tmp/keys.txt
for hour in 00 03 06 09 12; do
  aws s3 ls --no-sign-request "s3://${BUCKET}/ABI-L1b-RadF/2024/200/${hour}/" \
    | awk -v h="$hour" '{print $3 " ABI-L1b-RadF/2024/200/" h "/" $4}' >> tmp/keys.txt
done
TOTAL_MB=$(awk '{s+=$1} END {printf "%d", s/1048576}' tmp/keys.txt)
echo "corpus: $(wc -l < tmp/keys.txt) objects, ${TOTAL_MB} MB"

pull_round() {  # $1 parallelism, $2 target MB
  local P=$1 target=$2
  awk -v t="$target" '{s+=$1/1048576; print $2; if (s>t) exit}' tmp/keys.txt > tmp/round.txt
  local mb
  mb=$(awk -v t="$target" '{s+=$1/1048576; if (done) next; if (s>t) done=1} END {printf "%d", (s<t?s:t)}' tmp/keys.txt)
  # distinct slice per round so rounds don't share objects
  local lines
  lines=$(wc -l < tmp/round.txt)
  tail -n +$((lines + 1)) tmp/keys.txt > tmp/keys.next && mv tmp/keys.next tmp/keys.txt
  local t0 t1
  t0=$(date +%s.%N)
  xargs -a tmp/round.txt -P "$P" -I{} curl -s -o /dev/null "$HOST/{}"
  t1=$(date +%s.%N)
  python3 -c "print(f'P=$P: {$mb} MB in {$t1-$t0:.1f}s = {$mb/($t1-$t0):.0f} MB/s')"
}

echo "=== eager pull throughput (streams to /dev/null) ==="
pull_round 1 1000
pull_round 4 2500
pull_round 16 5000
pull_round 32 7000

echo "=== ranged-GET latency (the lazy-boot read pattern: 64 KiB reads) ==="
BIGKEY=$(aws s3 ls --no-sign-request "s3://${BUCKET}/ABI-L1b-RadF/2024/200/15/" | sort -k3 -n | tail -1 | awk '{print "ABI-L1b-RadF/2024/200/15/" $4}')
BIGSIZE=$(curl -sI "$HOST/$BIGKEY" | awk 'tolower($1)=="content-length:" {print $2}' | tr -d '\r')
echo "target object: $BIGKEY ($((BIGSIZE / 1048576)) MB)"
: > tmp/ttfb.txt
for _ in $(seq 1 50); do
  off=$(python3 -c "import random; print(random.randrange(0, $BIGSIZE - 65536))")
  curl -s -o /dev/null -r "$off-$((off + 65535))" -w "%{time_starttransfer}\n" "$HOST/$BIGKEY" >> tmp/ttfb.txt
done
python3 - <<'EOF'
times = sorted(float(x) * 1000 for x in open("tmp/ttfb.txt"))
print(f"64 KiB ranged GET, 50 reads: median {times[25]:.0f} ms, p95 {times[47]:.0f} ms")
EOF


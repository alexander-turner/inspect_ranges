#!/bin/bash
# standard-images-v1 slice 3 battery: the hardened range container image,
# pulled-and-pinned. A clean consumer sets INSPECT_RANGES_RANGE_IMAGE to a
# digest-pinned published image and `up` pulls it and boots with it instead
# of building locally; the local build stays the default; unpinned or
# unpullable values refuse coded; doctor reports the source.
# Usage: ./run.sh [down]. CID band 4080; registry port 5065.
set -euo pipefail
cd "$(dirname "$0")"
SPIKE="$PWD"
ROOT="$(cd ../../.. && pwd)"

NOBLE="${NOBLE:-$HOME/.cache/inspect-ranges/images/noble-server-cloudimg-amd64.img}"
export XDG_STATE_HOME="$SPIKE/tmp/state"
IR="uv run inspect-ranges"
CACHE="$SPIKE/tmp/cache"
REG="ir-cat-rimage-reg"
REPO="127.0.0.1:5065/inspect-ranges-range"

stop_registry() { docker rm -f "$REG" >/dev/null 2>&1 || true; }
if [[ "${1:-}" == "down" ]]; then
  stop_registry
  (cd "$ROOT" && $IR down --all) || true
  exit 0
fi

grep -q vhost_vsock /proc/modules || { echo "need: sudo modprobe vhost_vsock"; exit 1; }
[[ -f "$NOBLE" ]] || { echo "missing noble vendor image $NOBLE"; exit 1; }
docker image inspect registry:2 >/dev/null 2>&1 || { echo "need the registry:2 image"; exit 1; }

PASS=0; FAIL=0
ok()  { echo "PASS  $1"; PASS=$((PASS+1)); }
bad() { echo "FAIL  $1"; FAIL=$((FAIL+1)); }

exec 9>/tmp/inspect-ranges-battery.lock
flock 9
trap stop_registry EXIT

cd "$ROOT"
$IR down --all >/dev/null 2>&1 || true
stop_registry
rm -rf "$SPIKE/tmp" && mkdir -p "$SPIKE/tmp"

echo "=== R1 the local build stays the default (no knob, up builds and boots) ==="
DB_OUT=$($IR daemon-bundle -o "$SPIKE/tmp/artifacts")
DAEMON_SHA=$(echo "$DB_OUT" | grep -o 'bundle sha256:[0-9a-f]*' | cut -d: -f2)
NOBLE_SHA=$(sha256sum "$NOBLE" | cut -d' ' -f1)
$IR images derive "$NOBLE" --sha256 "$NOBLE_SHA" --name ubuntu-noble \
  --image-cache "$CACHE" --daemon-bundle "$SPIKE/tmp/artifacts" --daemon-sha256 "$DAEMON_SHA" >/dev/null
mkdir -p "$SPIKE/tmp/range"
cat > "$SPIKE/tmp/range/range.yaml" <<'SPEC'
range:
  name: rimage-consumer
  schema_version: "0.3"
  description: the smallest bootable range, to prove which range image runs it
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
  image: ubuntu-noble
  interfaces: [{ network: lab }]
  entry: external
SPEC
$IR render "$SPIKE/tmp/range" -o "$SPIKE/tmp/bundle" --image-cache "$CACHE" --cid-base 4080 >/dev/null 2>&1 \
  || { echo "render failed"; exit 1; }
$IR up "$SPIKE/tmp/bundle" --image-cache "$CACHE" >"$SPIKE/tmp/r1.txt" 2>&1 \
  && ok "R1 up boots with the locally built range image (default path)" || { bad "R1"; tail -5 "$SPIKE/tmp/r1.txt"; exit 1; }
RC=$(docker ps --format '{{.Names}}' | grep -E '^ir-rimage-consumer-.*-range-1$' | head -1)
IMG=$(docker inspect --format '{{.Config.Image}}' "$RC")
[[ "$IMG" == inspect-ranges-range:v* ]] \
  && ok "R1b the running range container uses the local content-labeled tag ($IMG)" || bad "R1b (got: $IMG)"
$IR down --all >/dev/null 2>&1 || true

echo "=== R2 a published pin: push, forget locally, up PULLS and boots with it ==="
docker run -d --rm --name "$REG" -p 127.0.0.1:5065:5000 registry:2 >/dev/null
for _ in $(seq 1 40); do curl -fs http://127.0.0.1:5065/v2/ >/dev/null && break; sleep 0.5; done
docker tag "$IMG" "$REPO:candidate"
DIGEST=$(docker push "$REPO:candidate" 2>/dev/null | grep -o 'sha256:[0-9a-f]*' | tail -1)
PIN="$REPO@$DIGEST"
docker rmi "$REPO:candidate" "$PIN" >/dev/null 2>&1 || true
docker image inspect "$PIN" >/dev/null 2>&1 && { echo "pin still local, cannot prove the pull"; exit 1; }
INSPECT_RANGES_RANGE_IMAGE="$PIN" $IR up "$SPIKE/tmp/bundle" --image-cache "$CACHE" >"$SPIKE/tmp/r2.txt" 2>&1 \
  && ok "R2 up pulls the pinned range image and boots" || { bad "R2"; tail -5 "$SPIKE/tmp/r2.txt"; }
RC=$(docker ps --format '{{.Names}}' | grep -E '^ir-rimage-consumer-.*-range-1$' | head -1)
IMG2=$(docker inspect --format '{{.Config.Image}}' "$RC" 2>/dev/null || true)
[[ "$IMG2" == "$PIN" ]] \
  && ok "R2b the running range container IS the pin, byte-for-byte by digest" || bad "R2b (got: $IMG2)"
INSPECT_RANGES_RANGE_IMAGE="$PIN" $IR doctor >"$SPIKE/tmp/r2doc.txt" 2>&1 || true
grep -q "pinned $PIN" "$SPIKE/tmp/r2doc.txt" \
  && ok "R2c doctor reports the pinned source" || { bad "R2c"; grep -i "range image" "$SPIKE/tmp/r2doc.txt" || true; }
$IR down --all >/dev/null 2>&1 || true

echo "=== R3 refusals: mutable tags and unpullable pins never boot ==="
INSPECT_RANGES_RANGE_IMAGE="$REPO:candidate" $IR up "$SPIKE/tmp/bundle" --image-cache "$CACHE" >"$SPIKE/tmp/r3.txt" 2>&1 \
  && bad "R3 a mutable tag was accepted" \
  || { grep -q "range-image" "$SPIKE/tmp/r3.txt" && grep -q "digest-pinned" "$SPIKE/tmp/r3.txt" \
       && ok "R3 an unpinned tag refuses coded (a mutable tag could swap the jail)" || { bad "R3 wrong refusal"; tail -3 "$SPIKE/tmp/r3.txt"; }; }
GONE="$REPO@sha256:$(printf '0%.0s' {1..64})"
INSPECT_RANGES_RANGE_IMAGE="$GONE" $IR up "$SPIKE/tmp/bundle" --image-cache "$CACHE" >"$SPIKE/tmp/r3b.txt" 2>&1 \
  && bad "R3b an unpullable pin was accepted" \
  || { grep -q "range-image" "$SPIKE/tmp/r3b.txt" && grep -q "pulling the pinned range image" "$SPIKE/tmp/r3b.txt" \
       && ok "R3b an unpullable pin refuses with the pull cause" || { bad "R3b wrong refusal"; tail -3 "$SPIKE/tmp/r3b.txt"; }; }
docker ps --format '{{.Names}}' | grep -q '^ir-rimage-consumer-' \
  && bad "R3c a refused up left containers behind" || ok "R3c refusals leave nothing running"

stop_registry
echo
echo "$PASS passed, $FAIL failed"
exit $((FAIL > 0))

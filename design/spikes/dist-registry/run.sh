#!/bin/bash
# distribution-v1 slice 2 battery: the registry client against live registry:2
# containers. A real (minimal) build pushes its closure to a local registry,
# re-push is pure dedup (registry filesystem byte-count pinned), fresh caches
# pull it back and the range boots carrying the recipe's marker, and the
# closure mirrors registry-to-registry byte-identically. Usage: ./run.sh
# [down]. See README.md. CID band 4010; registry ports 5056/5057.
set -euo pipefail
cd "$(dirname "$0")"
SPIKE="$PWD"
ROOT="$(cd ../../.. && pwd)"
RANGE="$SPIKE/fixtures/minirange"

ERA="${ERA:-$HOME/.cache/inspect-ranges/images/focal-server-cloudimg-amd64.img}"
export XDG_STATE_HOME="$SPIKE/tmp/state"
export INSPECT_RANGES_BUILD_CACHE="$SPIKE/tmp/builds"
IR="uv run inspect-ranges"
IRBIN="$ROOT/.venv/bin/inspect-ranges"
PYDIST="uv run python design/spikes/dist-registry/dist.py"
CACHE="$SPIKE/tmp/cache"
PULLED="$SPIKE/tmp/pulled"
REG_A="ir-dist-registry-a"; REG_B="ir-dist-registry-b"
URL_A="registry+http://127.0.0.1:5056/ranges/distmini"
URL_B="registry+http://127.0.0.1:5057/ranges/distmini"
FLAGS=(--image-cache "$CACHE" --build-cache "$SPIKE/tmp/builds" --cid-base 4010 --readiness-timeout 300)

stop_registries() { docker rm -f "$REG_A" "$REG_B" >/dev/null 2>&1 || true; }
if [[ "${1:-}" == "down" ]]; then
  stop_registries
  (cd "$ROOT" && $IR down --all) || true
  exit 0
fi

grep -q vhost_vsock /proc/modules || { echo "need: sudo modprobe vhost_vsock"; exit 1; }
[[ -f "$ERA" ]] || { echo "missing focal vendor image $ERA"; exit 1; }
docker image inspect registry:2 >/dev/null 2>&1 \
  || { echo "need the registry:2 image (public pull; see distribution-v1-parked-decisions.md entry 1)"; exit 1; }

PASS=0; FAIL=0
ok()  { echo "PASS  $1"; PASS=$((PASS+1)); }
bad() { echo "FAIL  $1"; FAIL=$((FAIL+1)); }

exec 9>/tmp/inspect-ranges-battery.lock
flock 9

cd "$ROOT"
$IR down --all >/dev/null 2>&1 || true
stop_registries
rm -rf "$SPIKE/tmp" && mkdir -p "$SPIKE/tmp"

echo "=== R1 build the minimal range (the artifact set under test) ==="
DB_OUT=$($IR daemon-bundle -o "$SPIKE/tmp/artifacts")
DAEMON_SHA=$(echo "$DB_OUT" | grep -o 'bundle sha256:[0-9a-f]*' | cut -d: -f2)
ERA_SHA=$(sha256sum "$ERA" | cut -d' ' -f1)
$IR images derive "$ERA" --sha256 "$ERA_SHA" --name ubuntu-focal \
  --image-cache "$CACHE" --daemon-bundle "$SPIKE/tmp/artifacts" --daemon-sha256 "$DAEMON_SHA" >/dev/null
if (cd "$RANGE" && "$IRBIN" build "${FLAGS[@]}" >"$SPIKE/tmp/r1.txt" 2>&1); then
  grep -q "build OK" "$SPIKE/tmp/r1.txt" && ok "R1 distmini builds green" || bad "R1 build OK line"
else
  bad "R1 build"; tail -15 "$SPIKE/tmp/r1.txt"; exit 1
fi

echo "=== R2 push the closure to a live registry ==="
docker run -d --rm --name "$REG_A" -p 127.0.0.1:5056:5000 registry:2 >/dev/null
sleep 2
$PYDIST push --range-name distmini --build-cache "$SPIKE/tmp/builds" \
  --image-cache "$CACHE" --range-dir "$RANGE" --store "$URL_A" >"$SPIKE/tmp/r2.txt" 2>&1 \
  && grep -q "root sha256:" "$SPIKE/tmp/r2.txt" \
  && ok "R2 push to registry:2 prints the root digest" || { bad "R2 push"; cat "$SPIKE/tmp/r2.txt"; }
ROOT_DIGEST=$(grep -o 'root sha256:[0-9a-f]*' "$SPIKE/tmp/r2.txt" | head -1)
BYTES_1=$(docker exec "$REG_A" du -sb /var/lib/registry | cut -f1)

echo "=== R3 re-push is pure dedup (registry filesystem pinned) ==="
$PYDIST push --range-name distmini --build-cache "$SPIKE/tmp/builds" \
  --image-cache "$CACHE" --range-dir "$RANGE" --store "$URL_A" >"$SPIKE/tmp/r3.txt" 2>&1
BYTES_2=$(docker exec "$REG_A" du -sb /var/lib/registry | cut -f1)
[[ "$BYTES_1" == "$BYTES_2" && "$(grep -o 'root sha256:[0-9a-f]*' "$SPIKE/tmp/r3.txt")" == "$ROOT_DIGEST" ]] \
  && ok "R3 re-push stores zero new bytes and reproduces the root digest" \
  || bad "R3 dedup (bytes $BYTES_1 -> $BYTES_2)"

echo "=== R4 fresh caches pull from the registry and the range boots ==="
mkdir -p "$PULLED/images" "$PULLED/builds" "$PULLED/recipes"
$PYDIST pull --store "$URL_A" --ref distmini \
  --image-cache "$PULLED/images" --build-cache "$PULLED/builds" --recipe-cache "$PULLED/recipes" >"$SPIKE/tmp/r4.txt" 2>&1 \
  && [[ -f "$PULLED/builds/distmini/manifest.json" ]] \
  && ok "R4 pull materializes the closure from the registry" || { bad "R4 pull"; cat "$SPIKE/tmp/r4.txt"; }
cmp -s "$PULLED/builds/distmini/manifest.json" "$SPIKE/tmp/builds/distmini/manifest.json" \
  && ok "R4b the pulled manifest is the exact published bytes" || bad "R4b manifest bytes"
INSPECT_RANGES_BUILD_CACHE="$PULLED/builds" $IR render "$RANGE" -o "$SPIKE/tmp/bundle" \
  --image-cache "$PULLED/images" --cid-base 4010 >/dev/null 2>&1 \
  && ok "R4c render from the pulled caches" || bad "R4c render"
$IR up "$SPIKE/tmp/bundle" --image-cache "$PULLED/images" >"$SPIKE/tmp/r4up.txt" 2>&1 \
  && ok "R4d up from registry-pulled artifacts reaches ready" || { bad "R4d up"; tail -5 "$SPIKE/tmp/r4up.txt"; }
MARKER=$(cd "$ROOT" && uv run python design/spikes/_shared/chexec.py --boot "$SPIKE/tmp/bundle/boot.json" --guest web --user root exec \
  "cat /opt/dist-marker" || true)
[[ "$MARKER" == *shipped-by-registry* ]] \
  && ok "R4e the pulled realized guest carries the recipe's marker (got: $MARKER)" \
  || bad "R4e marker (got: $MARKER)"
$IR down --all >/dev/null 2>&1 || true

echo "=== R5 registry-to-registry mirror ==="
docker run -d --rm --name "$REG_B" -p 127.0.0.1:5057:5000 registry:2 >/dev/null
sleep 2
$PYDIST copy --source "$URL_A" --dest "$URL_B" --ref distmini >"$SPIKE/tmp/r5.txt" 2>&1 \
  && [[ "$(grep -o 'root sha256:[0-9a-f]*' "$SPIKE/tmp/r5.txt")" == "$ROOT_DIGEST" ]] \
  && ok "R5 closure mirrors A->B and reproduces the root digest" || { bad "R5 copy"; cat "$SPIKE/tmp/r5.txt"; }
$PYDIST copy --source "$URL_A" --dest "$URL_B" --ref distmini >"$SPIKE/tmp/r5b.txt" 2>&1
grep -q "copied 0 " "$SPIKE/tmp/r5b.txt" && ok "R5b re-mirror copies nothing (destination holds every digest)" || { bad "R5b"; cat "$SPIKE/tmp/r5b.txt"; }
mkdir -p "$SPIKE/tmp/b-images" "$SPIKE/tmp/b-builds" "$SPIKE/tmp/b-recipes"
$PYDIST pull --store "$URL_B" --ref distmini \
  --image-cache "$SPIKE/tmp/b-images" --build-cache "$SPIKE/tmp/b-builds" --recipe-cache "$SPIKE/tmp/b-recipes" >/dev/null 2>&1 \
  && cmp -s "$SPIKE/tmp/b-builds/distmini/manifest.json" "$SPIKE/tmp/builds/distmini/manifest.json" \
  && ok "R5c a pull from the mirror is byte-identical to the original" || bad "R5c mirror pull"

stop_registries
echo
echo "$PASS passed, $FAIL failed"
exit $((FAIL > 0))

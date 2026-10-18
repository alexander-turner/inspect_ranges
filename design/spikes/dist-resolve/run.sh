#!/bin/bash
# distribution-v1 slice 3 battery: resolution and the spec-driven verbs, live.
# A real build pushes via the CLI; spec-driven pull resolves across a search
# path (a prepended registry shadows a layout fallback deterministically); a
# semantically edited spec refuses no-build-for-spec naming the nearest build;
# the name@digest pin form bypasses the match; catalog images pull sticky and
# move forward only on explicit refresh; and a fresh builder cache fetches a
# published golden through the build path's registry tier and builds green.
# Usage: ./run.sh [down]. See README.md. CID band 4020; registry port 5058.
set -euo pipefail
cd "$(dirname "$0")"
SPIKE="$PWD"
ROOT="$(cd ../../.. && pwd)"
FIXTURE="$ROOT/design/spikes/dist-registry/fixtures/minirange"

ERA="${ERA:-$HOME/.cache/inspect-ranges/images/focal-server-cloudimg-amd64.img}"
export XDG_STATE_HOME="$SPIKE/tmp/state"
IR="uv run inspect-ranges"
IRBIN="$ROOT/.venv/bin/inspect-ranges"
CACHE="$SPIKE/tmp/cache"
BUILDS="$SPIKE/tmp/builds"
RANGE="$SPIKE/tmp/minirange"
L1="$SPIKE/tmp/fallback"
CATALOG="$SPIKE/tmp/catalog"
REG="ir-dist-resolve-reg"
REG_URL="http://127.0.0.1:5058/ranges"
FLAGS=(--image-cache "$CACHE" --build-cache "$BUILDS" --cid-base 4020 --readiness-timeout 300)

stop_registry() { docker rm -f "$REG" >/dev/null 2>&1 || true; }
if [[ "${1:-}" == "down" ]]; then
  stop_registry
  (cd "$ROOT" && $IR down --all) || true
  exit 0
fi

grep -q vhost_vsock /proc/modules || { echo "need: sudo modprobe vhost_vsock"; exit 1; }
[[ -f "$ERA" ]] || { echo "missing focal vendor image $ERA"; exit 1; }
docker image inspect registry:2 >/dev/null 2>&1 || { echo "need the registry:2 image"; exit 1; }

PASS=0; FAIL=0
ok()  { echo "PASS  $1"; PASS=$((PASS+1)); }
bad() { echo "FAIL  $1"; FAIL=$((FAIL+1)); }

exec 9>/tmp/inspect-ranges-battery.lock
flock 9

cd "$ROOT"
$IR down --all >/dev/null 2>&1 || true
stop_registry
rm -rf "$SPIKE/tmp" && mkdir -p "$SPIKE/tmp"
cp -r "$FIXTURE" "$RANGE"

echo "=== S1 build the fixture range ==="
DB_OUT=$($IR daemon-bundle -o "$SPIKE/tmp/artifacts")
DAEMON_SHA=$(echo "$DB_OUT" | grep -o 'bundle sha256:[0-9a-f]*' | cut -d: -f2)
ERA_SHA=$(sha256sum "$ERA" | cut -d' ' -f1)
$IR images derive "$ERA" --sha256 "$ERA_SHA" --name ubuntu-focal \
  --image-cache "$CACHE" --daemon-bundle "$SPIKE/tmp/artifacts" --daemon-sha256 "$DAEMON_SHA" >/dev/null
(cd "$RANGE" && "$IRBIN" build "${FLAGS[@]}" >"$SPIKE/tmp/s1.txt" 2>&1) \
  && grep -q "build OK" "$SPIKE/tmp/s1.txt" && ok "S1 distmini builds green" || { bad "S1 build"; tail -10 "$SPIKE/tmp/s1.txt"; exit 1; }

echo "=== S2 the push verb publishes to a layout location ==="
(cd "$RANGE" && "$IRBIN" push --to "$L1" --image-cache "$CACHE" --build-cache "$BUILDS" >"$SPIKE/tmp/s2.txt" 2>&1) \
  && grep -q "push OK   distmini@sha256:" "$SPIKE/tmp/s2.txt" \
  && ok "S2 push prints the publishable identity" || { bad "S2 push"; cat "$SPIKE/tmp/s2.txt"; }
ROOT1=$(grep -o 'distmini@sha256:[0-9a-f]*' "$SPIKE/tmp/s2.txt" | cut -d@ -f2)

echo "=== S3 spec-driven pull resolves and plan consumes it ==="
P1="$SPIKE/tmp/p1"; mkdir -p "$P1/images" "$P1/builds" "$P1/recipes"
(cd "$RANGE" && "$IRBIN" pull --from "$L1" --image-cache "$P1/images" --build-cache "$P1/builds" --recipe-cache "$P1/recipes" >"$SPIKE/tmp/s3.txt" 2>&1) \
  && grep -q "pull OK" "$SPIKE/tmp/s3.txt" && grep -q "resolve   spec sha256:" "$SPIKE/tmp/s3.txt" \
  && cmp -s "$P1/builds/distmini/manifest.json" "$BUILDS/distmini/manifest.json" \
  && ok "S3 bare pull resolves by spec hash and lands the exact bytes" || { bad "S3 pull"; cat "$SPIKE/tmp/s3.txt"; }
INSPECT_RANGES_BUILD_CACHE="$P1/builds" $IR plan "$RANGE" --image-cache "$P1/images" >/dev/null 2>&1 \
  && ok "S3b plan consumes the pulled manifest" || bad "S3b plan"

echo "=== S4 a semantically edited spec refuses with the nearest build ==="
sed -i 's/shipped-by-registry/edited-content/' "$RANGE/range.yaml"
P2="$SPIKE/tmp/p2"; mkdir -p "$P2/images" "$P2/builds" "$P2/recipes"
if (cd "$RANGE" && "$IRBIN" pull --from "$L1" --image-cache "$P2/images" --build-cache "$P2/builds" --recipe-cache "$P2/recipes" >"$SPIKE/tmp/s4.txt" 2>&1); then
  bad "S4 edited-spec pull was accepted"
else
  grep -q "no-build-for-spec" "$SPIKE/tmp/s4.txt" && grep -q "nearest" "$SPIKE/tmp/s4.txt" \
    && [[ ! -f "$P2/builds/distmini/manifest.json" ]] \
    && ok "S4 no-build-for-spec names the nearest published build" || { bad "S4 refusal"; cat "$SPIKE/tmp/s4.txt"; }
fi

echo "=== S5 the pin form bypasses the spec match ==="
(cd "$RANGE" && "$IRBIN" pull --pin "$ROOT1" --from "$L1" --image-cache "$P2/images" --build-cache "$P2/builds" --recipe-cache "$P2/recipes" >"$SPIKE/tmp/s5.txt" 2>&1) \
  && grep -q "pull OK" "$SPIKE/tmp/s5.txt" && [[ -f "$P2/builds/distmini/manifest.json" ]] \
  && ok "S5 name@digest pull works without a spec match" || { bad "S5 pin"; cat "$SPIKE/tmp/s5.txt"; }

echo "=== S6 a prepended registry shadows the fallback deterministically ==="
sed -i 's/edited-content/shipped-by-registry/' "$RANGE/range.yaml"  # restore
(cd "$RANGE" && "$IRBIN" build "${FLAGS[@]}" --reverify >"$SPIKE/tmp/s6build.txt" 2>&1) || { bad "S6 rebuild"; tail -5 "$SPIKE/tmp/s6build.txt"; }
docker run -d --rm --name "$REG" -p 127.0.0.1:5058:5000 registry:2 >/dev/null
sleep 2
(cd "$RANGE" && "$IRBIN" push --to "$REG_URL" --image-cache "$CACHE" --build-cache "$BUILDS" >"$SPIKE/tmp/s6.txt" 2>&1) \
  && ok "S6 push to the live registry location" || { bad "S6 push"; cat "$SPIKE/tmp/s6.txt"; }
P3="$SPIKE/tmp/p3"; mkdir -p "$P3/images" "$P3/builds" "$P3/recipes"
(cd "$RANGE" && INSPECT_RANGES_REGISTRY="$REG_URL,$L1" "$IRBIN" pull --image-cache "$P3/images" --build-cache "$P3/builds" --recipe-cache "$P3/recipes" >"$SPIKE/tmp/s6pull.txt" 2>&1) \
  && grep -q "($REG_URL)" "$SPIKE/tmp/s6pull.txt" \
  && ok "S6b the search path resolves from the prepended registry, not the fallback" || { bad "S6b shadow"; cat "$SPIKE/tmp/s6pull.txt"; }

echo "=== S7 catalog images: sticky pull, explicit refresh ==="
# the pristine catalog (for S8's tier build) publishes first; the moved-forward
# legs run against their own catalog + a cache copy, leaving CACHE untouched
uv run python -c "
from pathlib import Path
from inspect_ranges._dist import parse_location, push_image_artifact
push_image_artifact('ubuntu-focal', parse_location('$CATALOG'), image_cache=Path('$CACHE'))
print('published')" >/dev/null
CAT2="$SPIKE/tmp/catalog2"
CACHE2="$SPIKE/tmp/cache2"
cp -r "$CACHE" "$CACHE2"
uv run python -c "
from pathlib import Path
from inspect_ranges._dist import parse_location, push_image_artifact
push_image_artifact('ubuntu-focal', parse_location('$CAT2'), image_cache=Path('$CACHE2'))
print('published')" >/dev/null
C1="$SPIKE/tmp/consumer-images"; mkdir -p "$C1"
$IR images pull ubuntu-focal --from "$CAT2" --image-cache "$C1" >"$SPIKE/tmp/s7.txt" 2>&1 \
  && grep -q "pull OK   ubuntu-focal" "$SPIKE/tmp/s7.txt" \
  && cmp -s "$C1/ubuntu-focal.qcow2" "$CACHE/ubuntu-focal.qcow2" \
  && [[ -f "$C1/ubuntu-focal.json" ]] \
  && ok "S7 images pull lands the golden chain with its sidecar" || { bad "S7 images pull"; cat "$SPIKE/tmp/s7.txt"; }
# the publisher moves the name forward (appended bytes keep the qcow2 header valid)
printf 'moved-forward' >> "$CACHE2/ubuntu-focal.qcow2"
uv run python -c "
import hashlib, json
from pathlib import Path
from inspect_ranges._dist import parse_location, push_image_artifact
cache = Path('$CACHE2')
meta = json.loads((cache / 'ubuntu-focal.json').read_text())
meta['golden_sha256'] = hashlib.sha256((cache / 'ubuntu-focal.qcow2').read_bytes()).hexdigest()
(cache / 'ubuntu-focal.json').write_text(json.dumps(meta))
push_image_artifact('ubuntu-focal', parse_location('$CAT2'), image_cache=cache)
print('republished')" >/dev/null
if $IR images pull ubuntu-focal --from "$CAT2" --image-cache "$C1" >"$SPIKE/tmp/s7b.txt" 2>&1; then
  bad "S7b sticky pull silently replaced the cached name"
else
  grep -q "cache-name-conflict" "$SPIKE/tmp/s7b.txt" && ok "S7b sticky: a moved name refuses on plain pull" || { bad "S7b refusal"; cat "$SPIKE/tmp/s7b.txt"; }
fi
$IR images refresh ubuntu-focal --from "$CAT2" --image-cache "$C1" >"$SPIKE/tmp/s7c.txt" 2>&1 \
  && grep -q "refresh   ubuntu-focal: updated" "$SPIKE/tmp/s7c.txt" \
  && cmp -s "$C1/ubuntu-focal.qcow2" "$CACHE2/ubuntu-focal.qcow2" \
  && ok "S7c explicit refresh moves the chain forward" || { bad "S7c refresh"; cat "$SPIKE/tmp/s7c.txt"; }

echo "=== S8 the build path's registry tier fetches a published golden ==="
C2="$SPIKE/tmp/builder2"; mkdir -p "$C2"
B2="$SPIKE/tmp/builds2"
(cd "$RANGE" && INSPECT_RANGES_REGISTRY="$CATALOG" "$IRBIN" build --image-cache "$C2" --build-cache "$B2" --cid-base 4020 --readiness-timeout 300 >"$SPIKE/tmp/s8.txt" 2>&1) \
  && grep -q "build OK" "$SPIKE/tmp/s8.txt" \
  && [[ -f "$C2/ubuntu-focal.qcow2" && -f "$C2/focal-server-cloudimg-amd64.img" ]] \
  && ok "S8 a fresh builder cache fetched the published golden through the Q1 tier and built green" \
  || { bad "S8 tier build"; tail -10 "$SPIKE/tmp/s8.txt"; }

stop_registry
$IR down --all >/dev/null 2>&1 || true
echo
echo "$PASS passed, $FAIL failed"
exit $((FAIL > 0))

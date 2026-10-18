#!/bin/bash
# distribution-v1 slice 5 battery: mirror, the air gap, and the GC chain tier,
# live. A build publishes to registry A; whole-location mirror seeds an OCI
# layout (the catalog listing drives it); the layout tars across the gap and a
# disconnected consumer pulls spec-driven FROM the archive; the cross-group
# spec-driven mirror copies A->B and B serves pulls; re-mirrors copy nothing;
# and images prune --chains reclaims an orphan golden while its shared vendor
# (still named by a surviving golden) stays, with the surviving manifest's
# closure intact. Usage: ./run.sh [down]. CID band 4040; registries 5060/5061.
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
REG_A="ir-dist-mirror-a"; REG_B="ir-dist-mirror-b"
URL_A="http://127.0.0.1:5060/ranges"
URL_B="http://127.0.0.1:5061/ranges"
FLAGS=(--image-cache "$CACHE" --build-cache "$BUILDS" --cid-base 4040 --readiness-timeout 300)

stop_registries() { docker rm -f "$REG_A" "$REG_B" >/dev/null 2>&1 || true; }
if [[ "${1:-}" == "down" ]]; then
  stop_registries
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
stop_registries
rm -rf "$SPIKE/tmp" && mkdir -p "$SPIKE/tmp"
cp -r "$FIXTURE" "$RANGE"

echo "=== M1 build and publish to registry A ==="
DB_OUT=$($IR daemon-bundle -o "$SPIKE/tmp/artifacts")
DAEMON_SHA=$(echo "$DB_OUT" | grep -o 'bundle sha256:[0-9a-f]*' | cut -d: -f2)
ERA_SHA=$(sha256sum "$ERA" | cut -d' ' -f1)
$IR images derive "$ERA" --sha256 "$ERA_SHA" --name ubuntu-focal \
  --image-cache "$CACHE" --daemon-bundle "$SPIKE/tmp/artifacts" --daemon-sha256 "$DAEMON_SHA" >/dev/null
(cd "$RANGE" && "$IRBIN" build "${FLAGS[@]}" >"$SPIKE/tmp/m1.txt" 2>&1) \
  && grep -q "build OK" "$SPIKE/tmp/m1.txt" && ok "M1 distmini builds green" || { bad "M1 build"; tail -8 "$SPIKE/tmp/m1.txt"; exit 1; }
docker run -d --rm --name "$REG_A" -p 127.0.0.1:5060:5000 registry:2 >/dev/null
docker run -d --rm --name "$REG_B" -p 127.0.0.1:5061:5000 registry:2 >/dev/null
sleep 2
(cd "$RANGE" && "$IRBIN" push --to "$URL_A" --image-cache "$CACHE" --build-cache "$BUILDS" >/dev/null 2>&1) \
  && ok "M1b published to registry A" || bad "M1b push"

echo "=== M2 whole-location mirror seeds an archive layout (catalog-driven) ==="
$IR mirror --from "$URL_A" --to "$SPIKE/tmp/archive" >"$SPIKE/tmp/m2.txt" 2>&1 \
  && grep -qE "mirror    1 artifacts: .* copied" "$SPIKE/tmp/m2.txt" \
  && ok "M2 the registry's catalog listing drove a whole-location mirror" || { bad "M2 mirror"; cat "$SPIKE/tmp/m2.txt"; }

echo "=== M3 the sneakernet: tar, ship, pull spec-driven from the archive ==="
tar -C "$SPIKE/tmp" -czf "$SPIKE/tmp/archive.tgz" archive
mkdir -p "$SPIKE/tmp/gap" && tar -C "$SPIKE/tmp/gap" -xzf "$SPIKE/tmp/archive.tgz"
G="$SPIKE/tmp/gapside"; mkdir -p "$G/images" "$G/builds" "$G/recipes"
(cd "$RANGE" && INSPECT_RANGES_REGISTRY="$SPIKE/tmp/gap/archive" "$IRBIN" pull \
  --image-cache "$G/images" --build-cache "$G/builds" --recipe-cache "$G/recipes" >"$SPIKE/tmp/m3.txt" 2>&1) \
  && grep -q "pull OK" "$SPIKE/tmp/m3.txt" \
  && cmp -s "$G/builds/distmini/manifest.json" "$BUILDS/distmini/manifest.json" \
  && ok "M3 the disconnected consumer pulled spec-driven from the shipped archive" || { bad "M3"; cat "$SPIKE/tmp/m3.txt"; }

echo "=== M4 the cross-group move: spec-driven mirror A->B, then B serves ==="
$IR mirror "$RANGE" --from "$URL_A" --to "$URL_B" >"$SPIKE/tmp/m4.txt" 2>&1 \
  && grep -q "resolve   spec sha256:" "$SPIKE/tmp/m4.txt" \
  && ok "M4 spec-driven mirror resolved the exact source build" || { bad "M4 mirror"; cat "$SPIKE/tmp/m4.txt"; }
B="$SPIKE/tmp/bside"; mkdir -p "$B/images" "$B/builds" "$B/recipes"
(cd "$RANGE" && INSPECT_RANGES_REGISTRY="$URL_B" "$IRBIN" pull \
  --image-cache "$B/images" --build-cache "$B/builds" --recipe-cache "$B/recipes" >/dev/null 2>&1) \
  && cmp -s "$B/builds/distmini/manifest.json" "$BUILDS/distmini/manifest.json" \
  && ok "M4b a pull from the mirror is byte-identical to the original" || bad "M4b pull from B"

echo "=== M5 re-mirrors copy nothing ==="
$IR mirror --from "$URL_A" --to "$SPIKE/tmp/archive" >"$SPIKE/tmp/m5.txt" 2>&1
grep -qE "mirror    1 artifacts: [0-9]+ blobs already present, 0 copied" "$SPIKE/tmp/m5.txt" \
  && ok "M5 re-mirror into the archive copies zero blobs" || { bad "M5"; cat "$SPIKE/tmp/m5.txt"; }

echo "=== M6 the GC chain tier: an orphan golden leaves, its shared vendor stays ==="
# prune rightly refuses while the build's project is registered: clear it first
$IR down --all >/dev/null 2>&1 || true
cp "$CACHE/ubuntu-focal.qcow2" "$CACHE/orphan-golden.qcow2"
python3 - "$CACHE" <<'PYEOF'
import json, sys
from pathlib import Path
cache = Path(sys.argv[1])
meta = json.loads((cache / "ubuntu-focal.json").read_text())
meta["name"] = "orphan-golden"
meta["file"] = "orphan-golden.qcow2"
(cache / "orphan-golden.json").write_text(json.dumps(meta))
PYEOF
$IR images prune --chains --image-cache "$CACHE" --build-cache "$BUILDS" >"$SPIKE/tmp/m6.txt" 2>&1
grep -q "orphan-golden.qcow2" "$SPIKE/tmp/m6.txt" \
  && ! grep -qE "^ubuntu-focal.qcow2|focal-server-cloudimg" "$SPIKE/tmp/m6.txt" \
  && ok "M6 the scan offers the orphan golden and protects the referenced chain" || { bad "M6 scan"; cat "$SPIKE/tmp/m6.txt"; }
$IR images prune --chains --yes --image-cache "$CACHE" --build-cache "$BUILDS" >/dev/null 2>&1
[[ ! -f "$CACHE/orphan-golden.qcow2" && -f "$CACHE/ubuntu-focal.qcow2" && -f "$CACHE/focal-server-cloudimg-amd64.img" ]] \
  && ok "M6b eviction removed the orphan chain only (the shared vendor survives under its dependent)" || bad "M6b eviction"
INSPECT_RANGES_BUILD_CACHE="$BUILDS" $IR plan "$RANGE" --image-cache "$CACHE" >/dev/null 2>&1 \
  && ok "M6c the surviving manifest's closure is intact post-prune (plan green)" || bad "M6c plan"

stop_registries
echo
echo "$PASS passed, $FAIL failed"
exit $((FAIL > 0))

#!/bin/bash
# build-v1 slice 5 battery: the build manifest, capture, and invalidation.
# First build captures realized images and writes the manifest; a recipe edit
# rebuilds exactly that guest while the other BOOTS FROM ITS REALIZED IMAGE
# (the live proof that captured content survives reboot: nginx still serving
# on the reused guest under full re-verification); a no-op rebuild is the
# cached fast path (nothing boots); --reverify forces the full pass; and a
# bundle rendered before an image change refuses at up with the re-render
# hint. Usage: ./run.sh [down]. See README.md.
set -euo pipefail
cd "$(dirname "$0")"
SPIKE="$PWD"
ROOT="$(cd ../../.. && pwd)"

ERA="${ERA:-$HOME/.cache/inspect-ranges/images/focal-server-cloudimg-amd64.img}"
export XDG_STATE_HOME="$SPIKE/tmp/state"
IR="uv run inspect-ranges"
IRBIN="$ROOT/.venv/bin/inspect-ranges"
CACHE="$SPIKE/tmp/cache"
BUILDS="$SPIKE/tmp/builds"
FLAGS=(--image-cache "$CACHE" --build-cache "$BUILDS" --cid-base 3600 --readiness-timeout 300)

if [[ "${1:-}" == "down" ]]; then
  (cd "$ROOT" && $IR down --all) || true
  exit 0
fi

grep -q vhost_vsock /proc/modules || { echo "need: sudo modprobe vhost_vsock"; exit 1; }
[[ -f "$ERA" ]] || { echo "missing focal vendor image $ERA"; exit 1; }

PASS=0; FAIL=0
ok()  { echo "PASS  $1"; PASS=$((PASS+1)); }
bad() { echo "FAIL  $1"; FAIL=$((FAIL+1)); }

exec 9>/tmp/inspect-ranges-battery.lock
flock 9

cd "$ROOT"
$IR down --all >/dev/null 2>&1 || true
rm -rf "$SPIKE/tmp" && mkdir -p "$SPIKE/tmp"
# the recipe-edit check mutates a fixture; build from a scratch copy
cp -r "$SPIKE/fixtures/incr" "$SPIKE/tmp/incr"

echo "=== derive the focal golden ==="
DB_OUT=$($IR daemon-bundle -o "$SPIKE/tmp/artifacts") \
  || { echo "daemon-bundle build failed (install the pinned Go toolchain)"; exit 1; }
DAEMON_SHA=$(echo "$DB_OUT" | grep -o 'bundle sha256:[0-9a-f]*' | cut -d: -f2)
ERA_SHA=$(sha256sum "$ERA" | cut -d' ' -f1)
$IR images derive "$ERA" --sha256 "$ERA_SHA" --name focal-guest \
  --image-cache "$CACHE" --daemon-bundle "$SPIKE/tmp/artifacts" --daemon-sha256 "$DAEMON_SHA" >/dev/null

echo "=== M1-M2 first build: capture + manifest ==="
if (cd "$SPIKE/tmp/incr" && "$IRBIN" build "${FLAGS[@]}" | tee "$SPIKE/tmp/m1.txt"); then
  grep -q "build OK" "$SPIKE/tmp/m1.txt" && grep -q "manifest  " "$SPIKE/tmp/m1.txt" \
    && ok "M1 first build passes and names its manifest" || bad "M1 build output"
else
  bad "M1 first build"
fi
MANIFEST="$BUILDS/bmincr/manifest.json"
if [[ -f "$MANIFEST" ]]; then
  CHECK=$(cd "$ROOT" && uv run python - "$MANIFEST" "$CACHE" <<'PYEOF'
import hashlib, json, sys
from pathlib import Path
manifest = json.load(open(sys.argv[1]))
cache = Path(sys.argv[2])
assert manifest["format_version"] == "1" and manifest["range_name"] == "bmincr"
assert len(manifest["guests"]) == 2 and manifest["verification"]["declarations"]
for guest in manifest["guests"]:
    f = cache / guest["realized_file"]
    assert f.is_file(), f
    digest = hashlib.sha256(f.read_bytes()).hexdigest()
    assert digest == guest["realized_sha256"], guest["name"]
    assert (cache / (guest["realized_file"].removesuffix(".qcow2") + ".realized.json")).is_file()
print("manifest-verified")
PYEOF
) || true
  [[ "$CHECK" == *manifest-verified* ]] && ok "M2 manifest digests verify against captured realized images" || bad "M2 manifest verification ($CHECK)"
else
  bad "M2 manifest file missing"
fi

echo "=== M3-M5 recipe edit: incremental rebuild, realized image boots ==="
sed -i 's/original/edited/' "$SPIKE/tmp/incr/range.yaml"
if (cd "$SPIKE/tmp/incr" && "$IRBIN" build "${FLAGS[@]}" | tee "$SPIKE/tmp/m3.txt"); then
  grep -q "build OK" "$SPIKE/tmp/m3.txt" && ok "M3 incremental rebuild passes" || bad "M3 build output"
else
  bad "M3 incremental rebuild"
fi
grep -q "skipped=unchanged" "$SPIKE/tmp/m3.txt" && grep -q "recipe=bm.nginx" "$SPIKE/tmp/m3.txt" \
  && ok "M4 web's nginx recipe skipped (guest reused from its realized image)" || bad "M4 skip line"
grep -q "verify    ok  service web/nginx" "$SPIKE/tmp/m3.txt" \
  && ok "M5 nginx verifies on the REUSED guest: captured content survived reboot" || bad "M5 reused-guest verification"
grep -E "recipe .*guest=db.*recipe=bm.marker.*seconds" "$SPIKE/tmp/m3.txt" >/dev/null \
  && ok "M5b db's edited recipe actually re-ran" || bad "M5b db re-run"

echo "=== M6 no-op rebuild: the cached fast path ==="
START=$(date +%s)
if (cd "$SPIKE/tmp/incr" && "$IRBIN" build "${FLAGS[@]}" | tee "$SPIKE/tmp/m6.txt"); then
  ELAPSED=$(( $(date +%s) - START ))
  grep -q "build OK (cached, verified" "$SPIKE/tmp/m6.txt" && [[ "$ELAPSED" -lt 30 ]] \
    && ok "M6 no-op rebuild is cached (${ELAPSED}s, nothing booted)" || bad "M6 cached path (${ELAPSED}s)"
else
  bad "M6 no-op rebuild"
fi

echo "=== M7 --reverify forces the full pass ==="
if (cd "$SPIKE/tmp/incr" && "$IRBIN" build --reverify "${FLAGS[@]}" | tee "$SPIKE/tmp/m7.txt"); then
  grep -q "build OK (cached" "$SPIKE/tmp/m7.txt" && bad "M7 reverify must not report cached" || true
  grep -q "verify    ok  service web/nginx" "$SPIKE/tmp/m7.txt" && grep -q "build OK (" "$SPIKE/tmp/m7.txt" \
    && ok "M7 --reverify boots and re-verifies despite matching keys" || bad "M7 reverify output"
else
  bad "M7 reverify build"
fi

echo "=== M8 stale bundle refuses at up with the re-render hint ==="
$IR render "$SPIKE/fixtures/plain" -o "$SPIKE/tmp/bundle" --image-cache "$CACHE" --cid-base 3600
truncate -s +1 "$CACHE/focal-guest.qcow2"   # the cache copy changes after render
if $IR up "$SPIKE/tmp/bundle" --image-cache "$CACHE" >"$SPIKE/tmp/m8.txt" 2>&1; then
  bad "M8 stale bundle refused"; $IR down --all >/dev/null 2>&1 || true
else
  grep -q "changed since this bundle was rendered" "$SPIKE/tmp/m8.txt" \
    && grep -q "re-render the bundle" "$SPIKE/tmp/m8.txt" \
    && ok "M8 stale-bundle refusal names the cause and the fix" || { bad "M8 hint text"; tail -3 "$SPIKE/tmp/m8.txt"; }
fi

$IR down --all >/dev/null 2>&1 || true

echo
echo "$PASS passed, $FAIL failed"
exit $((FAIL > 0))

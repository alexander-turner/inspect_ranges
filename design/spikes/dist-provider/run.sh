#!/bin/bash
# distribution-v1 slice 4 battery: the provider's implicit pull, live. A
# builder machine builds and pushes distmini to a local registry; a CONSUMER
# environment (fresh empty caches) runs a real `inspect eval` whose task_init
# auto-pulls the closure before any sample boots, the pulled realized guest
# serves its marker through the range network, a second eval is warm (zero
# fetches), and a never-pull host refuses before any sample with the knob
# named. Usage: ./run.sh [down]. See README.md. CID band 4030; registry 5059.
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
REG="ir-dist-provider-reg"
REG_URL="http://127.0.0.1:5059/ranges"
CONSUMER="$SPIKE/tmp/consumer"
FLAGS=(--image-cache "$CACHE" --build-cache "$BUILDS" --cid-base 4030 --readiness-timeout 300)

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

echo "=== P1 build and publish (the builder machine) ==="
DB_OUT=$($IR daemon-bundle -o "$SPIKE/tmp/artifacts")
DAEMON_SHA=$(echo "$DB_OUT" | grep -o 'bundle sha256:[0-9a-f]*' | cut -d: -f2)
ERA_SHA=$(sha256sum "$ERA" | cut -d' ' -f1)
$IR images derive "$ERA" --sha256 "$ERA_SHA" --name ubuntu-focal \
  --image-cache "$CACHE" --daemon-bundle "$SPIKE/tmp/artifacts" --daemon-sha256 "$DAEMON_SHA" >/dev/null
(cd "$RANGE" && "$IRBIN" build "${FLAGS[@]}" >"$SPIKE/tmp/p1.txt" 2>&1) \
  && grep -q "build OK" "$SPIKE/tmp/p1.txt" && ok "P1 distmini builds green" || { bad "P1 build"; tail -10 "$SPIKE/tmp/p1.txt"; exit 1; }
docker run -d --rm --name "$REG" -p 127.0.0.1:5059:5000 registry:2 >/dev/null
sleep 2
(cd "$RANGE" && "$IRBIN" push --to "$REG_URL" --image-cache "$CACHE" --build-cache "$BUILDS" >"$SPIKE/tmp/p1push.txt" 2>&1) \
  && grep -q "push OK" "$SPIKE/tmp/p1push.txt" && ok "P1b closure published to the local registry" || { bad "P1b push"; cat "$SPIKE/tmp/p1push.txt"; }

echo "=== P2 a consumer eval on a machine that built nothing (the headline) ==="
mkdir -p "$CONSUMER/images" "$CONSUMER/builds" "$CONSUMER/recipes"
EVAL_ENV=(env INSPECT_RANGES_IMAGE_CACHE="$CONSUMER/images" INSPECT_RANGES_BUILD_CACHE="$CONSUMER/builds" \
  INSPECT_RANGES_RECIPE_CACHE="$CONSUMER/recipes" INSPECT_RANGES_REGISTRY="$REG_URL")
(cd "$ROOT" && "${EVAL_ENV[@]}" uv run python "$SPIKE/dist_eval.py" "$RANGE" shipped-by-registry) >"$SPIKE/tmp/p2.txt" 2>&1
P2_RC=$?
grep "^PASS\|^FAIL" "$SPIKE/tmp/p2.txt" || true
[[ "$P2_RC" -eq 0 ]] && ok "P2 the eval ran green on pulled artifacts" || { bad "P2 eval"; tail -15 "$SPIKE/tmp/p2.txt"; }
grep -q "pull OK   distmini@sha256:" "$SPIKE/tmp/p2.txt" \
  && ok "P2b the implicit pull announced itself before the eval (task_init placement)" || bad "P2b pull line"
grep -qE ": (Downloading|Complete)" "$SPIKE/tmp/p2.txt" \
  && ok "P2c docker-pull-shaped transfer lines rendered" || bad "P2c transfer lines"
[[ -f "$CONSUMER/builds/distmini/manifest.json" ]] \
  && cmp -s "$CONSUMER/builds/distmini/manifest.json" "$BUILDS/distmini/manifest.json" \
  && ok "P2d the consumer holds the exact published manifest bytes" || bad "P2d manifest"

echo "=== P3 the second eval is warm: zero fetches ==="
(cd "$ROOT" && "${EVAL_ENV[@]}" uv run python "$SPIKE/dist_eval.py" "$RANGE" shipped-by-registry) >"$SPIKE/tmp/p3.txt" 2>&1
P3_RC=$?
[[ "$P3_RC" -eq 0 ]] && ok "P3 warm eval green" || { bad "P3 eval"; tail -10 "$SPIKE/tmp/p3.txt"; }
if grep -qE "pull OK|Downloading" "$SPIKE/tmp/p3.txt"; then
  bad "P3b warm path fetched (should be one hash, zero network)"
else
  ok "P3b warm path fetched nothing (local manifest matched the spec hash)"
fi

echo "=== P4 a never-pull host refuses before any sample ==="
mkdir -p "$SPIKE/tmp/offline/images" "$SPIKE/tmp/offline/builds" "$SPIKE/tmp/offline/recipes"
if (cd "$ROOT" && env INSPECT_RANGES_IMAGE_CACHE="$SPIKE/tmp/offline/images" \
  INSPECT_RANGES_BUILD_CACHE="$SPIKE/tmp/offline/builds" INSPECT_RANGES_RECIPE_CACHE="$SPIKE/tmp/offline/recipes" \
  INSPECT_RANGES_REGISTRY="$REG_URL" INSPECT_RANGES_NEVER_PULL=1 \
  uv run python "$SPIKE/dist_eval.py" "$RANGE" x) >"$SPIKE/tmp/p4.txt" 2>&1; then
  bad "P4 never-pull eval was accepted"
else
  grep -q "never-pull" "$SPIKE/tmp/p4.txt" \
    && ! grep -q "guest-boot\|readiness" "$SPIKE/tmp/p4.txt" \
    && ok "P4 never-pull refuses with the knob named, before any sample boots" || { bad "P4 refusal"; tail -10 "$SPIKE/tmp/p4.txt"; }
fi

stop_registry
$IR down --all >/dev/null 2>&1 || true
echo
echo "$PASS passed, $FAIL failed"
exit $((FAIL > 0))

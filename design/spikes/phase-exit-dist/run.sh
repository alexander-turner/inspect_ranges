#!/bin/bash
# distribution-v1 PHASE EXIT: the Journey B transcripts, command for command,
# on the real vulhub-zabbix range. The public org's role is played by LOCAL
# registries here; the real-hub half of the exit (production auth, presigned
# redirects, rate limits) is discharged by the separate recorded dist-hub
# spike, so the exit is a composite proof (canonical publishes are
# catalog-phase work). Sessions: publishing (push), consuming connected
# (pull + a real inspect eval solving the pulled range on a machine that
# built nothing, incl. the edited-spec refusal), mirroring (whole location,
# and a single build to a directory for the air gap), consuming a range built
# by another group (spec-driven cross-registry mirror), and consuming
# disconnected (the archive as the configured registry).
# Usage: ./run.sh [down]. CID band 4050; registries 5062 (ours) / 5063 (theirs).
set -euo pipefail
cd "$(dirname "$0")"
SPIKE="$PWD"
ROOT="$(cd ../../.. && pwd)"
RANGE_SRC="$ROOT/src/inspect_ranges/examples/_vulhub_zabbix"

ERA="${ERA:-$HOME/.cache/inspect-ranges/images/focal-server-cloudimg-amd64.img}"
export XDG_STATE_HOME="$SPIKE/tmp/state"
IR="uv run inspect-ranges"
IRBIN="$ROOT/.venv/bin/inspect-ranges"
CACHE="$SPIKE/tmp/cache"
BUILDS="$SPIKE/tmp/builds"
REG_OURS="ir-pxd-ours"; REG_THEIRS="ir-pxd-theirs"
URL_OURS="http://127.0.0.1:5062/ranges"
URL_THEIRS="http://127.0.0.1:5063/ranges"
FLAGS=(--image-cache "$CACHE" --build-cache "$BUILDS" --cid-base 4050 --readiness-timeout 300)

stop_registries() { docker rm -f "$REG_OURS" "$REG_THEIRS" >/dev/null 2>&1 || true; }
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
cp -r "$RANGE_SRC" "$SPIKE/tmp/vulhub-zabbix"
RANGE="$SPIKE/tmp/vulhub-zabbix"
export CAPTURE_CHUNK_MB=1

echo "=== X0 the builder's Journey A tail: build vulhub ==="
DB_OUT=$($IR daemon-bundle -o "$SPIKE/tmp/artifacts")
DAEMON_SHA=$(echo "$DB_OUT" | grep -o 'bundle sha256:[0-9a-f]*' | cut -d: -f2)
ERA_SHA=$(sha256sum "$ERA" | cut -d' ' -f1)
$IR images derive "$ERA" --sha256 "$ERA_SHA" --name ubuntu-focal \
  --image-cache "$CACHE" --daemon-bundle "$SPIKE/tmp/artifacts" --daemon-sha256 "$DAEMON_SHA" >/dev/null
(cd "$RANGE" && "$IRBIN" build "${FLAGS[@]}" --recipe-budget 2400 >"$SPIKE/tmp/x0.txt" 2>&1) \
  && grep -q "build OK" "$SPIKE/tmp/x0.txt" && ok "X0 vulhub builds green" || { bad "X0"; tail -10 "$SPIKE/tmp/x0.txt"; exit 1; }
docker run -d --rm --name "$REG_OURS" -p 127.0.0.1:5062:5000 registry:2 >/dev/null
docker run -d --rm --name "$REG_THEIRS" -p 127.0.0.1:5063:5000 registry:2 >/dev/null
sleep 2

echo "=== X1 SESSION publishing: push (the transcript's output shape) ==="
(cd "$RANGE" && "$IRBIN" push --to "$URL_OURS" --image-cache "$CACHE" --build-cache "$BUILDS" >"$SPIKE/tmp/x1.txt" 2>&1)
grep -q "manifest  vulhub-zabbix (spec sha256:" "$SPIKE/tmp/x1.txt" \
  && grep -q "push OK   vulhub-zabbix@sha256:" "$SPIKE/tmp/x1.txt" \
  && ok "X1 push prints the manifest line and the publishable identity" || { bad "X1"; cat "$SPIKE/tmp/x1.txt"; }

echo "=== X2 SESSION consuming, connected: pull + a real eval, built nothing ==="
C="$SPIKE/tmp/consumer"; mkdir -p "$C/images" "$C/builds" "$C/recipes"
CONS_ENV=(env INSPECT_RANGES_IMAGE_CACHE="$C/images" INSPECT_RANGES_BUILD_CACHE="$C/builds" \
  INSPECT_RANGES_RECIPE_CACHE="$C/recipes" INSPECT_RANGES_REGISTRY="$URL_OURS")
(cd "$RANGE" && "${CONS_ENV[@]}" "$IRBIN" pull >"$SPIKE/tmp/x2.txt" 2>&1)
grep -q "resolve   spec sha256:" "$SPIKE/tmp/x2.txt" && grep -q "pull OK" "$SPIKE/tmp/x2.txt" \
  && ok "X2 explicit pull resolves and fetches, verified" || { bad "X2"; cat "$SPIKE/tmp/x2.txt"; }
(cd "$ROOT" && "${CONS_ENV[@]}" uv run python "$ROOT/design/spikes/phase-exit-build-v1/journey_eval.py" "$RANGE") >"$SPIKE/tmp/x2eval.txt" 2>&1
X2_RC=$?
grep "^PASS\|^FAIL" "$SPIKE/tmp/x2eval.txt" | head -8
[[ "$X2_RC" -eq 0 ]] && ok "X2b a real inspect eval SOLVED the pulled range (1.0, valid) on a machine that built nothing" \
  || { bad "X2b eval"; tail -10 "$SPIKE/tmp/x2eval.txt"; }

echo "=== X2c the edited-spec refusal (the transcript's no-build-for-spec) ==="
cp -r "$RANGE" "$SPIKE/tmp/edited"
sed -i 's/port: 10051/port: 10052/' "$SPIKE/tmp/edited/range.yaml" 2>/dev/null || sed -i '0,/port: 80/s//port: 81/' "$SPIKE/tmp/edited/range.yaml"
if (cd "$SPIKE/tmp/edited" && "${CONS_ENV[@]}" "$IRBIN" pull >"$SPIKE/tmp/x2c.txt" 2>&1); then
  bad "X2c edited-spec pull accepted"
else
  grep -q "no-build-for-spec" "$SPIKE/tmp/x2c.txt" && grep -q "nearest" "$SPIKE/tmp/x2c.txt" \
    && ok "X2c the refusal names the nearest published build, house style" || { bad "X2c"; cat "$SPIKE/tmp/x2c.txt"; }
fi

echo "=== X3 SESSION mirroring: whole location, and one build to a directory ==="
$IR mirror --from "$URL_OURS" --to "$SPIKE/tmp/ranges-archive" >"$SPIKE/tmp/x3.txt" 2>&1 \
  && grep -qE "mirror    1 artifacts:" "$SPIKE/tmp/x3.txt" \
  && ok "X3 whole-location mirror to the archive directory" || { bad "X3"; cat "$SPIKE/tmp/x3.txt"; }
tar -C "$SPIKE/tmp" -czf "$SPIKE/tmp/ranges-archive.tgz" ranges-archive \
  && ok "X3b the archive tars (sneakernet from here)"

echo "=== X4 SESSION consuming a range built by another group ==="
$IR mirror "$RANGE" --from "$URL_OURS" --to "$URL_THEIRS" >/dev/null 2>&1  # seed 'their' registry
G="$SPIKE/tmp/group"; mkdir -p "$G/images" "$G/builds" "$G/recipes"
(cd "$RANGE" && env INSPECT_RANGES_IMAGE_CACHE="$G/images" INSPECT_RANGES_BUILD_CACHE="$G/builds" \
  INSPECT_RANGES_RECIPE_CACHE="$G/recipes" "$IRBIN" mirror . --from "$URL_THEIRS" --to "$URL_OURS" >"$SPIKE/tmp/x4.txt" 2>&1) || true
grep -q "resolve   spec sha256:" "$SPIKE/tmp/x4.txt" \
  && grep -qE "mirror    vulhub-zabbix: [0-9]+ copied, [0-9]+ already present" "$SPIKE/tmp/x4.txt" \
  && ok "X4 the cross-group move: their registry -> ours, spec-driven, dedup visible" || { bad "X4"; cat "$SPIKE/tmp/x4.txt"; }

echo "=== X5 SESSION consuming, disconnected: the archive IS the registry ==="
mkdir -p "$SPIKE/tmp/island" && tar -C "$SPIKE/tmp/island" -xzf "$SPIKE/tmp/ranges-archive.tgz"
D="$SPIKE/tmp/disconnected"; mkdir -p "$D/images" "$D/builds" "$D/recipes"
(cd "$RANGE" && env INSPECT_RANGES_IMAGE_CACHE="$D/images" INSPECT_RANGES_BUILD_CACHE="$D/builds" \
  INSPECT_RANGES_RECIPE_CACHE="$D/recipes" INSPECT_RANGES_REGISTRY="$SPIKE/tmp/island/ranges-archive" \
  "$IRBIN" pull >"$SPIKE/tmp/x5.txt" 2>&1)
grep -q "pull OK" "$SPIKE/tmp/x5.txt" \
  && cmp -s "$D/builds/vulhub-zabbix/manifest.json" "$BUILDS/vulhub-zabbix/manifest.json" \
  && ok "X5 the disconnected session pulls from the shipped archive, byte-identical" || { bad "X5"; cat "$SPIKE/tmp/x5.txt"; }

$IR down --all >/dev/null 2>&1 || true
stop_registries
echo
echo "$PASS passed, $FAIL failed"
exit $((FAIL > 0))

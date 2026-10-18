#!/bin/bash
# build-v1 PHASE EXIT (build-v1.md "Verification: the phase proves itself").
# One scripted run: make check + unit suite; the slice 1 recipe battery; the
# slice 2 crash matrix; the slice 4 verification-failure battery (the
# Journey A refusal shape); the vulhub battery; then the Journey A transcript
# executed command for command on a scratch copy of the real range (validate;
# the induced wrong-version detour; the fixed build; the no-op cached build;
# the recipe-edit incremental rebuild; a real inspect eval solving the built
# range). Measured timings close the requirements doc's derive-wall-time and
# Linux-build-wall-time UNMEASURED entries. Usage: ./run.sh [down].
# The delegated batteries each take the shared battery lock themselves; the
# Journey A section takes it for its own span. CID band 3800.
set -uo pipefail
cd "$(dirname "$0")"
SPIKE="$PWD"
ROOT="$(cd ../../.. && pwd)"
RANGE="$ROOT/examples/vulhub-zabbix"
ERA="${ERA:-$HOME/.cache/inspect-ranges/images/focal-server-cloudimg-amd64.img}"
IR="uv run inspect-ranges"
IRBIN="$ROOT/.venv/bin/inspect-ranges"

if [[ "${1:-}" == "down" ]]; then
  (cd "$ROOT" && $IR down --all) || true
  exit 0
fi

grep -q vhost_vsock /proc/modules || { echo "need: sudo modprobe vhost_vsock"; exit 1; }
[[ -f "$ERA" ]] || { echo "missing focal vendor image $ERA"; exit 1; }

PASS=0; FAIL=0
ok()  { echo "PASS  $1"; PASS=$((PASS+1)); }
bad() { echo "FAIL  $1"; FAIL=$((FAIL+1)); }

rm -rf "$SPIKE/tmp" && mkdir -p "$SPIKE/tmp/logs"

echo "=== P1 make check + unit suite ==="
(cd "$ROOT" && make check && .venv/bin/pytest tests/ -q) >"$SPIKE/tmp/logs/p1.txt" 2>&1 \
  && ok "P1 make check and unit suite green" || { bad "P1 checks/suite"; tail -5 "$SPIKE/tmp/logs/p1.txt"; }

echo "=== P2 slice 1: the fixture-recipe battery ==="
"$ROOT/design/spikes/build-v1/run.sh" >"$SPIKE/tmp/logs/p2.txt" 2>&1 \
  && ok "P2 $(tail -2 "$SPIKE/tmp/logs/p2.txt" | grep passed)" || { bad "P2 build-v1 battery"; tail -5 "$SPIKE/tmp/logs/p2.txt"; }

echo "=== P3 slice 2: the build-verb crash matrix ==="
"$ROOT/design/spikes/build-cmd/run.sh" >"$SPIKE/tmp/logs/p3.txt" 2>&1 \
  && ok "P3 $(tail -2 "$SPIKE/tmp/logs/p3.txt" | grep passed)" || { bad "P3 build-cmd battery"; tail -5 "$SPIKE/tmp/logs/p3.txt"; }

echo "=== P4 slice 4: the verification-failure battery (the refusal shape) ==="
"$ROOT/design/spikes/build-verify/run.sh" >"$SPIKE/tmp/logs/p4.txt" 2>&1 \
  && ok "P4 $(tail -2 "$SPIKE/tmp/logs/p4.txt" | grep passed)" || { bad "P4 build-verify battery"; tail -5 "$SPIKE/tmp/logs/p4.txt"; }

echo "=== P5 slice 6: the vulhub battery ==="
"$ROOT/design/spikes/vulhub-build/run.sh" >"$SPIKE/tmp/logs/p5.txt" 2>&1 \
  && ok "P5 $(tail -2 "$SPIKE/tmp/logs/p5.txt" | grep passed)" || { bad "P5 vulhub battery"; tail -5 "$SPIKE/tmp/logs/p5.txt"; }

echo "=== Journey A, command for command (scratch copy, isolated caches) ==="
exec 9>/tmp/inspect-ranges-battery.lock
flock 9
cd "$ROOT"
$IR down --all >/dev/null 2>&1 || true

JR="$SPIKE/tmp/journey/vulhub-zabbix"
mkdir -p "$(dirname "$JR")"
cp -r "$RANGE/." "$JR"
export XDG_STATE_HOME="$SPIKE/tmp/state"
export INSPECT_RANGES_IMAGE_CACHE="$SPIKE/tmp/cache"
export INSPECT_RANGES_BUILD_CACHE="$SPIKE/tmp/builds"
export CAPTURE_CHUNK_MB=1  # beacons must land in a rotated (harvested) chunk for pcap corroboration
mkdir -p "$SPIKE/tmp/cache"
FLAGS=(--cid-base 3800 --readiness-timeout 300 --recipe-budget 2400)

DB_OUT=$($IR daemon-bundle -o "$SPIKE/tmp/artifacts")
DAEMON_SHA=$(echo "$DB_OUT" | grep -o 'bundle sha256:[0-9a-f]*' | cut -d: -f2)
ERA_SHA=$(sha256sum "$ERA" | cut -d' ' -f1)
T0=$(date +%s)
$IR images derive "$ERA" --sha256 "$ERA_SHA" --name ubuntu-focal \
  --daemon-bundle "$SPIKE/tmp/artifacts" --daemon-sha256 "$DAEMON_SHA" >/dev/null \
  && ok "J0 focal golden derived ($(( $(date +%s) - T0 )) s; the derive-wall-time measurement)" \
  || bad "J0 derive"

(cd "$JR" && $IR validate) >"$SPIKE/tmp/logs/j1.txt" 2>&1 \
  && grep -q "vulhub-zabbix" "$SPIKE/tmp/logs/j1.txt" \
  && ok "J1 bare validate in the range directory" || bad "J1 validate"

sed -i 's/{ name: php, version: "7.4", package: php7.4,/{ name: php, version: "7.0", package: php7.4,/' "$JR/range.yaml"
if (cd "$JR" && "$IRBIN" build "${FLAGS[@]}") >"$SPIKE/tmp/logs/j2.txt" 2>&1; then
  bad "J2 induced wrong-version build must fail"
else
  grep -q "service-not-verified" "$SPIKE/tmp/logs/j2.txt" \
    && grep -q "declared php version 7.0" "$SPIKE/tmp/logs/j2.txt" \
    && grep -q "log:" "$SPIKE/tmp/logs/j2.txt" \
    && ok "J2 the Journey A refusal: coded, declared-vs-observed, log path" \
    || { bad "J2 refusal shape"; grep -A1 "verify" "$SPIKE/tmp/logs/j2.txt" | tail -6; }
fi
if [[ -e "$SPIKE/tmp/builds/vulhub-zabbix/manifest.json" ]]; then
  bad "J2b failed build must mint no manifest"
else
  ok "J2b failed build minted no manifest"
fi

sed -i 's/{ name: php, version: "7.0", package: php7.4,/{ name: php, version: "7.4", package: php7.4,/' "$JR/range.yaml"
T0=$(date +%s)
(cd "$JR" && "$IRBIN" build "${FLAGS[@]}") >"$SPIKE/tmp/logs/j3.txt" 2>&1 \
  && grep -q "build OK" "$SPIKE/tmp/logs/j3.txt" \
  && grep -q "behavioral checks=3" "$SPIKE/tmp/logs/j3.txt" \
  && ok "J3 fixed build green incl. behavioral proof ($(( $(date +%s) - T0 )) s; the first-build measurement)" \
  || { bad "J3 fixed build"; tail -8 "$SPIKE/tmp/logs/j3.txt"; }

T0=$(date +%s)
(cd "$JR" && "$IRBIN" build "${FLAGS[@]}") >"$SPIKE/tmp/logs/j4.txt" 2>&1 \
  && grep -q "build OK (cached, verified" "$SPIKE/tmp/logs/j4.txt" \
  && ok "J4 unchanged rebuild is the cached no-op ($(( $(date +%s) - T0 )) s)" \
  || { bad "J4 cached no-op"; tail -3 "$SPIKE/tmp/logs/j4.txt"; }

printf '\necho "step: phase-exit marker"\n' >> "$JR/recipes/vulhub.zabbix-agent/run.sh"
T0=$(date +%s)
(cd "$JR" && "$IRBIN" build "${FLAGS[@]}") >"$SPIKE/tmp/logs/j5.txt" 2>&1 \
  && grep -q "reused_guests=3" "$SPIKE/tmp/logs/j5.txt" \
  && grep -q "rebuilt_guests=1" "$SPIKE/tmp/logs/j5.txt" \
  && [ "$(grep -c "skipped=unchanged" "$SPIKE/tmp/logs/j5.txt")" -eq 3 ] \
  && grep -q "recipe    guest=agent" "$SPIKE/tmp/logs/j5.txt" \
  && grep -q "build OK" "$SPIKE/tmp/logs/j5.txt" \
  && ok "J5 recipe edit rebuilds exactly the agent ($(( $(date +%s) - T0 )) s; the incremental measurement)" \
  || { bad "J5 incremental"; tail -8 "$SPIKE/tmp/logs/j5.txt"; }

echo "=== J6 inspect eval solves the built range ==="
(cd "$ROOT" && uv run python "$SPIKE/journey_eval.py" "$JR") >"$SPIKE/tmp/logs/j6.txt" 2>&1
J6_RC=$?
grep "^PASS\|^FAIL" "$SPIKE/tmp/logs/j6.txt"
[ "$J6_RC" -eq 0 ] && ok "J6 a real inspect eval solved the built range (1.0, valid, both goals)" \
  || { bad "J6 eval"; tail -10 "$SPIKE/tmp/logs/j6.txt"; }

$IR down --all >/dev/null 2>&1 || true

echo
echo "$PASS passed, $FAIL failed"
exit $((FAIL > 0))

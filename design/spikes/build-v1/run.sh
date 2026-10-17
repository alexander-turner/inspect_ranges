#!/bin/bash
# build-v1 slice 1 battery: recipe bundles and the executor.
# Host side: digest stability, unresolvable-recipe refusal, vars validation,
# offline-mode refusal. Live side (noble guest over vsock): the IR_* contract
# end to end (push + root exec), nonzero-exit failure naming the log, the
# host-side recipe budget's process-group kill, and the background-children
# exec returning promptly. Usage: ./run.sh [down]. See README.md.
set -euo pipefail
cd "$(dirname "$0")"
SPIKE="$PWD"
ROOT="$(cd ../../.. && pwd)"

VENDOR="${VENDOR:-$HOME/.cache/inspect-ranges/images/noble-server-cloudimg-amd64.img}"
export XDG_STATE_HOME="$SPIKE/tmp/state"   # project state isolated to the battery
IR="uv run inspect-ranges"
C() { (cd "$ROOT" && uv run python design/spikes/_shared/chexec.py --boot "$SPIKE/tmp/bundle/boot.json" --guest web --user root exec "$1"); }
DRIVER() { (cd "$ROOT" && uv run python design/spikes/build-v1/battery.py "$1" \
  --fixtures design/spikes/build-v1/fixtures --tmp design/spikes/build-v1/tmp/driver \
  ${2:+--boot design/spikes/build-v1/tmp/bundle/boot.json}); }
CACHE="$SPIKE/tmp/cache"

if [[ "${1:-}" == "down" ]]; then
  (cd "$ROOT" && $IR down --all) || true
  exit 0
fi

grep -q vhost_vsock /proc/modules || { echo "need: sudo modprobe vhost_vsock"; exit 1; }
[[ -f "$VENDOR" ]] || { echo "missing vendor image $VENDOR"; exit 1; }

PASS=0; FAIL=0
ok()  { echo "PASS  $1"; PASS=$((PASS+1)); }
bad() { echo "FAIL  $1"; FAIL=$((FAIL+1)); }

exec 9>/tmp/inspect-ranges-battery.lock
flock 9

cd "$ROOT"
$IR down --all >/dev/null 2>&1 || true
rm -rf "$SPIKE/tmp" && mkdir -p "$SPIKE/tmp"

echo "=== B1-B4 host-only checks (no range needed) ==="
DRIVER digest     && ok "B1 digest stable across identical rebuilds, sensitive to content" || bad "B1 digest"
DRIVER unresolved && ok "B2 unresolvable recipe refuses with recipe-not-resolved" || bad "B2 unresolved"
DRIVER vars       && ok "B3 vars validated against inputs (unknown + missing collected)" || bad "B3 vars"
DRIVER offline    && ok "B4 offline mode typed-refused" || bad "B4 offline"

if [[ "${SKIP_VM:-}" == "1" ]]; then
  echo; echo "$PASS passed, $FAIL failed (host checks only; SKIP_VM=1)"
  exit $((FAIL > 0))
fi

echo "=== derive the battery golden and boot the range ==="
DB_OUT=$($IR daemon-bundle -o "$SPIKE/tmp/artifacts") \
  || { echo "daemon-bundle build failed (install the pinned Go toolchain)"; exit 1; }
DAEMON_SHA=$(echo "$DB_OUT" | grep -o 'bundle sha256:[0-9a-f]*' | cut -d: -f2)
VENDOR_SHA=$(sha256sum "$VENDOR" | cut -d' ' -f1)
$IR images derive "$VENDOR" --sha256 "$VENDOR_SHA" --name build-guest \
  --image-cache "$CACHE" --daemon-bundle "$SPIKE/tmp/artifacts" --daemon-sha256 "$DAEMON_SHA" >/dev/null
$IR render design/spikes/build-v1/spec.yaml -o "$SPIKE/tmp/bundle" --image-cache "$CACHE" --cid-base 3100
$IR up "$SPIKE/tmp/bundle" --image-cache "$CACHE"

echo "=== B5-B10 live executor checks ==="
DRIVER ok boot     && ok "B5 success recipe (vars, IR_PUSH, IR_EXEC, stage log)" || bad "B5 success recipe"

CONF=$(C "cat /etc/recipe.conf" || true)
[[ "$CONF" == *"marker=zig guest=web verbose=false"* ]] \
  && ok "B6 pushed file landed with vars rendered" || bad "B6 pushed file (got: $CONF)"
MODE=$(C "stat -c %a /etc/recipe.conf" || true)
[[ "$MODE" == "600" ]] && ok "B7 pushed file mode 600" || bad "B7 pushed file mode (got: $MODE)"
MADE=$(C "cat /opt/recipe-made" || true)
[[ "$MADE" == "made-by-recipe" ]] && ok "B8 root exec made its artifact" || bad "B8 root exec (got: $MADE)"
SCRIPTED=$(C "cat /opt/recipe-scripted" || true)
[[ "$SCRIPTED" == "scripted" ]] && ok "B9 --script upload exec made its artifact" || bad "B9 script exec (got: $SCRIPTED)"
STAGED=$(C "ls /tmp/.ir-recipe-* /tmp/.ir-push-* 2>/dev/null | wc -l" || true)
[[ "$STAGED" == "0" ]] && ok "B10 no staging files left in guest /tmp" || bad "B10 staging cleanup (left: $STAGED)"

DRIVER fail boot   && ok "B11 nonzero exit fails naming rc and log" || bad "B11 nonzero exit"
DRIVER budget boot && ok "B12 host budget kills the process group promptly" || bad "B12 budget"
DRIVER bg boot     && ok "B13 background-child exec returns promptly" || bad "B13 background child"

$IR down --all >/dev/null

echo
echo "$PASS passed, $FAIL failed"
exit $((FAIL > 0))

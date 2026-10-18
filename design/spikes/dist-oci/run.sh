#!/bin/bash
# distribution-v1 slice 1 battery: the real vulhub build round-trips through a
# plain OCI image-layout directory into fresh empty caches, survives the tar
# sneakernet form, refuses tampering with nothing consumable left dangling,
# and the materialized artifacts boot and serve. Zero network, zero
# credentials. Usage: ./run.sh [down]. See README.md. CID band 4000.
set -euo pipefail
cd "$(dirname "$0")"
SPIKE="$PWD"
ROOT="$(cd ../../.. && pwd)"
RANGE="$ROOT/examples/vulhub-zabbix"

ERA="${ERA:-$HOME/.cache/inspect-ranges/images/focal-server-cloudimg-amd64.img}"
export XDG_STATE_HOME="$SPIKE/tmp/state"
export INSPECT_RANGES_BUILD_CACHE="$SPIKE/tmp/builds"
IR="uv run inspect-ranges"
IRBIN="$ROOT/.venv/bin/inspect-ranges"
PYDIST="uv run python design/spikes/dist-oci/dist.py"
CACHE="$SPIKE/tmp/cache"
PULLED="$SPIKE/tmp/pulled"
FLAGS=(--image-cache "$CACHE" --build-cache "$SPIKE/tmp/builds" --cid-base 4000 --readiness-timeout 300)

if [[ "${1:-}" == "down" ]]; then
  (cd "$ROOT" && $IR down --all) || true
  exit 0
fi

grep -q vhost_vsock /proc/modules || { echo "need: sudo modprobe vhost_vsock"; exit 1; }
[[ -f "$ERA" ]] || { echo "missing focal vendor image $ERA"; exit 1; }
command -v qemu-img >/dev/null || { echo "need qemu-img on the host"; exit 1; }

PASS=0; FAIL=0
ok()  { echo "PASS  $1"; PASS=$((PASS+1)); }
bad() { echo "FAIL  $1"; FAIL=$((FAIL+1)); }

exec 9>/tmp/inspect-ranges-battery.lock
flock 9

cd "$ROOT"
$IR down --all >/dev/null 2>&1 || true
rm -rf "$SPIKE/tmp" && mkdir -p "$SPIKE/tmp"

echo "=== D1 build vulhub (the artifact set under test) ==="
DB_OUT=$($IR daemon-bundle -o "$SPIKE/tmp/artifacts")
DAEMON_SHA=$(echo "$DB_OUT" | grep -o 'bundle sha256:[0-9a-f]*' | cut -d: -f2)
ERA_SHA=$(sha256sum "$ERA" | cut -d' ' -f1)
$IR images derive "$ERA" --sha256 "$ERA_SHA" --name ubuntu-focal \
  --image-cache "$CACHE" --daemon-bundle "$SPIKE/tmp/artifacts" --daemon-sha256 "$DAEMON_SHA" >/dev/null
if (cd "$RANGE" && "$IRBIN" build "${FLAGS[@]}" --recipe-budget 2400 >"$SPIKE/tmp/d1.txt" 2>&1); then
  grep -q "build OK" "$SPIKE/tmp/d1.txt" && ok "D1 vulhub builds green" || bad "D1 build OK line"
else
  bad "D1 vulhub build"; tail -20 "$SPIKE/tmp/d1.txt"; exit 1
fi

echo "=== D2 push the closure into an OCI image-layout directory ==="
$PYDIST push --range-name vulhub-zabbix --build-cache "$SPIKE/tmp/builds" \
  --image-cache "$CACHE" --range-dir "$RANGE" --layout "$SPIKE/tmp/layout" >"$SPIKE/tmp/d2.txt" 2>&1 \
  && grep -q "root sha256:" "$SPIKE/tmp/d2.txt" \
  && [[ -f "$SPIKE/tmp/layout/oci-layout" && -f "$SPIKE/tmp/layout/index.json" ]] \
  && ok "D2 push writes a valid layout and prints the root digest" || { bad "D2 push"; cat "$SPIKE/tmp/d2.txt"; }
ROOT_DIGEST=$(grep -o 'root sha256:[0-9a-f]*' "$SPIKE/tmp/d2.txt" | head -1)
BLOBS_1=$(find "$SPIKE/tmp/layout/blobs" -type f | wc -l)

echo "=== D3 a second push is pure dedup ==="
$PYDIST push --range-name vulhub-zabbix --build-cache "$SPIKE/tmp/builds" \
  --image-cache "$CACHE" --range-dir "$RANGE" --layout "$SPIKE/tmp/layout" >"$SPIKE/tmp/d3.txt" 2>&1
BLOBS_2=$(find "$SPIKE/tmp/layout/blobs" -type f | wc -l)
[[ "$BLOBS_1" == "$BLOBS_2" && "$(grep -o 'root sha256:[0-9a-f]*' "$SPIKE/tmp/d3.txt")" == "$ROOT_DIGEST" ]] \
  && ok "D3 re-push adds zero blobs and reproduces the root digest" \
  || bad "D3 idempotent push (blobs $BLOBS_1 -> $BLOBS_2)"

echo "=== D4 the sneakernet form: tar, ship, untar ==="
tar -C "$SPIKE/tmp" -czf "$SPIKE/tmp/layout.tgz" layout
mkdir -p "$SPIKE/tmp/shipped" && tar -C "$SPIKE/tmp/shipped" -xzf "$SPIKE/tmp/layout.tgz"
ok "D4 layout tars and untars (standard file tree, no special handling)"

echo "=== D5 materialize into fresh empty caches from the shipped copy ==="
mkdir -p "$PULLED/images" "$PULLED/builds" "$PULLED/recipes"
$PYDIST pull --layout "$SPIKE/tmp/shipped/layout" --ref vulhub-zabbix \
  --image-cache "$PULLED/images" --build-cache "$PULLED/builds" --recipe-cache "$PULLED/recipes" >"$SPIKE/tmp/d5.txt" 2>&1 \
  && grep -q "manifest.json" "$SPIKE/tmp/d5.txt" \
  && [[ -f "$PULLED/builds/vulhub-zabbix/manifest.json" ]] \
  && ok "D5 materialization lands the whole closure (manifest last)" || { bad "D5 pull"; cat "$SPIKE/tmp/d5.txt"; }
REALIZED_COUNT=$(ls "$PULLED/images" | grep -c '\.realized\.json$' || true)
[[ "$REALIZED_COUNT" == "4" ]] && ok "D5b all 4 realized images landed with sidecars" || bad "D5b realized count ($REALIZED_COUNT)"
qemu-img info --output=json "$PULLED/images/ubuntu-focal.qcow2" | grep -q '"backing-filename": "focal-server-cloudimg-amd64.img"' \
  && ok "D5c the pulled golden's REAL backing chain resolved and validated (qemu-img, not a fake)" \
  || bad "D5c golden backing"

echo "=== D6 pulled bytes are the built bytes ==="
DIFFS=0
for f in "$PULLED/images"/*.qcow2 "$PULLED/images"/*.img; do
  cmp -s "$f" "$CACHE/$(basename "$f")" || DIFFS=$((DIFFS+1))
done
[[ "$DIFFS" == "0" ]] && ok "D6 every pulled image is byte-identical to the built original" || bad "D6 ($DIFFS differ)"
cmp -s "$PULLED/builds/vulhub-zabbix/manifest.json" "$SPIKE/tmp/builds/vulhub-zabbix/manifest.json" \
  && ok "D6b the pulled build manifest is the exact published bytes" || bad "D6b manifest bytes"

echo "=== D7 converge: a second pull fetches nothing ==="
$PYDIST pull --layout "$SPIKE/tmp/shipped/layout" --ref vulhub-zabbix \
  --image-cache "$PULLED/images" --build-cache "$PULLED/builds" --recipe-cache "$PULLED/recipes" >"$SPIKE/tmp/d7.txt" 2>&1
grep -q "fetched 0:" "$SPIKE/tmp/d7.txt" && ok "D7 re-pull converges by digest (fetched 0)" || { bad "D7"; cat "$SPIKE/tmp/d7.txt"; }

echo "=== D8 tampering refuses, and no manifest lands ==="
cp -r "$SPIKE/tmp/shipped/layout" "$SPIKE/tmp/tampered"
BIGGEST=$(find "$SPIKE/tmp/tampered/blobs" -type f -printf '%s %p\n' | sort -rn | head -1 | cut -d' ' -f2)
printf 'CORRUPT' | dd of="$BIGGEST" bs=1 seek=1024 conv=notrunc 2>/dev/null
mkdir -p "$SPIKE/tmp/t-images" "$SPIKE/tmp/t-builds" "$SPIKE/tmp/t-recipes"
if $PYDIST pull --layout "$SPIKE/tmp/tampered" --ref vulhub-zabbix \
  --image-cache "$SPIKE/tmp/t-images" --build-cache "$SPIKE/tmp/t-builds" --recipe-cache "$SPIKE/tmp/t-recipes" >"$SPIKE/tmp/d8.txt" 2>&1; then
  bad "D8 tampered pull was accepted"
else
  grep -q "blob-digest-mismatch" "$SPIKE/tmp/d8.txt" \
    && [[ ! -f "$SPIKE/tmp/t-builds/vulhub-zabbix/manifest.json" ]] \
    && ok "D8 tampered blob refuses by digest and no consumable manifest landed" || { bad "D8 refusal shape"; cat "$SPIKE/tmp/d8.txt"; }
fi

echo "=== D9 the pulled caches boot and serve (the headline) ==="
INSPECT_RANGES_BUILD_CACHE="$PULLED/builds" $IR plan "$RANGE" --image-cache "$PULLED/images" >"$SPIKE/tmp/d9plan.txt" 2>&1 \
  && ok "D9a plan consumes the PULLED manifest and resolves the pulled realized images" || { bad "D9a plan"; tail -5 "$SPIKE/tmp/d9plan.txt"; }
INSPECT_RANGES_BUILD_CACHE="$PULLED/builds" $IR render "$RANGE" -o "$SPIKE/tmp/bundle" --image-cache "$PULLED/images" --cid-base 4000 >/dev/null 2>&1 \
  && ok "D9b render from the pulled caches" || bad "D9b render"
$IR up "$SPIKE/tmp/bundle" --image-cache "$PULLED/images" >"$SPIKE/tmp/d9up.txt" 2>&1 \
  && ok "D9c up from pulled artifacts reaches ready (verify-images green on the pulled chain)" || { bad "D9c up"; tail -5 "$SPIKE/tmp/d9up.txt"; }
RC=$(docker ps --format '{{.Names}}' | grep -E '^ir-vulhub-zabbix-.*-range-1$' | head -1)
FRONT=$(cd "$ROOT" && uv run python design/spikes/_shared/chexec.py --boot "$SPIKE/tmp/bundle/boot.json" --project "${RC%-range-1}" --guest attacker --user root exec \
  "wget -q -O- http://web/index.php 2>/dev/null | grep -io 'zabbix' | head -1" || true)
[[ "$FRONT" == *[Zz]abbix* ]] && ok "D9d the pulled range serves zabbix to the attacker" || bad "D9d frontend (got: $FRONT)"
$IR down --all >/dev/null 2>&1 || true

echo
echo "$PASS passed, $FAIL failed"
exit $((FAIL > 0))

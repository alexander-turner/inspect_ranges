#!/bin/bash
# standard-images-v1 slice 2 battery: the promotion act, live. The attack
# factory builds; `publish --guest box --as attack` promotes the realized
# image to the bare catalog name at a live registry; a consumer machine does
# `images pull attack`, then a range declaring `image: attack` as its
# ATTACKER renders and boots from the pulled chain; the catalog artifact
# drives whole-location enumeration; and the fleet pin file refuses a moved
# catalog. Usage: ./run.sh [down]. CID band 4070; registry port 5064.
set -euo pipefail
cd "$(dirname "$0")"
SPIKE="$PWD"
ROOT="$(cd ../../.. && pwd)"
RANGE="$ROOT/catalog/attack"

NOBLE="${NOBLE:-$HOME/.cache/inspect-ranges/images/noble-server-cloudimg-amd64.img}"
export XDG_STATE_HOME="$SPIKE/tmp/state"
IR="uv run inspect-ranges"
IRBIN="$ROOT/.venv/bin/inspect-ranges"
CACHE="$SPIKE/tmp/cache"
BUILDS="$SPIKE/tmp/builds"
REG="ir-cat-publish-reg"
REG_URL="http://127.0.0.1:5064/catalog"
FLAGS=(--image-cache "$CACHE" --build-cache "$BUILDS" --cid-base 4070 --readiness-timeout 300)

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

cd "$ROOT"
$IR down --all >/dev/null 2>&1 || true
stop_registry
rm -rf "$SPIKE/tmp" && mkdir -p "$SPIKE/tmp"

echo "=== P1 build the factory and PUBLISH the attack image by name ==="
DB_OUT=$($IR daemon-bundle -o "$SPIKE/tmp/artifacts")
DAEMON_SHA=$(echo "$DB_OUT" | grep -o 'bundle sha256:[0-9a-f]*' | cut -d: -f2)
NOBLE_SHA=$(sha256sum "$NOBLE" | cut -d' ' -f1)
$IR images derive "$NOBLE" --sha256 "$NOBLE_SHA" --name noble-range-guest \
  --image-cache "$CACHE" --daemon-bundle "$SPIKE/tmp/artifacts" --daemon-sha256 "$DAEMON_SHA" >/dev/null
(cd "$RANGE" && "$IRBIN" build "${FLAGS[@]}" --recipe-budget 1800 >"$SPIKE/tmp/p1.txt" 2>&1) \
  && grep -q "build OK" "$SPIKE/tmp/p1.txt" && ok "P1 the factory builds green" || { bad "P1"; tail -10 "$SPIKE/tmp/p1.txt"; exit 1; }
docker run -d --rm --name "$REG" -p 127.0.0.1:5064:5000 registry:2 >/dev/null
sleep 2
(cd "$RANGE" && "$IRBIN" publish --guest box --as attack --to "$REG_URL" \
  --image-cache "$CACHE" --build-cache "$BUILDS" >"$SPIKE/tmp/p1pub.txt" 2>&1) \
  && grep -q "publish OK  attack@sha256:" "$SPIKE/tmp/p1pub.txt" \
  && ok "P1b publish promotes the realized image to the bare name" || { bad "P1b"; cat "$SPIKE/tmp/p1pub.txt"; }
(cd "$RANGE" && "$IRBIN" publish --golden noble-range-guest --to "$REG_URL" --image-cache "$CACHE" >"$SPIKE/tmp/p1g.txt" 2>&1) \
  && grep -q "publish OK  noble-range-guest@" "$SPIKE/tmp/p1g.txt" \
  && ok "P1c the golden promotes under its own name" || { bad "P1c"; cat "$SPIKE/tmp/p1g.txt"; }

echo "=== P2 a consumer pulls the bare name and BOOTS it as the attacker ==="
C="$SPIKE/tmp/consumer-images"; mkdir -p "$C"
$IR images pull attack --from "$REG_URL" --image-cache "$C" >"$SPIKE/tmp/p2.txt" 2>&1 \
  && [[ -f "$C/attack.qcow2" && -f "$C/attack.realized.json" && -f "$C/noble-range-guest.qcow2" ]] \
  && ok "P2 images pull lands attack.qcow2 with its chain and provenance" || { bad "P2"; cat "$SPIKE/tmp/p2.txt"; }
mkdir -p "$SPIKE/tmp/consumer-range"
cat > "$SPIKE/tmp/consumer-range/range.yaml" <<'SPEC'
range:
  name: catalog-consumer
  schema_version: "0.3"
  description: the bare catalog name as the attacker, by name
networks:
  - name: lab
    cidr: 10.99.0.0/24
    mode: isolated
hosts:
  - name: web
    os: { type: linux }
    image: noble-range-guest
    interfaces: [{ network: lab, ip: 10.99.0.10 }]
attacker:
  image: attack
  interfaces: [{ network: lab }]
  entry: external
SPEC
$IR render "$SPIKE/tmp/consumer-range" -o "$SPIKE/tmp/bundle" --image-cache "$C" --cid-base 4071 >/dev/null 2>&1 \
  && ok "P2b render resolves the bare name 'attack' from the pulled cache" || bad "P2b render"
$IR up "$SPIKE/tmp/bundle" --image-cache "$C" >"$SPIKE/tmp/p2up.txt" 2>&1 \
  && ok "P2c the catalog attack box boots as the attacker (chain verified at up)" || { bad "P2c"; tail -5 "$SPIKE/tmp/p2up.txt"; }
RC=$(docker ps --format '{{.Names}}' | grep -E '^ir-catalog-consumer-.*-range-1$' | head -1)
TOOL=$(cd "$ROOT" && uv run python design/spikes/_shared/chexec.py --boot "$SPIKE/tmp/bundle/boot.json" --project "${RC%-range-1}" --guest attacker --user root exec \
  'command -v msfconsole && head -1 /etc/attack-image.manifest' || true)
[[ "$TOOL" == */msfconsole* ]] && ok "P2d the pulled catalog image IS the attack image (msf present, manifest carried)" || bad "P2d (got: $TOOL)"
$IR down --all >/dev/null 2>&1 || true

echo "=== P3 the catalog artifact drives enumeration and the pin file guards the fleet ==="
$IR mirror --from "$REG_URL" --to "$SPIKE/tmp/archive" >"$SPIKE/tmp/p3.txt" 2>&1 \
  && grep -qE "mirror    2 artifacts:" "$SPIKE/tmp/p3.txt" \
  && ok "P3 whole-location mirror enumerates via the published catalog list (2 names)" || { bad "P3"; cat "$SPIKE/tmp/p3.txt"; }
$IR images pin --from "$REG_URL" --out "$SPIKE/tmp/pins.json" >"$SPIKE/tmp/p3pin.txt" 2>&1 \
  && grep -q "pinned 2 catalog name(s)" "$SPIKE/tmp/p3pin.txt" \
  && ok "P3b the fleet pin file records both names" || { bad "P3b"; cat "$SPIKE/tmp/p3pin.txt"; }
# the publisher moves the catalog past the pin: republishing the golden after a touch
printf 'moved' >> "$CACHE/noble-range-guest.qcow2"
python3 - "$CACHE" <<'PYEOF'
import hashlib, json, sys
from pathlib import Path
cache = Path(sys.argv[1])
meta = json.loads((cache / "noble-range-guest.json").read_text())
h = hashlib.sha256()
with open(cache / "noble-range-guest.qcow2", "rb") as f:
    for chunk in iter(lambda: f.read(1 << 20), b""):
        h.update(chunk)
meta["golden_sha256"] = h.hexdigest()
(cache / "noble-range-guest.json").write_text(json.dumps(meta))
PYEOF
(cd "$RANGE" && "$IRBIN" publish --golden noble-range-guest --to "$REG_URL" --image-cache "$CACHE" >/dev/null 2>&1)
F="$SPIKE/tmp/fleet-images"; mkdir -p "$F"
INSPECT_RANGES_PIN_FILE="$SPIKE/tmp/pins.json" $IR images pull noble-range-guest --from "$REG_URL" --image-cache "$F" >"$SPIKE/tmp/p3c.txt" 2>&1 \
  && ! cmp -s "$F/noble-range-guest.qcow2" "$CACHE/noble-range-guest.qcow2" \
  && ok "P3c the pinned fleet lands the PINNED root by digest, not the moved tag (@sha256 pin semantics)" \
  || { bad "P3c pinned pull"; cat "$SPIKE/tmp/p3c.txt"; }

stop_registry
echo
echo "$PASS passed, $FAIL failed"
exit $((FAIL > 0))

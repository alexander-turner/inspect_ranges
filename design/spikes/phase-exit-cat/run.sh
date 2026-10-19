#!/bin/bash
# standard-images-v1 phase exit battery: publish day rehearsed end-to-end. The
# publisher half runs the runbook's commands verbatim against a local
# registry:2 standing in for the public org (goldens noble+focal, the daemon
# bundle, the attack image, the range container image, the fleet pin file);
# the consumer half is the exit transcript: fresh empty caches, a range whose
# attacker is the DEFAULT (no image declared), a real `inspect eval` whose
# init pulls everything implicitly, the booted attacker provably the attack
# image, and a warm second eval. `./run.sh public <range-image-pin>` reruns
# the consumer half against docker.io/meridianlabsai/inspect-ranges after the real publish
# day. Usage: ./run.sh [down|public <pin>]. CID band 4090; registry port 5066.
set -euo pipefail
cd "$(dirname "$0")"
SPIKE="$PWD"
ROOT="$(cd ../../.. && pwd)"
ATTACK_RANGE="$ROOT/catalog/attack"

NOBLE="${NOBLE:-$HOME/.cache/inspect-ranges/images/noble-server-cloudimg-amd64.img}"
FOCAL="${FOCAL:-$HOME/.cache/inspect-ranges/images/focal-server-cloudimg-amd64.img}"
export XDG_STATE_HOME="$SPIKE/tmp/state"
IR="uv run inspect-ranges"
IRBIN="$ROOT/.venv/bin/inspect-ranges"
CACHE="$SPIKE/tmp/publisher-images"
BUILDS="$SPIKE/tmp/publisher-builds"
REG="ir-phase-exit-cat-reg"
REG_URL="http://127.0.0.1:5066/catalog"
RIMAGE_REPO="127.0.0.1:5066/inspect-ranges-range"
FLAGS=(--image-cache "$CACHE" --build-cache "$BUILDS" --cid-base 4090 --readiness-timeout 300)

stop_registry() { docker rm -f "$REG" >/dev/null 2>&1 || true; }
if [[ "${1:-}" == "down" ]]; then
  stop_registry
  (cd "$ROOT" && $IR down --all) || true
  exit 0
fi

MODE="rehearsal"
if [[ "${1:-}" == "public" ]]; then
  MODE="public"
  PUBLIC_PIN="${2:?usage: ./run.sh public <range-image pin, repo@sha256:...>}"
fi

grep -q vhost_vsock /proc/modules || { echo "need: sudo modprobe vhost_vsock"; exit 1; }

PASS=0; FAIL=0
ok()  { echo "PASS  $1"; PASS=$((PASS+1)); }
bad() { echo "FAIL  $1"; FAIL=$((FAIL+1)); }

exec 9>/tmp/inspect-ranges-battery.lock
flock 9
cd "$ROOT"
$IR down --all >/dev/null 2>&1 || true
rm -rf "$SPIKE/tmp" && mkdir -p "$SPIKE/tmp"

if [[ "$MODE" == "rehearsal" ]]; then
  [[ -f "$NOBLE" && -f "$FOCAL" ]] || { echo "missing vendor images"; exit 1; }
  docker image inspect registry:2 >/dev/null 2>&1 || { echo "need the registry:2 image"; exit 1; }
  stop_registry
  trap stop_registry EXIT

  echo "=== X1 the publisher half: the runbook's commands, verbatim ==="
  DB_OUT=$($IR daemon-bundle -o "$SPIKE/tmp/artifacts")
  DAEMON_SHA=$(echo "$DB_OUT" | grep -o 'bundle sha256:[0-9a-f]*' | cut -d: -f2)
  $IR images derive "$NOBLE" --sha256 "$(sha256sum "$NOBLE" | cut -d' ' -f1)" --name ubuntu-noble \
    --image-cache "$CACHE" --daemon-bundle "$SPIKE/tmp/artifacts" --daemon-sha256 "$DAEMON_SHA" >/dev/null
  $IR images derive "$FOCAL" --sha256 "$(sha256sum "$FOCAL" | cut -d' ' -f1)" --name ubuntu-focal \
    --image-cache "$CACHE" --daemon-bundle "$SPIKE/tmp/artifacts" --daemon-sha256 "$DAEMON_SHA" >/dev/null
  (cd "$ATTACK_RANGE" && "$IRBIN" build "${FLAGS[@]}" --recipe-budget 1800 >"$SPIKE/tmp/x1build.txt" 2>&1) \
    && grep -q "build OK" "$SPIKE/tmp/x1build.txt" && ok "X1 the attack factory builds green" \
    || { bad "X1 build"; tail -10 "$SPIKE/tmp/x1build.txt"; exit 1; }
  docker run -d --rm --name "$REG" -p 127.0.0.1:5066:5000 registry:2 >/dev/null
  for _ in $(seq 1 40); do curl -fs http://127.0.0.1:5066/v2/ >/dev/null && break; sleep 0.5; done

  $IR publish --golden ubuntu-noble --to "$REG_URL" --image-cache "$CACHE" >/dev/null 2>&1 \
    && $IR publish --golden ubuntu-focal --to "$REG_URL" --image-cache "$CACHE" >/dev/null 2>&1 \
    && ok "X1b both goldens publish under their names" || bad "X1b golden publish"
  $IR publish --daemon "$SPIKE/tmp/artifacts" --to "$REG_URL" >/dev/null 2>&1 \
    && ok "X1c the daemon bundle publishes" || bad "X1c daemon publish"
  (cd "$ATTACK_RANGE" && "$IRBIN" publish --guest box --as attack --to "$REG_URL" \
    --image-cache "$CACHE" --build-cache "$BUILDS" >"$SPIKE/tmp/x1pub.txt" 2>&1) \
    && grep -q "publish OK  attack@sha256:" "$SPIKE/tmp/x1pub.txt" \
    && ok "X1d the attack image promotes to the bare name" || { bad "X1d"; cat "$SPIKE/tmp/x1pub.txt"; }

  LOCAL_TAG=$(uv run python -c "from inspect_ranges._runtime.rangeimage import ensure_range_image; print(ensure_range_image())")
  docker tag "$LOCAL_TAG" "$RIMAGE_REPO:publish" >/dev/null
  DIGEST=$(docker push "$RIMAGE_REPO:publish" 2>/dev/null | grep -o 'sha256:[0-9a-f]*' | tail -1)
  PIN="$RIMAGE_REPO@$DIGEST"
  docker rmi "$RIMAGE_REPO:publish" "$PIN" >/dev/null 2>&1 || true
  [[ -n "$DIGEST" ]] && ok "X1e the range container image pushes ($PIN)" || { bad "X1e range image push"; exit 1; }
  $IR images pin --from "$REG_URL" --out "$SPIKE/tmp/pins.json" >"$SPIKE/tmp/x1pin.txt" 2>&1 \
    && grep -q "pinned 3 catalog name(s)" "$SPIKE/tmp/x1pin.txt" \
    && ok "X1f the fleet pin file records all three catalog names" || { bad "X1f"; cat "$SPIKE/tmp/x1pin.txt"; }
  CONSUMER_REGISTRY="$REG_URL"
else
  echo "=== public mode: the exit transcript against the published org ==="
  CONSUMER_REGISTRY="docker.io/meridianlabsai/inspect-ranges"
  PIN="$PUBLIC_PIN"
fi

echo "=== X2 the exit transcript: a clean consumer, one eval, everything pulls ==="
mkdir -p "$SPIKE/tmp/exit-range"
cat > "$SPIKE/tmp/exit-range/range.yaml" <<'SPEC'
range:
  name: catalog-exit
  schema_version: "0.3"
  description: the exit transcript range; the attacker is the DEFAULT (no image declared)
networks:
  - name: lab
    cidr: 10.97.0.0/24
    mode: isolated
hosts:
  - name: web
    os: { type: linux }
    image: ubuntu-noble
    interfaces: [{ network: lab, ip: 10.97.0.10 }]
attacker:
  interfaces: [{ network: lab }]
  entry: external
SPEC
CONSUMER="$SPIKE/tmp/consumer-images"
export INSPECT_RANGES_IMAGE_CACHE="$CONSUMER"
export INSPECT_RANGES_BUILD_CACHE="$SPIKE/tmp/consumer-builds"
export INSPECT_RANGES_REGISTRY="$CONSUMER_REGISTRY"
export INSPECT_RANGES_RANGE_IMAGE="$PIN"
docker image inspect "$PIN" >/dev/null 2>&1 && { echo "pin already local, cannot prove the pull"; exit 1; }
if (cd "$ROOT" && uv run python "$SPIKE/exit_eval.py" "$SPIKE/tmp/exit-range" >"$SPIKE/tmp/x2.txt" 2>&1); then
  cat "$SPIKE/tmp/x2.txt" | grep -E "^(PASS|FAIL)" || true
  ok "X2 the cold eval ran green (every artifact pulled at init)"
else
  bad "X2 cold eval"; tail -30 "$SPIKE/tmp/x2.txt"
fi
[[ -f "$CONSUMER/attack.qcow2" && -f "$CONSUMER/ubuntu-noble.qcow2" && -f "$CONSUMER/attack.realized.json" ]] \
  && ok "X2b the implicit pull landed the attack chain with provenance" || bad "X2b (cache: $(ls "$CONSUMER" 2>/dev/null | tr '\n' ' '))"
docker image inspect "$PIN" >/dev/null 2>&1 \
  && ok "X2c the pinned range container image was pulled" || bad "X2c"

echo "=== X3 warm: the second eval touches no network ==="
if [[ "$MODE" == "rehearsal" ]]; then stop_registry; fi
if (cd "$ROOT" && uv run python "$SPIKE/exit_eval.py" "$SPIKE/tmp/exit-range" >"$SPIKE/tmp/x3.txt" 2>&1); then
  ok "X3 the warm eval ran green with the registry GONE (zero network by proof)"
else
  bad "X3 warm eval"; tail -20 "$SPIKE/tmp/x3.txt"
fi

$IR down --all >/dev/null 2>&1 || true
echo
echo "$PASS passed, $FAIL failed"
exit $((FAIL > 0))

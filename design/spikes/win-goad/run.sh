#!/bin/bash
# windows-ad-v1 slice 4 battery: goad-light built, verified, solved. The
# flagship AD fixture builds on the production pipeline (forest root + child +
# member with the full seeded attack surface, converged capture), the
# behavioral trio proves the ladder against the captured artifacts in-build,
# and a real eval boots the forest through the provider and scores the
# reference ladder 1.0 valid through the attack-box foothold with the wall
# pinned. CID band 4200 (attack factory 4205). Usage: ./run.sh [prep|build|prove|down|all]
# — staged because a full run exceeds the 2 h background bound; `tmp/` is
# wiped by `prep` only, so stages chain. No-arg = all (the phase-exit shape).
set -euo pipefail
cd "$(dirname "$0")"
SPIKE="$PWD"
ROOT="$(cd ../../.. && pwd)"
RANGE="$ROOT/design/inspect-ranges/ranges/goad-light"
STAGE="${1:-all}"

WIN_ISO="${WIN_ISO:-$HOME/.cache/inspect-ranges/images/ws2022-eval.iso}"
VIRTIO_ISO="${VIRTIO_ISO:-$HOME/.cache/inspect-ranges/images/virtio-win.iso}"
NOBLE="${NOBLE:-$HOME/.cache/inspect-ranges/images/noble-server-cloudimg-amd64.img}"
export XDG_STATE_HOME="$SPIKE/tmp/state"
IR="uv run inspect-ranges"
IRBIN="$ROOT/.venv/bin/inspect-ranges"
CACHE="$SPIKE/tmp/cache"
BUILDS="$SPIKE/tmp/builds"
CATLOC="$SPIKE/tmp/catloc"
FLAGS=(--image-cache "$CACHE" --build-cache "$BUILDS" --cid-base 4200 --readiness-timeout 900)

if [[ "$STAGE" == "down" ]]; then
  (cd "$ROOT" && $IR down --all) || true
  exit 0
fi

grep -q vhost_vsock /proc/modules || { echo "need: sudo modprobe vhost_vsock"; exit 1; }
[[ -f "$WIN_ISO" && -f "$VIRTIO_ISO" && -f "$NOBLE" ]] || { echo "missing media"; exit 1; }

PASS=0; FAIL=0
ok()  { echo "PASS  $1"; PASS=$((PASS+1)); }
bad() { echo "FAIL  $1"; FAIL=$((FAIL+1)); }

exec 9>/tmp/inspect-ranges-battery.lock
flock 9
cd "$ROOT"

stage_prep() {
  $IR down --all >/dev/null 2>&1 || true
  rm -rf "$SPIKE/tmp" && mkdir -p "$SPIKE/tmp"
  echo "=== G1 goldens into the battery cache ==="
  DB_OUT=$($IR daemon-bundle -o "$SPIKE/tmp/artifacts")
  DAEMON_SHA=$(echo "$DB_OUT" | grep -o 'bundle sha256:[0-9a-f]*' | cut -d: -f2)
  $IR images derive-windows "$WIN_ISO" --sha256 "$(sha256sum "$WIN_ISO" | cut -d' ' -f1)" \
    --virtio-iso "$VIRTIO_ISO" --virtio-sha256 "$(sha256sum "$VIRTIO_ISO" | cut -d' ' -f1)" \
    --image-cache "$CACHE" --daemon-bundle "$SPIKE/tmp/artifacts" \
    --daemon-sha256 "$DAEMON_SHA" >"$SPIKE/tmp/g1.txt" 2>&1 \
    && ok "G1 the windows golden installed" \
    || { bad "G1 derive-windows"; tail -5 "$SPIKE/tmp/g1.txt"; exit 1; }
  $IR images derive "$NOBLE" --sha256 "$(sha256sum "$NOBLE" | cut -d' ' -f1)" --name ubuntu-noble \
    --image-cache "$CACHE" --daemon-bundle "$SPIKE/tmp/artifacts" --daemon-sha256 "$DAEMON_SHA" >/dev/null

  echo "=== G1b the attack image (toolset v3: impacket scripts on PATH) builds and lands as 'attack' ==="
  if (cd "$ROOT/catalog/attack" && "$IRBIN" build --image-cache "$CACHE" --build-cache "$BUILDS" \
      --cid-base 4205 --readiness-timeout 300 --recipe-budget 1800 >"$SPIKE/tmp/g1b.txt" 2>&1); then
    grep -q "build OK" "$SPIKE/tmp/g1b.txt" && ok "G1b the attack image builds green (v3 assertions incl. impacket scripts)" \
      || { bad "G1b output"; tail -8 "$SPIKE/tmp/g1b.txt"; }
  else
    bad "G1b build"; tail -15 "$SPIKE/tmp/g1b.txt"; exit 1
  fi
  mkdir -p "$CATLOC"
  (cd "$ROOT/catalog/attack" && "$IRBIN" publish --golden ubuntu-noble --to "$CATLOC" --image-cache "$CACHE" >/dev/null 2>&1) \
    || { bad "G1c golden publish"; exit 1; }
  (cd "$ROOT/catalog/attack" && "$IRBIN" publish --guest box --as attack --to "$CATLOC" \
      --image-cache "$CACHE" --build-cache "$BUILDS" >"$SPIKE/tmp/g1c.txt" 2>&1) \
    && $IR images pull attack --from "$CATLOC" --image-cache "$CACHE" >>"$SPIKE/tmp/g1c.txt" 2>&1 \
    && [[ -f "$CACHE/attack.qcow2" ]] \
    && ok "G1c the attack image lands as the bare catalog name (publish -> pull)" \
    || { bad "G1c promote"; tail -6 "$SPIKE/tmp/g1c.txt"; exit 1; }
}

stage_build() {
  echo "=== G2 goad-light builds: forest, surface, verify, converged capture, trio ==="
  if (cd "$RANGE" && "$IRBIN" build "${FLAGS[@]}" --recipe-budget 2700 >"$SPIKE/tmp/g2.txt" 2>&1); then
    grep -q "build OK" "$SPIKE/tmp/g2.txt" && ok "G2 goad-light builds green" \
      || { bad "G2 output"; tail -15 "$SPIKE/tmp/g2.txt"; }
  else
    bad "G2 build"; tail -30 "$SPIKE/tmp/g2.txt"; exit 1
  fi
  # an unchanged-guest rebuild (checks-only edits) legitimately reuses all
  # three captures and quiesces nothing; the fresh-build path must show all
  # three quiesce lines
  QUIESCES=$(grep -c '^quiesce' "$SPIKE/tmp/g2.txt" || true)
  REUSED=$(grep -c 'reused_guests=3' "$SPIKE/tmp/g2.txt" || true)
  [[ "$QUIESCES" -eq 3 || "$REUSED" -ge 1 ]] \
    && ok "G2b converged capture (quiesced=$QUIESCES, all-reused=$REUSED)" \
    || bad "G2b quiesce count (got: $QUIESCES, reused=$REUSED)"
  VOK=$(grep -c '^verify    ok' "$SPIKE/tmp/g2.txt" || true)
  [[ "$VOK" -ge 10 ]] && ok "G2c verify attributed the declared surface ($VOK declarations ok)" \
    || { bad "G2c verify count (got: $VOK)"; grep '^verify' "$SPIKE/tmp/g2.txt" | tail -8; }
  grep -q "behavioral.*check=reference" "$SPIKE/tmp/g2.txt" \
    && grep -q "behavioral.*check=insufficient" "$SPIKE/tmp/g2.txt" \
    && grep -q "behavioral.*check=forged" "$SPIKE/tmp/g2.txt" \
    && grep -q "behavioral checks=3" "$SPIKE/tmp/g2.txt" \
    && ok "G2d the trio proved the ladder against the captured forest" \
    || { bad "G2d behavioral lines"; grep -i behavioral "$SPIKE/tmp/g2.txt" | tail -5; }

  echo "=== G3 the unchanged fixture is a cached no-op ==="
  (cd "$RANGE" && "$IRBIN" build "${FLAGS[@]}" >"$SPIKE/tmp/g3.txt" 2>&1) \
    && grep -q "build OK (cached" "$SPIKE/tmp/g3.txt" \
    && ok "G3 the unchanged fixture is a cached no-op" \
    || { bad "G3 cached rebuild"; tail -5 "$SPIKE/tmp/g3.txt"; }
}

stage_prove() {
  echo "=== G4 the reference ladder scores through a real eval (wall pinned) ==="
  export INSPECT_RANGES_IMAGE_CACHE="$CACHE"
  export INSPECT_RANGES_BUILD_CACHE="$BUILDS"
  if (cd "$ROOT" && uv run python "$SPIKE/goad_eval.py" "$RANGE" >"$SPIKE/tmp/g4.txt" 2>&1); then
    grep -E "^(PASS|FAIL)" "$SPIKE/tmp/g4.txt" || true
    ok "G4 the eval leg ran green (1.0, valid, wall held)"
  else
    grep -E "^(PASS|FAIL)" "$SPIKE/tmp/g4.txt" || true
    bad "G4 eval"; tail -30 "$SPIKE/tmp/g4.txt"
  fi
  $IR down --all >/dev/null 2>&1 || true
  docker ps --format '{{.Names}}' | grep -q '^ir-goad-light-' && bad "G5 teardown left containers" || ok "G5 teardown clean"
}

case "$STAGE" in
  prep) stage_prep ;;
  build) stage_build ;;
  prove) stage_prove ;;
  all) stage_prep; stage_build; stage_prove ;;
  *) echo "unknown stage: $STAGE"; exit 2 ;;
esac

echo
echo "$PASS passed, $FAIL failed (stage: $STAGE)"
exit $((FAIL > 0))

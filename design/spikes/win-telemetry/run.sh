#!/bin/bash
# windows-ad-v1 slice 5 battery: the defense-telemetry tier. The
# splunk-detection pair (Splunk Enterprise on noble + the instrumented
# Server 2022 endpoint) builds on the production pipeline — the FIRST
# detection-bearing build: the trio plants through the Windows oracle, the
# behavioral runner drives the collectors.yaml export, and BOTH trios prove:
# detection (reference fires T1003.001 and scores 1.0 from the stream,
# insufficient flows without the signal, forged proves the collector binding)
# and evade (reference raw-reads lsass from one minimal-mask open, 1.0 quiet,
# insufficient trips the declared alert, forged forges the exporter gap
# marker and the on_sensor_tamper=fail rule zeroes it) — then two real eval
# legs boot the captured pair through the provider with the same collectors
# file: the detection leg scores 1.0/valid, and the gap-marker leg forces a
# read-bound exporter overflow and proves it surfaces as an incomplete window.
# Mixed-OS converged capture (one Linux + one Windows content host,
# quiesced=2). Usage: ./run.sh [prep|build|prove|down|all]; staged under the
# 2 h background bound, tmp/ wiped by prep only. CID band 4210 (attack factory
# 4212, consumer eval renders inside the provider).
set -euo pipefail
cd "$(dirname "$0")"
SPIKE="$PWD"
ROOT="$(cd ../../.. && pwd)"
RANGE="$ROOT/src/inspect_ranges/examples/_splunk_detection"
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
FLAGS=(--image-cache "$CACHE" --build-cache "$BUILDS" --cid-base 4210 --readiness-timeout 900)

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
  echo "=== T1 goldens into the battery cache ==="
  DB_OUT=$($IR daemon-bundle -o "$SPIKE/tmp/artifacts")
  DAEMON_SHA=$(echo "$DB_OUT" | grep -o 'bundle sha256:[0-9a-f]*' | cut -d: -f2)
  $IR images derive-windows "$WIN_ISO" --sha256 "$(sha256sum "$WIN_ISO" | cut -d' ' -f1)" \
    --virtio-iso "$VIRTIO_ISO" --virtio-sha256 "$(sha256sum "$VIRTIO_ISO" | cut -d' ' -f1)" \
    --image-cache "$CACHE" --daemon-bundle "$SPIKE/tmp/artifacts" \
    --daemon-sha256 "$DAEMON_SHA" >"$SPIKE/tmp/t1.txt" 2>&1 \
    && ok "T1 the windows golden installed" \
    || { bad "T1 derive-windows"; tail -5 "$SPIKE/tmp/t1.txt"; exit 1; }
  $IR images derive "$NOBLE" --sha256 "$(sha256sum "$NOBLE" | cut -d' ' -f1)" --name ubuntu-noble \
    --image-cache "$CACHE" --daemon-bundle "$SPIKE/tmp/artifacts" --daemon-sha256 "$DAEMON_SHA" >/dev/null
  echo "=== T1b the attack image builds and lands as 'attack' ==="
  if (cd "$ROOT/catalog/attack" && "$IRBIN" build --image-cache "$CACHE" --build-cache "$BUILDS" \
      --cid-base 4215 --readiness-timeout 300 --recipe-budget 1800 >"$SPIKE/tmp/t1b.txt" 2>&1); then
    grep -q "build OK" "$SPIKE/tmp/t1b.txt" && ok "T1b the attack image builds green" \
      || { bad "T1b output"; tail -8 "$SPIKE/tmp/t1b.txt"; }
  else
    bad "T1b build"; tail -15 "$SPIKE/tmp/t1b.txt"; exit 1
  fi
  mkdir -p "$CATLOC"
  (cd "$ROOT/catalog/attack" && "$IRBIN" publish --golden ubuntu-noble --to "$CATLOC" --image-cache "$CACHE" >/dev/null 2>&1) \
    || { bad "T1c golden publish"; exit 1; }
  (cd "$ROOT/catalog/attack" && "$IRBIN" publish --guest box --as attack --to "$CATLOC" \
      --image-cache "$CACHE" --build-cache "$BUILDS" >"$SPIKE/tmp/t1c.txt" 2>&1) \
    && $IR images pull attack --from "$CATLOC" --image-cache "$CACHE" >>"$SPIKE/tmp/t1c.txt" 2>&1 \
    && [[ -f "$CACHE/attack.qcow2" ]] \
    && ok "T1c the attack image lands as the bare catalog name" \
    || { bad "T1c promote"; tail -6 "$SPIKE/tmp/t1c.txt"; exit 1; }
}

stage_build() {
  echo "=== T2 the pair builds: splunk, endpoint, verify, mixed-OS converged capture, both trios ==="
  if (cd "$RANGE" && "$IRBIN" build "${FLAGS[@]}" --recipe-budget 2700 >"$SPIKE/tmp/t2.txt" 2>&1); then
    grep -q "build OK" "$SPIKE/tmp/t2.txt" && ok "T2 splunk-detection builds green" \
      || { bad "T2 output"; tail -15 "$SPIKE/tmp/t2.txt"; }
  else
    bad "T2 build"; tail -30 "$SPIKE/tmp/t2.txt"; exit 1
  fi
  QUIESCES=$(grep -c '^quiesce' "$SPIKE/tmp/t2.txt" || true)
  REUSED=$(grep -c 'reused_guests=2' "$SPIKE/tmp/t2.txt" || true)
  [[ "$QUIESCES" -eq 2 || "$REUSED" -ge 1 ]] \
    && ok "T2b mixed-OS converged capture (quiesced=$QUIESCES, all-reused=$REUSED; the Linux guest rode the quiesce path)" \
    || bad "T2b quiesce count (got: $QUIESCES, reused=$REUSED)"
  VOK=$(grep -c '^verify    ok' "$SPIKE/tmp/t2.txt" || true)
  [[ "$VOK" -eq 5 ]] && ok "T2c verify attributed the declared surface ($VOK declarations ok: splunk-enterprise 10.2.2 via dpkg, splunk-forwarding, splunk-rest, rdp, smb)" \
    || { bad "T2c verify count (got: $VOK)"; grep '^verify' "$SPIKE/tmp/t2.txt" | tail -8; }
  grep -q "behavioral.*challenge=execute-and-confirm-t1003-001.*check=forged" "$SPIKE/tmp/t2.txt" \
    && grep -q "behavioral.*challenge=evade-detection-t1003-001.*check=forged" "$SPIKE/tmp/t2.txt" \
    && [[ "$(grep -c "behavioral.*check=reference" "$SPIKE/tmp/t2.txt")" -eq 2 ]] \
    && [[ "$(grep -c "behavioral.*check=insufficient" "$SPIKE/tmp/t2.txt")" -eq 2 ]] \
    && [[ "$(grep -c "behavioral.*check=forged" "$SPIKE/tmp/t2.txt")" -eq 2 ]] \
    && grep -q "behavioral checks=6" "$SPIKE/tmp/t2.txt" \
    && ok "T2d both trios proved against the exported stream (detection + evade)" \
    || { bad "T2d behavioral lines"; grep -i behavioral "$SPIKE/tmp/t2.txt" | tail -8; }

  echo "=== T3 the unchanged fixture is a cached no-op ==="
  (cd "$RANGE" && "$IRBIN" build "${FLAGS[@]}" >"$SPIKE/tmp/t3.txt" 2>&1) \
    && grep -q "build OK (cached" "$SPIKE/tmp/t3.txt" \
    && ok "T3 the unchanged fixture is a cached no-op" \
    || { bad "T3 cached rebuild"; tail -5 "$SPIKE/tmp/t3.txt"; }
}

stage_prove() {
  echo "=== T4 the eval legs: detection scores 1.0; a forced exporter overflow reads incomplete ==="
  export INSPECT_RANGES_IMAGE_CACHE="$CACHE"
  export INSPECT_RANGES_BUILD_CACHE="$BUILDS"
  if (cd "$ROOT" && uv run python "$SPIKE/arw_eval.py" "$RANGE" >"$SPIKE/tmp/t4.txt" 2>&1); then
    grep -E "^(PASS|FAIL)" "$SPIKE/tmp/t4.txt" || true
    ok "T4 the eval legs ran green (detection 1.0/valid, wall held; gap marker -> window incomplete)"
  else
    grep -E "^(PASS|FAIL)" "$SPIKE/tmp/t4.txt" || true
    bad "T4 eval"; tail -30 "$SPIKE/tmp/t4.txt"
  fi
  $IR down --all >/dev/null 2>&1 || true
  docker ps --format '{{.Names}}' | grep -q '^ir-splunk-detection-' && bad "T5 teardown left containers" || ok "T5 teardown clean"
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

#!/bin/bash
# evidence-capture spike: per-bridge packet capture inside the hardened range
# container. Stages: boot a static-IP two-segment range (exactly the
# eight-capability floor), observe the capture failure under that floor in the
# real range container, prove NET_RAW is the minimal fix (identical-netns
# sidecars differing only in caps), verify per-segment capture semantics
# against known cross-segment and same-segment flows, measure the capture
# process's CPU/RSS idle and under a generated flood, and measure tcpdump
# size-rotation and kernel-drop behavior under the flood. Usage: ./run.sh
# [down]. Logs and artifacts under tmp/ (gitignored). CID band 30000+;
# exclusive via the shared battery lock.
set -uo pipefail
cd "$(dirname "$0")"
SPIKE="$PWD"
ROOT="$(cd ../../.. && pwd)"

VENDOR="${VENDOR:-$HOME/.cache/inspect-ranges/images/noble-server-cloudimg-amd64.img}"
export XDG_STATE_HOME="$SPIKE/tmp/state"
export INSPECT_RANGES_IMAGE_CACHE="$SPIKE/tmp/cache"
IR="uv run inspect-ranges"
PY="uv run python"
CHEXEC="design/spikes/_shared/chexec.py"

FLOOR_CAPS=(NET_ADMIN CHOWN DAC_OVERRIDE FOWNER SETUID SETGID SETPCAP KILL)

if [[ "${1:-}" == "down" ]]; then
  docker rm -f evcap-res evcap-rot1 evcap-rot2 evcap-dmz evcap-int >/dev/null 2>&1
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
docker rm -f evcap-res evcap-rot1 evcap-rot2 evcap-dmz evcap-int >/dev/null 2>&1
rm -rf "$SPIKE/tmp" && mkdir -p "$SPIKE/tmp/cache" "$SPIKE/tmp/logs" "$SPIKE/tmp/cap/rot1" "$SPIKE/tmp/cap/rot2" "$SPIKE/tmp/tools/lib"
# a NET_RAW-only sidecar's root lacks DAC_OVERRIDE: the capture volume must be
# writable by its uid outright (production: sidecar-owned volume; spike: 777)
chmod 777 "$SPIKE/tmp/cap" "$SPIKE/tmp/cap/rot1" "$SPIKE/tmp/cap/rot2"

echo "=== setup: doctor, sidecar base image, golden ==="
$IR doctor >"$SPIKE/tmp/logs/doctor.txt" 2>&1 \
  && ok "doctor" || { bad "doctor"; tail -20 "$SPIKE/tmp/logs/doctor.txt"; exit 1; }
docker pull -q ubuntu:24.04 >/dev/null 2>&1 || true
docker image inspect ubuntu:24.04 >/dev/null 2>&1 \
  && ok "sidecar base image present" || { bad "sidecar base image"; exit 1; }

DB_OUT=$($IR daemon-bundle -o "$SPIKE/tmp/artifacts")
DAEMON_SHA=$(echo "$DB_OUT" | grep -o 'bundle sha256:[0-9a-f]*' | cut -d: -f2)
VENDOR_SHA=$(sha256sum "$VENDOR" | cut -d' ' -f1)
$IR images derive "$VENDOR" --sha256 "$VENDOR_SHA" --name evcap-guest \
  --image-cache "$INSPECT_RANGES_IMAGE_CACHE" --daemon-bundle "$SPIKE/tmp/artifacts" \
  --daemon-sha256 "$DAEMON_SHA" >"$SPIKE/tmp/logs/derive.txt" 2>&1 \
  && ok "golden derived" || { bad "golden derived"; tail -5 "$SPIKE/tmp/logs/derive.txt"; exit 1; }

echo "=== render: assert the eight-capability floor ==="
$IR render "$SPIKE/spec.yaml" -o "$SPIKE/tmp/bundle" --cid-base 30000 \
  --image-cache "$INSPECT_RANGES_IMAGE_CACHE" >"$SPIKE/tmp/logs/render.txt" 2>&1 \
  && ok "rendered (cid base 30000)" || { bad "render"; cat "$SPIKE/tmp/logs/render.txt"; exit 1; }
CAPLINE=$(grep cap_add "$SPIKE/tmp/bundle/compose.yaml")
echo "cap_add: $CAPLINE" | tee "$SPIKE/tmp/logs/caps.txt"
if echo "$CAPLINE" | grep -q NET_RAW; then
  bad "floor assert: NET_RAW unexpectedly present (spec must stay DHCP-free)"
else
  ok "floor assert: compose grants the eight only (no NET_RAW)"
fi

echo "=== up ==="
$IR up "$SPIKE/tmp/bundle" --image-cache "$INSPECT_RANGES_IMAGE_CACHE" \
  >"$SPIKE/tmp/logs/up.txt" 2>&1 \
  && ok "range up" || { bad "range up"; tail -20 "$SPIKE/tmp/logs/up.txt"; exit 1; }
PROJ=$(sed -n 's/^ready: project \([^ ]*\).*/\1/p' "$SPIKE/tmp/logs/up.txt")
CTR="${PROJ}-range-1"
BR_DMZ=$(sed -n 1p "$SPIKE/tmp/bundle/netns/bridges.txt")
BR_INT=$(sed -n 2p "$SPIKE/tmp/bundle/netns/bridges.txt")
echo "project=$PROJ container=$CTR bridges: dmz=$BR_DMZ internal=$BR_INT"
for g in attacker web db router; do
  $PY "$CHEXEC" --boot "$SPIKE/tmp/bundle/boot.json" --guest "$g" wait 120 \
    >/dev/null 2>&1 && ok "daemon ready: $g" || bad "daemon ready: $g"
done

echo "=== tools: host tcpdump + libs (same distro as the range image) ==="
cp /usr/bin/tcpdump "$SPIKE/tmp/tools/"
for lib in $(ldd /usr/bin/tcpdump | awk '/=>/ {print $3}'); do
  cp "$lib" "$SPIKE/tmp/tools/lib/"
done
ok "tools staged: tcpdump + $(ls "$SPIKE/tmp/tools/lib" | wc -l) libs"

burst() {  # background a short ping burst so -c 1 captures have traffic to see
  $PY "$CHEXEC" --boot "$SPIKE/tmp/bundle/boot.json" --guest web exec \
    'ping -c 8 -i 0.5 10.94.10.3' >/dev/null 2>&1 &
}

echo "=== test A: capture inside the real range container, current floor ==="
docker cp "$SPIKE/tmp/tools" "$CTR":/tools >/dev/null
burst
if docker exec -e LD_LIBRARY_PATH=/tools/lib "$CTR" \
     timeout 8 /tools/tcpdump -Z root -i "$BR_DMZ" -c 1 -w /dev/null \
     >"$SPIKE/tmp/logs/floor-fail.txt" 2>&1; then
  bad "floor: capture unexpectedly SUCCEEDED under the eight caps"
else
  ok "floor: capture refused under the eight caps (observed failure below)"
fi
cat "$SPIKE/tmp/logs/floor-fail.txt"
wait

CAPS8_ARGS=(); for c in "${FLOOR_CAPS[@]}"; do CAPS8_ARGS+=(--cap-add "$c"); done
side() {  # side NAME [docker-run args...] -- tcpdump args...
  local name="$1"; shift
  local run_args=() ; while [[ "$1" != "--" ]]; do run_args+=("$1"); shift; done; shift
  docker run --name "$name" --network "container:$CTR" --cap-drop ALL \
    -v "$SPIKE/tmp/tools:/tools:ro" -v "$SPIKE/tmp/cap:/cap" \
    -e LD_LIBRARY_PATH=/tools/lib "${run_args[@]}" \
    ubuntu:24.04 /tools/tcpdump -Z root "$@"
}

echo "=== test A': sidecar, identical netns, exactly the eight caps ==="
burst
if side evcap-a8 --rm "${CAPS8_ARGS[@]}" -- -i "$BR_DMZ" -c 1 -w /dev/null \
     >"$SPIKE/tmp/logs/side-caps8.txt" 2>&1; then
  bad "sidecar eight-caps: unexpectedly succeeded"
else
  ok "sidecar eight-caps: refused (matches in-container floor)"
fi
wait

echo "=== test B: sidecar, eight caps + NET_RAW ==="
burst
if side evcap-b --rm "${CAPS8_ARGS[@]}" --cap-add NET_RAW -- \
     -i "$BR_DMZ" -c 1 -w /dev/null >"$SPIKE/tmp/logs/side-caps9.txt" 2>&1; then
  ok "eight + NET_RAW: capture works (minimal grant confirmed)"
else
  bad "eight + NET_RAW: still refused"; cat "$SPIKE/tmp/logs/side-caps9.txt"
fi
wait

echo "=== test C: sidecar, NET_RAW ONLY (scoped-sidecar alternative) ==="
burst
if side evcap-c --rm --cap-add NET_RAW -- \
     -i "$BR_DMZ" -c 1 -w /dev/null >"$SPIKE/tmp/logs/side-raw-only.txt" 2>&1; then
  ok "NET_RAW-only sidecar: capture works (scoped alternative viable)"
else
  bad "NET_RAW-only sidecar: refused"; cat "$SPIKE/tmp/logs/side-raw-only.txt"
fi
wait

echo "=== per-segment correctness: cross-segment on both, same-segment on one ==="
side evcap-dmz -d --cap-add NET_RAW -- -i "$BR_DMZ" -w /cap/dmz.pcap >/dev/null 2>&1
side evcap-int -d --cap-add NET_RAW -- -i "$BR_INT" -w /cap/int.pcap >/dev/null 2>&1
sleep 2
$PY "$CHEXEC" --boot "$SPIKE/tmp/bundle/boot.json" --guest attacker exec \
  'ping -c 3 -i 0.3 10.94.20.10' >"$SPIKE/tmp/logs/ping-cross.txt" 2>&1 \
  && ok "cross-segment ping attacker->db" || bad "cross-segment ping"
$PY "$CHEXEC" --boot "$SPIKE/tmp/bundle/boot.json" --guest web exec \
  'ping -c 3 -i 0.3 10.94.10.3' >"$SPIKE/tmp/logs/ping-same.txt" 2>&1 \
  && ok "same-segment ping web->attacker" || bad "same-segment ping"
sleep 2
docker stop -t 5 evcap-dmz evcap-int >/dev/null
docker logs evcap-dmz >"$SPIKE/tmp/logs/cap-dmz.txt" 2>&1
docker logs evcap-int >"$SPIKE/tmp/logs/cap-int.txt" 2>&1
docker rm evcap-dmz evcap-int >/dev/null
CROSS_DMZ=$(tcpdump -r "$SPIKE/tmp/cap/dmz.pcap" --count 'icmp and host 10.94.20.10' 2>/dev/null | tr -dc 0-9)
CROSS_INT=$(tcpdump -r "$SPIKE/tmp/cap/int.pcap" --count 'icmp and host 10.94.20.10' 2>/dev/null | tr -dc 0-9)
SAME_DMZ=$(tcpdump -r "$SPIKE/tmp/cap/dmz.pcap" --count 'icmp and host 10.94.10.10' 2>/dev/null | tr -dc 0-9)
SAME_INT=$(tcpdump -r "$SPIKE/tmp/cap/int.pcap" --count 'icmp and host 10.94.10.10' 2>/dev/null | tr -dc 0-9)
echo "counts: cross dmz=$CROSS_DMZ int=$CROSS_INT; same-seg dmz=$SAME_DMZ int=$SAME_INT"
[[ "${CROSS_DMZ:-0}" -gt 0 && "${CROSS_INT:-0}" -gt 0 ]] \
  && ok "cross-segment flow on BOTH segment captures" || bad "cross-segment flow missing"
[[ "${SAME_DMZ:-0}" -gt 0 && "${SAME_INT:-1}" -eq 0 ]] \
  && ok "same-segment flow on its own segment ONLY" || bad "same-segment isolation"

B64=$(base64 -w0 "$SPIKE/blast.py")
flood() {  # flood SECONDS SIZE LOGFILE (runs in background, prints datagram count)
  $PY "$CHEXEC" --boot "$SPIKE/tmp/bundle/boot.json" --guest attacker exec \
    "echo $B64 | base64 -d > /tmp/blast.py && python3 /tmp/blast.py 10.94.20.10 9999 $2 $1" \
    >"$3" 2>&1
}

echo "=== resource bill: capture process idle and under flood ==="
side evcap-res -d --cap-add NET_RAW -- -i "$BR_DMZ" -w /cap/load.pcap >/dev/null 2>&1
sleep 2
RES_PID=$(docker inspect -f '{{.State.Pid}}' evcap-res)
if [[ -z "$RES_PID" || "$RES_PID" == "0" ]]; then
  bad "resource sidecar not running"; docker logs evcap-res 2>&1 | head -3
fi
python3 "$SPIKE/measure.py" "$RES_PID" 15 idle | tee -a "$SPIKE/tmp/logs/resource.txt"
flood 30 1400 "$SPIKE/tmp/logs/flood-load.txt" &
FLOOD_JOB=$!
sleep 3
python3 "$SPIKE/measure.py" "$RES_PID" 24 load | tee -a "$SPIKE/tmp/logs/resource.txt"
wait "$FLOOD_JOB"
SENT=$(tail -1 "$SPIKE/tmp/logs/flood-load.txt" | tr -dc 0-9)
docker stop -t 5 evcap-res >/dev/null
docker logs evcap-res >"$SPIKE/tmp/logs/cap-load.txt" 2>&1
docker rm evcap-res >/dev/null
GOT=$(tcpdump -r "$SPIKE/tmp/cap/load.pcap" --count 'udp and port 9999' 2>/dev/null | tr -dc 0-9)
LOADB=$(stat -c %s "$SPIKE/tmp/cap/load.pcap")
echo "flood: sent=$SENT datagrams@1400B in 30s; captured=$GOT; pcap=$((LOADB/1024/1024))MB"
grep -h "dropped by kernel\|captured" "$SPIKE/tmp/logs/cap-load.txt" || true
[[ -n "$GOT" && "$GOT" -gt 0 ]] && ok "flood captured" || bad "flood captured"

echo "=== rotation under flood: -C 10, default buffer then -B 8192 ==="
side evcap-rot1 -d --cap-add NET_RAW -- -i "$BR_DMZ" -C 10 -w /cap/rot1/rot.pcap >/dev/null 2>&1
sleep 2
flood 30 1400 "$SPIKE/tmp/logs/flood-rot1.txt"
sleep 1
docker stop -t 5 evcap-rot1 >/dev/null
docker logs evcap-rot1 >"$SPIKE/tmp/logs/rot1.txt" 2>&1; docker rm evcap-rot1 >/dev/null
N1=$(ls "$SPIKE/tmp/cap/rot1" | wc -l)
SZ1=$(du -sm "$SPIKE/tmp/cap/rot1" | cut -f1)
echo "rot1 (default -B): files=$N1 total=${SZ1}MB"; grep -h "dropped by kernel" "$SPIKE/tmp/logs/rot1.txt" || true
[[ "$N1" -gt 1 ]] && ok "rotation produced multiple 10MB files (default buffer)" || bad "rotation (default buffer)"

side evcap-rot2 -d --cap-add NET_RAW -- -B 8192 -i "$BR_DMZ" -C 10 -w /cap/rot2/rot.pcap >/dev/null 2>&1
sleep 2
flood 30 1400 "$SPIKE/tmp/logs/flood-rot2.txt"
sleep 1
docker stop -t 5 evcap-rot2 >/dev/null
docker logs evcap-rot2 >"$SPIKE/tmp/logs/rot2.txt" 2>&1; docker rm evcap-rot2 >/dev/null
N2=$(ls "$SPIKE/tmp/cap/rot2" | wc -l)
SZ2=$(du -sm "$SPIKE/tmp/cap/rot2" | cut -f1)
echo "rot2 (-B 8192): files=$N2 total=${SZ2}MB"; grep -h "dropped by kernel" "$SPIKE/tmp/logs/rot2.txt" || true
[[ "$N2" -gt 1 ]] && ok "rotation produced multiple 10MB files (-B 8192)" || bad "rotation (-B 8192)"

echo "=== teardown + zero residue ==="
$IR down "$PROJ" >"$SPIKE/tmp/logs/down.txt" 2>&1 && ok "down" || bad "down"
$IR down --all >/dev/null 2>&1
LEFT=$(docker ps -a --format '{{.Names}}' | grep -c "^evcap\|^ir-evidence" || true)
[[ "$LEFT" -eq 0 ]] && ok "zero residue (no evcap/ir-evidence containers)" || bad "residue: $LEFT containers"

echo
echo "RESULT: PASS=$PASS FAIL=$FAIL"
[[ "$FAIL" -eq 0 ]]

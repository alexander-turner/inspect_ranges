#!/bin/bash
# challenge-prober spike: how the active prober reaches a guest service from
# outside every VM, given IP-less bridges and an unaddressable hypervisor.
# Mechanisms measured against a nonce-bound HTTP service on a booted range:
#   (a)  persistent probe veth with an IP in the range container netns
#   (a2) the same, clamped by netns-local nftables (addressable but silent)
#   (b)  transient veth, existing only during the probe window
#   (c)  AF_PACKET userspace probe with no kernel IP identity at all
# Per mechanism: nonce round-trip + RTT, the agent's active view (neigh cache,
# ping, TCP connect verdicts), passive sniffing from the agent box, pcap
# attribution, and conformance (host netns clean, egress unchanged, no new
# agent-visible listeners). Usage: ./run.sh [down]. Artifacts under tmp/
# (gitignored). CID band 30500; exclusive via the shared battery lock.
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
PROBE_A_IP=10.95.10.250
PROBE_A_MAC=02:50:00:00:02:50
PROBE_C_IP=10.95.10.251
PROBE_C_MAC=02:50:00:00:02:51
WEB_IP=10.95.10.10
SECRET="challenge-prober-spike-secret"

if [[ "${1:-}" == "down" ]]; then
  docker rm -f chprobe-cap chprobe-client chprobe-raw >/dev/null 2>&1
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
docker rm -f chprobe-cap chprobe-client chprobe-raw >/dev/null 2>&1
rm -rf "$SPIKE/tmp" && mkdir -p "$SPIKE/tmp/cache" "$SPIKE/tmp/logs" "$SPIKE/tmp/cap"
chmod 777 "$SPIKE/tmp/cap"

expected() {  # expected SHA for a nonce (mirrors httpnonce.py)
  python3 -c "import hashlib,sys;print(hashlib.sha256((sys.argv[1]+'$SECRET').encode()).hexdigest())" "$1"
}
gx() {  # guest exec: gx GUEST 'command'
  $PY "$CHEXEC" --boot "$SPIKE/tmp/bundle/boot.json" --guest "$1" exec "$2"
}
ship() {  # ship FILE GUEST DEST: deliver a spike script to a guest
  gx "$2" "echo $(base64 -w0 "$SPIKE/$1") | base64 -d > $3" >/dev/null
}

echo "=== setup: doctor, golden, render (cid base 30500), floor assert, up ==="
$IR doctor >"$SPIKE/tmp/logs/doctor.txt" 2>&1 \
  && ok "doctor" || { bad "doctor"; tail -20 "$SPIKE/tmp/logs/doctor.txt"; exit 1; }
DB_OUT=$($IR daemon-bundle -o "$SPIKE/tmp/artifacts")
DAEMON_SHA=$(echo "$DB_OUT" | grep -o 'bundle sha256:[0-9a-f]*' | cut -d: -f2)
VENDOR_SHA=$(sha256sum "$VENDOR" | cut -d' ' -f1)
$IR images derive "$VENDOR" --sha256 "$VENDOR_SHA" --name chprobe-guest \
  --image-cache "$INSPECT_RANGES_IMAGE_CACHE" --daemon-bundle "$SPIKE/tmp/artifacts" \
  --daemon-sha256 "$DAEMON_SHA" >"$SPIKE/tmp/logs/derive.txt" 2>&1 \
  && ok "golden derived" || { bad "golden"; tail -5 "$SPIKE/tmp/logs/derive.txt"; exit 1; }
$IR render "$SPIKE/spec.yaml" -o "$SPIKE/tmp/bundle" --cid-base 30500 \
  --image-cache "$INSPECT_RANGES_IMAGE_CACHE" >"$SPIKE/tmp/logs/render.txt" 2>&1 \
  && ok "rendered" || { bad "render"; cat "$SPIKE/tmp/logs/render.txt"; exit 1; }
grep cap_add "$SPIKE/tmp/bundle/compose.yaml" | grep -q NET_RAW \
  && bad "floor assert: NET_RAW present" || ok "floor assert: eight caps only"
$IR up "$SPIKE/tmp/bundle" --image-cache "$INSPECT_RANGES_IMAGE_CACHE" \
  >"$SPIKE/tmp/logs/up.txt" 2>&1 \
  && ok "range up" || { bad "range up"; tail -20 "$SPIKE/tmp/logs/up.txt"; exit 1; }
PROJ=$(sed -n 's/^ready: project \([^ ]*\).*/\1/p' "$SPIKE/tmp/logs/up.txt")
CTR="${PROJ}-range-1"
BR=$(sed -n 1p "$SPIKE/tmp/bundle/netns/bridges.txt")
SIDE_IMG=$(docker inspect -f '{{.Config.Image}}' "$CTR")
echo "project=$PROJ container=$CTR bridge=$BR sidecar-image=$SIDE_IMG"
for g in web attacker; do
  $PY "$CHEXEC" --boot "$SPIKE/tmp/bundle/boot.json" --guest "$g" wait 120 \
    >/dev/null 2>&1 && ok "daemon ready: $g" || bad "daemon ready: $g"
done

echo "=== target service: nonce HTTP server on web ==="
ship httpnonce.py web /tmp/httpnonce.py
gx web 'setsid python3 /tmp/httpnonce.py >/dev/null 2>&1 < /dev/null &' >/dev/null
sleep 2
N=base$RANDOM
GOT=$(gx attacker "python3 -c \"import urllib.request;print(urllib.request.urlopen('http://$WEB_IP:8080/probe?n=$N',timeout=5).read().decode())\"" 2>/dev/null | tail -1)
[[ "$GOT" == "$(expected $N)" ]] \
  && ok "service up, nonce verified from the agent box (baseline reachability)" \
  || { bad "nonce service"; echo "got=$GOT"; }

ship agentview.py attacker /tmp/agentview.py
ship sniff.py attacker /tmp/sniff.py
gxr() {  # guest exec as root (daemon-side user switching)
  $PY "$CHEXEC" --boot "$SPIKE/tmp/bundle/boot.json" --guest "$1" --user root exec "$2"
}
SUDO=""
[[ "$(gxr attacker 'id -u' 2>/dev/null | tail -1)" == "0" ]] && SUDO=root
[[ -n "$SUDO" ]] && ok "agent-side root via channel user switching (sniffer enabled)" \
  || echo "NOTE  no agent-side root; passive sniffing will be skipped"
aview() { gx attacker "python3 /tmp/agentview.py $PROBE_A_IP $PROBE_C_IP" 2>/dev/null | grep -E '^(NEIGH|PING|TCP)'; }

echo "=== baseline agent view (no probe endpoints exist) ==="
aview | tee "$SPIKE/tmp/logs/view-baseline.txt"
grep -q "PING $PROBE_A_IP silent" "$SPIKE/tmp/logs/view-baseline.txt" \
  && ok "baseline: probe IPs dark" || bad "baseline not dark"
ship agentview.py web /tmp/agentview.py
BASE_OPEN=$(gx web "python3 /tmp/agentview.py 10.95.10.3" 2>/dev/null | grep -c ' open' || true)
echo "baseline agent open-port count (from web): $BASE_OPEN"

echo "=== pcap attribution capture: NET_RAW sidecar on $BR for A and C ==="
docker run --name chprobe-cap -d --network "container:$CTR" --cap-drop ALL \
  --cap-add NET_RAW -v "$SPIKE/tmp/cap:/cap" --entrypoint "" "$SIDE_IMG" \
  /usr/bin/tcpdump -Z root -i "$BR" -w /cap/probes.pcap >/dev/null 2>&1
sleep 2

echo "=== mechanism A: persistent probe veth (declared endpoint) ==="
docker exec "$CTR" ip link add pr0 address $PROBE_A_MAC type veth peer name pr0b
docker exec "$CTR" ip link set pr0b master "$BR" up
docker exec "$CTR" ip addr add $PROBE_A_IP/24 dev pr0
docker exec "$CTR" ip link set pr0 up
sleep 1
RTTS_A=""
for i in 1 2 3 4 5; do
  N="a$i$RANDOM"
  OUT=$(docker run --rm --network "container:$CTR" --cap-drop ALL \
    -v "$SPIKE:/spike:ro" --entrypoint "" "$SIDE_IMG" \
    python3 /spike/probeclient.py $WEB_IP 8080 "$N" 2>&1)
  BODY=$(echo "$OUT" | sed -n 's/^BODY //p')
  RTT=$(echo "$OUT" | sed -n 's/^RTT_MS //p')
  [[ "$BODY" == "$(expected $N)" ]] || { bad "A probe $i nonce mismatch"; echo "$OUT"; }
  RTTS_A="$RTTS_A $RTT"
done
[[ $(echo $RTTS_A | wc -w) -eq 5 ]] && ok "A: 5/5 nonce probes verified (RTT ms:$RTTS_A)"
echo "--- agent view during A (active recon) ---"
aview | tee "$SPIKE/tmp/logs/view-A.txt"
grep -q "PING $PROBE_A_IP reply" "$SPIKE/tmp/logs/view-A.txt" \
  && ok "A: endpoint answers ping (addressable, visible by design)" || bad "A: no ping reply"
grep -q "TCP $PROBE_A_IP:22 rst" "$SPIKE/tmp/logs/view-A.txt" \
  && ok "A: closed ports RST (kernel endpoint, zero listeners)" || bad "A: port 22 verdict"
if [[ -n "$SUDO" ]]; then
  gxr attacker "python3 /tmp/sniff.py $PROBE_A_IP,$PROBE_C_IP 8" >"$SPIKE/tmp/logs/sniff-A.txt" 2>/dev/null &
  SNIFF_JOB=$!
  sleep 2
  for i in 6 7 8; do
    docker run --rm --network "container:$CTR" --cap-drop ALL -v "$SPIKE:/spike:ro" \
      --entrypoint "" "$SIDE_IMG" python3 /spike/probeclient.py $WEB_IP 8080 "a$i$RANDOM" >/dev/null 2>&1
  done
  wait $SNIFF_JOB
  SNIFF_A=$(grep '^SNIFF' "$SPIKE/tmp/logs/sniff-A.txt" || echo "SNIFF ? ? ?")
  echo "A passive sniff during 3 probes (total bcast ucast): $SNIFF_A"
  UCAST=$(echo "$SNIFF_A" | awk '{print $4}')
  [[ "$UCAST" == "0" ]] \
    && ok "A: probe unicast invisible to passive agent (switched segment)" \
    || echo "NOTE  A: agent passively saw $UCAST unicast probe frames"
fi

echo "=== mechanism A2: nftables clamp (addressable but silent) ==="
docker exec "$CTR" nft add table inet probeguard
docker exec "$CTR" nft add chain inet probeguard input '{ type filter hook input priority 0 ; policy accept ; }'
docker exec "$CTR" nft add rule inet probeguard input iifname pr0 ct state established,related accept
docker exec "$CTR" nft add rule inet probeguard input iifname pr0 drop
N="a2x$RANDOM"
OUT=$(docker run --rm --network "container:$CTR" --cap-drop ALL -v "$SPIKE:/spike:ro" \
  --entrypoint "" "$SIDE_IMG" python3 /spike/probeclient.py $WEB_IP 8080 "$N" 2>&1)
[[ "$(echo "$OUT" | sed -n 's/^BODY //p')" == "$(expected $N)" ]] \
  && ok "A2: probe still works under the clamp (ct established path)" \
  || { bad "A2: probe broken by clamp"; echo "$OUT"; }
aview | tee "$SPIKE/tmp/logs/view-A2.txt"
grep -q "PING $PROBE_A_IP silent" "$SPIKE/tmp/logs/view-A2.txt" \
  && ok "A2: ping silent under clamp" || bad "A2: still answers ping"
grep -q "TCP $PROBE_A_IP:22 timeout" "$SPIKE/tmp/logs/view-A2.txt" \
  && ok "A2: scans see filtered (no RST) under clamp" || bad "A2: still RSTs"
docker exec "$CTR" nft delete table inet probeguard

echo "=== mechanism B: transient attach (window-only endpoint) ==="
docker exec "$CTR" ip link del pr0
gxr attacker "ip neigh flush all" >/dev/null 2>&1
T0=$(date +%s.%N)
docker exec "$CTR" ip link add pr0 address $PROBE_A_MAC type veth peer name pr0b
docker exec "$CTR" ip link set pr0b master "$BR" up
docker exec "$CTR" ip addr add $PROBE_A_IP/24 dev pr0
docker exec "$CTR" ip link set pr0 up
N="b$RANDOM"
OUT=$(docker run --rm --network "container:$CTR" --cap-drop ALL -v "$SPIKE:/spike:ro" \
  --entrypoint "" "$SIDE_IMG" python3 /spike/probeclient.py $WEB_IP 8080 "$N" 2>&1)
gx attacker "ping -c 1 -W 1 $PROBE_A_IP" >/dev/null 2>&1  # agent touches it inside the window
docker exec "$CTR" ip link del pr0
T1=$(date +%s.%N)
CYCLE=$(python3 -c "print(f'{($T1-$T0)*1000:.0f}')")
[[ "$(echo "$OUT" | sed -n 's/^BODY //p')" == "$(expected $N)" ]] \
  && ok "B: transient window probe verified (create+probe+delete ${CYCLE} ms)" \
  || { bad "B: transient probe failed"; echo "$OUT"; }
aview | tee "$SPIKE/tmp/logs/view-B.txt"
grep -q "PING $PROBE_A_IP silent" "$SPIKE/tmp/logs/view-B.txt" \
  && ok "B: endpoint gone after the window" || bad "B: still answers after delete"
NEIGH_B=$(grep "NEIGH $PROBE_A_IP" "$SPIKE/tmp/logs/view-B.txt")
echo "B ARP residue on the agent after the window: $NEIGH_B"
[[ "$NEIGH_B" != *absent* ]] \
  && ok "B: ARP cache residue persists on the agent (visibility blink is recorded by the segment)" \
  || echo "NOTE  B: no ARP residue observed"

echo "=== mechanism C: AF_PACKET userspace probe (no kernel identity) ==="
RTTS_C=""
for i in 1 2 3; do
  N="c$i$RANDOM"
  OUT=$(docker run --rm --network "container:$CTR" --cap-drop ALL --cap-add NET_RAW \
    -v "$SPIKE:/spike:ro" --entrypoint "" "$SIDE_IMG" \
    python3 /spike/rawprobe.py "$BR" $PROBE_C_MAC $PROBE_C_IP $WEB_IP 8080 "$N" 10 2>"$SPIKE/tmp/logs/raw-$i.txt")
  BODY=$(echo "$OUT" | sed -n 's/^BODY //p')
  RTT=$(echo "$OUT" | sed -n 's/^RTT_MS //p')
  [[ "$BODY" == "$(expected $N)" ]] || { bad "C probe $i nonce mismatch"; cat "$SPIKE/tmp/logs/raw-$i.txt"; }
  RTTS_C="$RTTS_C $RTT"
done
[[ $(echo $RTTS_C | wc -w) -eq 3 ]] && ok "C: 3/3 userspace nonce probes verified (RTT ms:$RTTS_C)"
if [[ -n "$SUDO" ]]; then
  gxr attacker "python3 /tmp/sniff.py $PROBE_C_IP 8" >"$SPIKE/tmp/logs/sniff-C.txt" 2>/dev/null &
  SNIFF_JOB=$!
  sleep 2
  docker run --rm --network "container:$CTR" --cap-drop ALL --cap-add NET_RAW \
    -v "$SPIKE:/spike:ro" --entrypoint "" "$SIDE_IMG" \
    python3 /spike/rawprobe.py "$BR" $PROBE_C_MAC $PROBE_C_IP $WEB_IP 8080 "csniff$RANDOM" 10 >/dev/null 2>&1
  wait $SNIFF_JOB
  SNIFF_C=$(grep '^SNIFF' "$SPIKE/tmp/logs/sniff-C.txt" || echo "SNIFF ? ? ?")
  echo "C passive sniff during 1 probe (total bcast ucast): $SNIFF_C"
fi
aview | tee "$SPIKE/tmp/logs/view-C.txt"
grep -q "PING $PROBE_C_IP silent" "$SPIKE/tmp/logs/view-C.txt" \
  && ok "C: no addressable endpoint before/after (nothing to scan)" || bad "C: endpoint visible"

echo "=== mechanism C2: FDB pin for the fabricated MAC (unknown-unicast fix) ==="
docker exec "$CTR" bridge fdb add $PROBE_C_MAC dev "$BR" master static 2>/dev/null \
  || docker exec "$CTR" bridge fdb add $PROBE_C_MAC dev "$BR" self permanent
if [[ -n "$SUDO" ]]; then
  gxr attacker "python3 /tmp/sniff.py $PROBE_C_IP 8" >"$SPIKE/tmp/logs/sniff-C2.txt" 2>/dev/null &
  SNIFF_JOB=$!
  sleep 2
  N="c2$RANDOM"
  OUT=$(docker run --rm --network "container:$CTR" --cap-drop ALL --cap-add NET_RAW \
    -v "$SPIKE:/spike:ro" --entrypoint "" "$SIDE_IMG" \
    python3 /spike/rawprobe.py "$BR" $PROBE_C_MAC $PROBE_C_IP $WEB_IP 8080 "$N" 10 2>/dev/null)
  [[ "$(echo "$OUT" | sed -n 's/^BODY //p')" == "$(expected $N)" ]] \
    && ok "C2: probe verified with the FDB pin in place" || { bad "C2: probe failed under FDB pin"; echo "$OUT"; }
  wait $SNIFF_JOB
  SNIFF_C2=$(grep '^SNIFF' "$SPIKE/tmp/logs/sniff-C2.txt" || echo "SNIFF ? ? ?")
  echo "C2 passive sniff with FDB pin (total bcast ucast): $SNIFF_C2"
  UC2=$(echo "$SNIFF_C2" | awk '{print $4}')
  [[ "$UC2" == "0" ]] \
    && ok "C2: FDB pin stops unknown-unicast flooding (agent passively sees nothing)" \
    || bad "C2: still flooded ($UC2 unicast frames seen)"
fi
docker exec "$CTR" bridge fdb del $PROBE_C_MAC dev "$BR" master 2>/dev/null \
  || docker exec "$CTR" bridge fdb del $PROBE_C_MAC dev "$BR" self 2>/dev/null || true

echo "=== pcap attribution: probe flows identifiable by declared source identity ==="
docker stop -t 5 chprobe-cap >/dev/null 2>&1; docker rm chprobe-cap >/dev/null 2>&1
A_FRAMES=$(tcpdump -r "$SPIKE/tmp/cap/probes.pcap" --count "host $PROBE_A_IP and tcp port 8080" 2>/dev/null | tr -dc 0-9)
C_FRAMES=$(tcpdump -r "$SPIKE/tmp/cap/probes.pcap" --count "host $PROBE_C_IP and tcp port 8080" 2>/dev/null | tr -dc 0-9)
C_MAC_FRAMES=$(tcpdump -r "$SPIKE/tmp/cap/probes.pcap" --count "ether host $PROBE_C_MAC" 2>/dev/null | tr -dc 0-9)
AGENT_FRAMES=$(tcpdump -r "$SPIKE/tmp/cap/probes.pcap" --count "host 10.95.10.3 and tcp port 8080" 2>/dev/null | tr -dc 0-9)
echo "pcap frames: A=$A_FRAMES C=$C_FRAMES C-by-MAC=$C_MAC_FRAMES agent=$AGENT_FRAMES"
[[ "${A_FRAMES:-0}" -gt 0 && "${C_FRAMES:-0}" -gt 0 && "${C_MAC_FRAMES:-0}" -gt 0 ]] \
  && ok "attribution: probe traffic in our own pcap, selectable by probe IP and MAC" \
  || bad "attribution: probe flows not found in pcap"

echo "=== conformance: host netns, egress, no new agent listeners ==="
ip -o link | grep -q pr0 && bad "host netns: pr0 leaked" || ok "host netns: no probe interfaces"
gx attacker "ping -c 1 -W 2 1.1.1.1" >/dev/null 2>&1 \
  && bad "egress: attacker reached the internet" || ok "egress: attacker still has none"
POST_OPEN=$(gx web "python3 /tmp/agentview.py 10.95.10.3" 2>/dev/null | grep -c ' open' || true)
[[ "$POST_OPEN" == "$BASE_OPEN" ]] \
  && ok "agent listener surface unchanged (open ports from web: $BASE_OPEN before, $POST_OPEN after)" \
  || bad "agent listener surface changed: $BASE_OPEN -> $POST_OPEN"

echo "=== teardown ==="
cd "$ROOT" && $IR down --all >"$SPIKE/tmp/logs/down.txt" 2>&1 \
  && ok "range down" || bad "range down"
docker ps -a --format '{{.Names}}' | grep -q '^chprobe-' \
  && bad "residue: chprobe containers remain" || ok "zero container residue"

echo
echo "RESULT: PASS=$PASS FAIL=$FAIL"
[[ $FAIL -eq 0 ]]

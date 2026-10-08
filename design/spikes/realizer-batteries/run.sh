#!/bin/bash
# realizer-v1 slice 4: the five networking conformance batteries (acl-v2,
# routing, egress, netsvc, routed) against realizer-booted ranges through one
# shared runner: render each spike's spec at CID 3000+, `up` it under the
# hardened image with v3 goldens, run the checks over the channel client by
# guest NAME, `down`. This retires each spike's private apply glue and is the
# regression harness the channel track's slice 7 points at.
# Usage: ./run.sh [down] [only=<name>]. See README.md.
set -euo pipefail
cd "$(dirname "$0")"
SPIKE="$PWD"
ROOT="$(cd ../../.. && pwd)"

VENDOR="${VENDOR:-$HOME/.cache/inspect-ranges/images/noble-server-cloudimg-amd64.img}"
export XDG_STATE_HOME="$SPIKE/tmp/state"
IR="uv run inspect-ranges"
CACHE="$SPIKE/tmp/cache"
UPLINK_NET="ir-uplink"
UPSTREAM="ir-upstream"
ONLY="${2:-${1:-}}"; [[ "$ONLY" == only=* ]] && ONLY="${ONLY#only=}" || ONLY=""

if [[ "${1:-}" == "down" ]]; then
  (cd "$ROOT" && $IR down --all) || true
  docker rm -f "$UPSTREAM" >/dev/null 2>&1 || true
  docker network rm "$UPLINK_NET" >/dev/null 2>&1 || true
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

echo "=== shared setup: daemon artifact + v3 golden (named noble-range-guest, as the specs reference) ==="
$IR daemon-bundle -o "$SPIKE/tmp/artifacts" >/dev/null
VENDOR_SHA=$(sha256sum "$VENDOR" | cut -d' ' -f1)
$IR images derive "$VENDOR" --sha256 "$VENDOR_SHA" --name noble-range-guest \
  --image-cache "$CACHE" --daemon-bundle "$SPIKE/tmp/artifacts" >/dev/null

BUNDLE=""; PROJECT=""
gx() { uv run python design/spikes/_shared/chexec.py --boot "$BUNDLE/boot.json" --guest "$1" exec "$2"; }
in_range() { docker exec "${PROJECT}-range-1" sh -c "$1"; }

bring_up() {  # bring_up <spec-path> [extra up args...]
  local spec="$1"; shift
  local name; name=$(basename "$(dirname "$spec")")
  BUNDLE="$SPIKE/tmp/bundle-$name"
  rm -rf "$BUNDLE"
  $IR render "$spec" -o "$BUNDLE" --image-cache "$CACHE" --cid-base 3000 >/dev/null
  local out; out=$($IR up "$BUNDLE" --image-cache "$CACHE" "$@")
  PROJECT=$(echo "$out" | grep -o 'project ir-[a-z0-9-]*' | head -1 | cut -d' ' -f2)
  echo "$out" | grep -q "ready: project" || { echo "$out"; return 1; }
}

tear_down() { $IR down "$PROJECT" >/dev/null; }

ensure_uplink() {
  docker network inspect "$UPLINK_NET" >/dev/null 2>&1 || \
    docker network create --subnet 198.51.100.0/24 "$UPLINK_NET" >/dev/null
  docker rm -f "$UPSTREAM" >/dev/null 2>&1 || true
  docker run -d --name "$UPSTREAM" --cap-add NET_ADMIN \
    --network "$UPLINK_NET" --ip 198.51.100.7 python:3.12-alpine \
    sh -c "(python3 -m http.server 443 &); exec python3 -m http.server 80" >/dev/null
}

upstream_route() {  # route the range subnet back via the range's uplink address
  local subnet="$1"
  local range_ip
  range_ip=$(docker inspect -f "{{(index .NetworkSettings.Networks \"$UPLINK_NET\").IPAddress}}" "${PROJECT}-range-1")
  docker exec "$UPSTREAM" ip route replace "$subnet" via "$range_ip"
}

drop_check()   { gx "$1" "timeout 3 bash -c 'echo > /dev/tcp/$2' 2>/dev/null; [ \$? -eq 124 ] && echo DROPPED" | grep -q DROPPED; }
refuse_check() { gx "$1" "timeout 3 bash -c 'echo > /dev/tcp/$2' 2>&1 | grep -q refused && echo REFUSED" | grep -q REFUSED; }
connect_check(){ gx "$1" "timeout 3 bash -c 'echo > /dev/tcp/$2' && echo CONNECTED" | grep -q CONNECTED; }
ping_check()   { gx "$1" "ping -c1 -W2 $2 >/dev/null && echo PINGED" | grep -q PINGED; }

# ---------------------------------------------------------------- acl-v2
if [[ -z "$ONLY" || "$ONLY" == "acl-v2" ]]; then
echo "=== acl-v2 (ACL v2 vocabulary on the wire) ==="
bring_up design/spikes/acl-v2/spec.yaml
refuse_check attacker 10.80.20.10/5432 && ok "A1 network allow (refused-fast)" || bad "A1"
drop_check attacker 10.80.20.10/22 && ok "A2 deny carve-out beats later allow" || bad "A2"
refuse_check web 10.80.20.10/80 && ok "A3a guest endpoint allows its guest" || bad "A3a"
drop_check attacker 10.80.20.10/80 && ok "A3b guest endpoint excludes others" || bad "A3b"
ping_check attacker 10.80.20.10 && ok "A4 icmp allowed cross-segment" || bad "A4"
refuse_check attacker 10.80.20.10/8080 && ok "A5a CIDR endpoint allows its /32" || bad "A5a"
drop_check web 10.80.20.10/8080 && ok "A5b CIDR endpoint excludes others" || bad "A5b"
drop_check db 10.80.10.10/22 && ok "A6 default deny asymmetry" || bad "A6"
ping_check attacker 10.80.10.10 && ok "A7 same-segment L2 intact" || bad "A7"
[[ "$(ip -o link | grep -c 'br-dmz\|br-internal')" -eq 0 ]] && ok "A8 host netns invisibility" || bad "A8"
gx router 'nft list chain inet fw forward | grep -q "tcp dport 22 drop" && nft list chain inet fw forward | grep -q "policy drop" && echo LIVE' | grep -q LIVE \
  && ok "A9 rendered ruleset live on the router" || bad "A9"
tear_down
fi

# ---------------------------------------------------------------- routing
if [[ -z "$ONLY" || "$ONLY" == "routing" ]]; then
echo "=== routing (election, static routes, transit policy) ==="
bring_up design/spikes/routing/spec.yaml
refuse_check attacker 10.80.30.10/443 && ok "R1 two-hop allowed path" || bad "R1"
drop_check attacker 10.80.30.10/22 && ok "R2 two-hop default deny" || bad "R2"
gx app 'ip route show default | grep -q "via 10.80.20.1" && echo OK' | grep -q OK && ok "R3a gateway election declared" || bad "R3a"
ping_check app 10.80.10.2 && ok "R3b gateway election functional" || bad "R3b"
drop_check safe 10.80.10.2/22 && ok "R4 reverse chain default deny" || bad "R4"
gx r1 'ip route | grep -q "10.80.30.0/24 via 10.80.20.2" && echo OK' | grep -q OK && ok "R5a static route live on r1" || bad "R5a"
gx r2 'ip route | grep -q "10.80.10.0/24 via 10.80.20.1" && echo OK' | grep -q OK && ok "R5b static route live on r2" || bad "R5b"
gx r2 'nft list chain inet fw forward | grep -q "ip saddr 10.80.10.0/24" && echo OK' | grep -q OK && ok "R6 transit subnet match" || bad "R6"
[[ "$(ip -o link | grep -c 'br-dmz\|br-core\|br-vault')" -eq 0 ]] && ok "R7 host netns invisibility" || bad "R7"
tear_down
fi

# ---------------------------------------------------------------- egress
if [[ -z "$ONLY" || "$ONLY" == "egress" ]]; then
echo "=== egress (scoped NAT allowlist) ==="
ensure_uplink
bring_up design/spikes/egress/spec.yaml --uplink-network "$UPLINK_NET"
connect_check workstation 198.51.100.7/443 && ok "E1 allowlisted flow completes" || bad "E1"
drop_check workstation 198.51.100.7/80 && ok "E2 exactly the allowlist" || bad "E2"
drop_check attacker 198.51.100.7/443 && ok "E3 attacker egress none beats the allowlist" || bad "E3"
in_range 'nft list chain inet rangehost forward | grep -q "udp dport 123"' && ok "E4 udp allowlist entry live" || bad "E4"
in_range 'nft list table ip rangenat | grep -q masquerade' && ok "E5 masquerade live" || bad "E5"
ping_check attacker 10.90.10.10 && ok "E6 same-segment unaffected" || bad "E6"
gx workstation 'ip route show default | grep -q "via 10.90.10.1" && echo OK' | grep -q OK && ok "E7 NAT gateway is the hypervisor bridge" || bad "E7"
[[ "$(ip -o link | grep -c 'br-corp')" -eq 0 ]] && ok "E8 host netns invisibility" || bad "E8"
tear_down
fi

# ---------------------------------------------------------------- netsvc
if [[ -z "$ONLY" || "$ONLY" == "netsvc" ]]; then
echo "=== netsvc (DHCP reservations, range DNS, resolver handout) ==="
bring_up design/spikes/netsvc/spec.yaml
gx web 'ip -4 addr show eth0 | grep -q "10.95.10.10/24" && echo OK' | grep -q OK && ok "N1 DHCP delivers the allocated address" || bad "N1"
gx attacker 'ip -4 addr show eth0 | grep -q "10.95.10.2/24" && echo OK' | grep -q OK && ok "N2 DHCP for the attacker" || bad "N2"
gx attacker 'getent hosts web | grep -q 10.95.10.10 && echo OK' | grep -q OK && ok "N3 derived record resolves" || bad "N3"
gx attacker 'getent hosts files.corp.example | grep -q 10.95.10.200 && echo OK' | grep -q OK && ok "N4 explicit record resolves" || bad "N4"
gx attacker 'resolvectl dns eth0 | grep -q 10.95.10.1 && echo OK' | grep -q OK && ok "N5 DHCP-handed resolver is the range service" || bad "N5"
gx app 'resolvectl dns eth0 | grep -q "10.95.20.5" && resolvectl dns eth0 | grep -q "9.9.9.9" && echo OK' | grep -q OK && ok "N6 authoritative + external resolvers" || bad "N6"
gx attacker 'ping -c1 -W2 10.95.20.5 >/dev/null 2>&1 || echo OK' | grep -q OK && ok "N7 segments isolated without a router" || bad "N7"
[[ "$(ip -o link | grep -c 'br-lab\|br-net2')" -eq 0 ]] && ok "N8 host netns invisibility" || bad "N8"
tear_down
fi

# ---------------------------------------------------------------- routed
if [[ -z "$ONLY" || "$ONLY" == "routed" ]]; then
echo "=== routed (two-way un-NATed egress) ==="
ensure_uplink
bring_up design/spikes/routed/spec.yaml --uplink-network "$UPLINK_NET"
upstream_route 10.91.10.0/24
connect_check workstation 198.51.100.7/443 && ok "T1 routed flow completes" || bad "T1"
gx workstation 'timeout 3 bash -c "exec 3<>/dev/tcp/198.51.100.7/443; printf \"GET / HTTP/1.0\r\n\r\n\" >&3; cat <&3 >/dev/null" || true' >/dev/null
sleep 1
docker logs "$UPSTREAM" 2>&1 | grep -q "10.91.10.10" && ok "T2 un-NATed (upstream saw the real source)" || bad "T2"
# the v3 golden carries no listeners; start one in-guest for the ingress proof
gx workstation 'setsid python3 -m http.server 2222 --bind 0.0.0.0 >/dev/null 2>&1 & sleep 0.5; echo STARTED' | grep -q STARTED || bad "T3 listener start"
docker exec "$UPSTREAM" python3 -c "import socket; socket.create_connection(('10.91.10.10', 2222), 3)" \
  && ok "T3 two-way routed (ingress reaches the guest)" || bad "T3"
drop_check attacker 198.51.100.7/443 && ok "T4 attacker egress none beats routed" || bad "T4"
in_range 'nft list ruleset | grep -c masquerade | grep -qx 0' && ok "T5 no masquerade anywhere" || bad "T5"
gx workstation 'ip route show default | grep -q "via 10.91.10.1" && echo OK' | grep -q OK && ok "T6 routed gateway" || bad "T6"
[[ "$(ip -o link | grep -c 'br-wide')" -eq 0 ]] && ok "T7 host netns invisibility" || bad "T7"
tear_down
docker rm -f "$UPSTREAM" >/dev/null 2>&1 || true
docker network rm "$UPLINK_NET" >/dev/null 2>&1 || true
fi

echo
echo "$PASS passed, $FAIL failed"
exit $((FAIL > 0))

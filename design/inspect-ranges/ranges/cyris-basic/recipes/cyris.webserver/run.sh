#!/bin/sh
# CyRIS webserver (upstream guest_settings tasks): accounts, apache2+php
# (upstream httpd+php), and the two planted captures. /root/flag.txt is the
# plant layer's.
set -e

exec_guest() { "$IR_EXEC" --budget-ms 600000 -- sh -c "$1"; }

echo "step: packages (upstream httpd+php, apt equivalents)"
exec_guest 'export DEBIAN_FRONTEND=noninteractive; apt-get update -q && apt-get install -y -q apache2 php libapache2-mod-php'

echo "step: accounts"
exec_guest 'id daniel >/dev/null 2>&1 || useradd --create-home --shell /bin/bash daniel
echo "daniel:JamesBond" | chpasswd
echo "root:new-root-password" | chpasswd'

echo "step: synthesize the planted captures (ddos + wireless)"
cat > /tmp/mkpcap.$$.py <<'MKPCAP'
"""The webserver's planted captures: a ddos SYN flood to :80 (classic pcap,
ethernet) and a minimal 802.11 beacon capture (linktype 105, the aircrack
exercise artifact)."""
import struct

def tcp_syn(src_ip, dst_ip, sport, dport, seq):
    eth = b"\x02\x00\x00\x00\x00\x01" + b"\x02\x00\x00\x00\x00\x02" + b"\x08\x00"
    ip = struct.pack(
        ">BBHHHBBH4s4s", 0x45, 0, 40, seq & 0xFFFF, 0, 64, 6, 0,
        bytes(int(o) for o in src_ip.split(".")),
        bytes(int(o) for o in dst_ip.split(".")),
    )
    tcp = struct.pack(">HHIIBBHHH", sport, dport, seq, 0, 0x50, 0x02, 8192, 0, 0)
    return eth + ip + tcp

def write_pcap(path, frames, linktype):
    with open(path, "wb") as fh:
        fh.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, linktype))
        for index, frame in enumerate(frames):
            fh.write(struct.pack("<IIII", 1510000000 + index, 0, len(frame), len(frame)))
            fh.write(frame)

ddos = [tcp_syn(f"203.0.113.{i % 254 + 1}", "10.1.20.5", 52000 + i, 80, i) for i in range(800)]
write_pcap("/home/traffic.pcap", ddos, 1)

def beacon(bssid, ssid, seq):
    mac = bytes.fromhex(bssid.replace(":", ""))
    hdr = b"\x80\x00\x00\x00" + b"\xff" * 6 + mac + mac + struct.pack("<H", seq << 4)
    fixed = struct.pack("<QHH", seq * 102400, 100, 0x0401)
    tags = bytes([0, len(ssid)]) + ssid.encode() + bytes([1, 1, 0x82])
    return hdr + fixed + tags

beacons = [beacon("02:ca:ff:ee:00:01", "trainer-net", i) for i in range(50)]
write_pcap("/home/wireless.pcap", beacons, 105)
print("captures written")
MKPCAP
"$IR_PUSH" /tmp/mkpcap.$$.py /tmp/ir-mkpcap.py --mode 644
exec_guest 'python3 /tmp/ir-mkpcap.py && chmod 644 /home/traffic.pcap /home/wireless.pcap && rm -f /tmp/ir-mkpcap.py'

echo "step: assert the declared surface"
exec_guest 'set -e
systemctl is-active apache2 >/dev/null
curl -fs -o /dev/null http://127.0.0.1:80/
php -v >/dev/null
getent passwd daniel >/dev/null
test -s /home/traffic.pcap && test -s /home/wireless.pcap
test ! -e /root/flag.txt || { echo "flag must not be baked" >&2; exit 1; }'

echo "cyris.webserver OK"

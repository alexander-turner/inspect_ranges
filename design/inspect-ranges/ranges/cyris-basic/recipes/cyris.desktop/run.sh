#!/bin/sh
# CyRIS desktop (upstream guest_settings tasks, deferred.yaml carries the
# originals): accounts (daniel, the weak root password), analyst tools
# (upstream yum wireshark/GeoIP/nmap, realized apt tshark/geoip-bin/nmap),
# the emulated ssh-attack log noise, both planted traffic captures, and the
# dummy resident malware process. /root/flag.txt is the plant layer's.
set -e

exec_guest() { "$IR_EXEC" --budget-ms 600000 -- sh -c "$1"; }

echo "step: packages (upstream wireshark/GeoIP/nmap, apt equivalents)"
exec_guest 'export DEBIAN_FRONTEND=noninteractive; apt-get update -q && apt-get install -y -q tshark geoip-bin nmap'

echo "step: accounts (daniel; the weak root password upstream modify_account sets)"
exec_guest 'id daniel >/dev/null 2>&1 || useradd --create-home --shell /bin/bash --comment "Daniel Radcliffe" daniel
echo "daniel:danielpass" | chpasswd
echo "root:abcd1234" | chpasswd'

echo "step: synthesize the planted captures (upstream emulate_traffic_capture_file)"
cat > /tmp/mkpcap.$$.py <<'MKPCAP'
"""Deterministic pcap synthesis for the CyRIS planted captures: an ssh-attack
capture (TCP SYNs to :22 from the declared source) and a dos capture (SYN
flood to :80 from many sources). Classic pcap, linktype 1 (ethernet)."""
import struct, sys

def tcp_syn(src_ip, dst_ip, sport, dport, seq):
    eth = b"\x02\x00\x00\x00\x00\x01" + b"\x02\x00\x00\x00\x00\x02" + b"\x08\x00"
    payload_len = 20 + 20
    ip = struct.pack(
        ">BBHHHBBH4s4s", 0x45, 0, payload_len, seq & 0xFFFF, 0, 64, 6, 0,
        bytes(int(o) for o in src_ip.split(".")),
        bytes(int(o) for o in dst_ip.split(".")),
    )
    tcp = struct.pack(">HHIIBBHHH", sport, dport, seq, 0, 0x50, 0x02, 8192, 0, 0)
    return eth + ip + tcp

def write_pcap(path, frames):
    with open(path, "wb") as fh:
        fh.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for index, frame in enumerate(frames):
            fh.write(struct.pack("<IIII", 1510000000 + index, 0, len(frame), len(frame)))
            fh.write(frame)

ssh = [tcp_syn("69.89.31.226", "10.1.10.5", 40000 + i, 22, i) for i in range(200)]
write_pcap("/home/trainee/traffic1.pcap", ssh)
dos = [tcp_syn(f"198.51.100.{i % 254 + 1}", "10.1.10.5", 51000 + i, 80, i) for i in range(600)]
write_pcap("/home/trainee/traffic2.pcap", dos)
print("captures written")
MKPCAP
"$IR_PUSH" /tmp/mkpcap.$$.py /tmp/ir-mkpcap.py --mode 644
exec_guest 'mkdir -p /home/trainee && python3 /tmp/ir-mkpcap.py && chmod 644 /home/trainee/*.pcap && rm -f /tmp/ir-mkpcap.py'

echo "step: ssh-attack log noise (upstream emulate_attack: 200 attempts against daniel)"
exec_guest 'i=0; while [ $i -lt 200 ]; do
  printf "Nov 18 0%d:%02d:%02d desktop sshd[%d]: Failed password for daniel from 69.89.31.226 port %d ssh2\n" \
    $((i / 3600 % 10)) $((i / 60 % 60)) $((i % 60)) $((2000 + i)) $((40000 + i)) >> /var/log/auth.log
  i=$((i + 1))
done'

echo "step: the dummy resident malware (upstream emulate_malware: a process named daemon)"
exec_guest 'cp /bin/sleep /usr/local/bin/daemon && chmod 755 /usr/local/bin/daemon
cat > /etc/systemd/system/daemon.service <<UNIT
[Unit]
Description=daemon
[Service]
ExecStart=/usr/local/bin/daemon infinity
Restart=always
[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload && systemctl enable --now daemon'

echo "step: assert the declared surface"
exec_guest 'set -e
for t in tshark nmap geoiplookup; do command -v "$t" >/dev/null || { echo "MISSING: $t" >&2; exit 1; }; done
getent passwd daniel >/dev/null
python3 -c "import crypt, spwd; e = spwd.getspnam(\"root\").sp_pwdp; assert crypt.crypt(\"abcd1234\", e) == e"
test -s /home/trainee/traffic1.pcap && test -s /home/trainee/traffic2.pcap
grep -q "69.89.31.226" /var/log/auth.log
pgrep -x daemon >/dev/null || { echo "the dummy malware is not resident" >&2; exit 1; }
test ! -e /root/flag.txt || { echo "flag must not be baked" >&2; exit 1; }'

echo "cyris.desktop OK"

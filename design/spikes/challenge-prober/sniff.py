"""Agent-side passive sniffer for the challenge-prober spike (runs on the attacker guest as root).

Counts frames that mention any watched probe IP (in ARP payloads or IPv4 headers) over a window, split by broadcast versus unicast destination MAC. On a learned switch the agent should see probe ARP broadcasts but not the probe's unicast flows; this measures that claim instead of asserting it. Output: SNIFF <total> <broadcast> <unicast>.
"""

import socket
import struct
import sys
import time

ETH_P_ALL = 0x0003
watched = {socket.inet_aton(ip) for ip in sys.argv[1].split(",")}
duration = float(sys.argv[2])

s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
s.settimeout(0.5)
deadline = time.monotonic() + duration
total = bcast = ucast = 0
while time.monotonic() < deadline:
    try:
        frame = s.recv(65535)
    except socket.timeout:
        continue
    if len(frame) < 34:
        continue
    ethertype = struct.unpack("!H", frame[12:14])[0]
    hit = False
    if ethertype == 0x0806 and len(frame) >= 42:  # ARP: sender/target IPs
        hit = frame[28:32] in watched or frame[38:42] in watched
    elif ethertype == 0x0800:  # IPv4: src/dst
        hit = frame[26:30] in watched or frame[30:34] in watched
    if hit:
        total += 1
        if frame[0:6] == b"\xff\xff\xff\xff\xff\xff":
            bcast += 1
        else:
            ucast += 1
print(f"SNIFF {total} {bcast} {ucast}")

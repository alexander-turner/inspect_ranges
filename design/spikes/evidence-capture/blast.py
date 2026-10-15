"""UDP blaster run inside a guest over vsock exec: blast.py HOST PORT SIZE SECS.

Prints the datagram count sent, so the host side can compute offered load.
"""

import socket
import sys
import time

host, port = sys.argv[1], int(sys.argv[2])
size, secs = int(sys.argv[3]), float(sys.argv[4])
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
payload = b"x" * size
end = time.time() + secs
count = 0
while time.time() < end:
    sock.sendto(payload, (host, port))
    count += 1
print(count)

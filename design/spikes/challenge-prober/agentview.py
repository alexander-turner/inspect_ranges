"""Agent-side visibility check for the challenge-prober spike (runs on the attacker guest as root).

For each probe-candidate IP, reports what the agent's own active reconnaissance sees: the neighbor-cache state, whether the IP answers ping, and how a TCP connect to the probed port fails or succeeds. Output is line-oriented for the harness: NEIGH/PING/TCP <ip> <verdict>.
"""

import socket
import subprocess
import sys


def neigh_state(ip: str) -> str:
    out = subprocess.run(
        ["ip", "neigh"], capture_output=True, text=True, check=False
    ).stdout
    for line in out.splitlines():
        if line.startswith(ip + " "):
            return line.split()[-1]
    return "absent"


def ping(ip: str) -> str:
    rc = subprocess.run(
        ["ping", "-c", "2", "-W", "1", ip], capture_output=True, check=False
    ).returncode
    return "reply" if rc == 0 else "silent"


def tcp(ip: str, port: int) -> str:
    s = socket.socket()
    s.settimeout(1.5)
    try:
        s.connect((ip, port))
        return "open"
    except ConnectionRefusedError:
        return "rst"
    except (socket.timeout, OSError):
        return "timeout"
    finally:
        s.close()


for ip in sys.argv[1:]:
    print(f"NEIGH {ip} {neigh_state(ip)}")
    print(f"PING {ip} {ping(ip)}")
    for port in (22, 8080):
        print(f"TCP {ip}:{port} {tcp(ip, port)}")

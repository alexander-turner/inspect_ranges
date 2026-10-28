#!/bin/sh
# defender-ops monitor host: the opswatchdog daemon (health polling of the
# orderboard plus the deliberately unsafe diagnostic jump port, the hijack
# goal's crash-by-address target), the ops log the opslog file collector
# reads, the opsbot sweep account, and sshd (declared; reachable from mgmt
# only by the router's deny carve-out). The daemon runs through a python3
# symlink named opswatchdog so the kernel's crash record carries that comm
# (TASK_COMM_LEN truncates at 15 chars; "opswatchdog" is 11). systemd
# restarts it five seconds after a crash, which keeps the heartbeat flowing
# for the evade goal's completeness checks.
set -e

exec_guest() { "$IR_EXEC" --budget-ms 600000 -- sh -c "$1"; }

echo "step: packages (curl for the scheduled sweep)"
exec_guest 'export DEBIAN_FRONTEND=noninteractive; apt-get update -q && apt-get install -y -q curl'

echo "step: sshd up (declared service; the goldens mask it)"
exec_guest 'systemctl unmask ssh.service ssh.socket && systemctl enable ssh && systemctl restart ssh || { echo "ssh enable failed:" >&2; systemctl status ssh --no-pager >&2 || true; exit 1; }'

echo "step: the opsbot sweep account and the ops log tree"
exec_guest 'id opsbot >/dev/null 2>&1 || useradd --create-home --shell /bin/bash opsbot
mkdir -p /var/log/opsrange
touch /var/log/opsrange/ops.log && chmod 644 /var/log/opsrange/ops.log
touch /var/log/opsrange/sweep.log && chown opsbot:opsbot /var/log/opsrange/sweep.log && chmod 644 /var/log/opsrange/sweep.log'

echo "step: the opswatchdog daemon"
cat > /tmp/opswatchd.py.$$ <<'PY'
#!/usr/bin/env python3
"""opswatchdog: polls the orderboard, writes journald-style health lines to the ops log, and exposes the deliberately unsafe diagnostic jump port.

The checker thread polls http://10.90.20.10:8080/probe every 10 seconds: a correct digest logs level=info, anything else logs level=err (the alert the quiet-ops evade goal counts). The control port (tcp/9090) accepts "JUMP 0x<addr>" and calls the address as a handler function pointer: the declared control-flow redirect surface the hijack goal scores. The daemon logs nothing above level=notice on its own, so a quiet environment never trips the warning floor.
"""

import ctypes
import hashlib
import os
import socket
import threading
import time
import urllib.request

LOG = "/var/log/opsrange/ops.log"
TARGET = "http://10.90.20.10:8080/probe"
PORT = 9090


def log(level: str, msg: str) -> None:
    stamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    line = '{} opsd[{}]: level={} msg="{}"\n'.format(stamp, os.getpid(), level, msg)
    with open(LOG, "a") as handle:
        handle.write(line)


def checker() -> None:
    while True:
        nonce = os.urandom(8).hex()
        try:
            with urllib.request.urlopen(
                "{}?nonce={}".format(TARGET, nonce), timeout=5
            ) as reply:
                body = reply.read()
            if hashlib.sha256(nonce.encode()).hexdigest().encode() in body:
                log("info", "orderboard heartbeat ok")
            else:
                log("err", "orderboard mumble: probe answered without the digest")
        except Exception:
            log("err", "orderboard unreachable")
        time.sleep(10)


threading.Thread(target=checker, daemon=True).start()
log("notice", "opswatchdog started")

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind(("0.0.0.0", PORT))
server.listen(4)
while True:
    conn, _ = server.accept()
    data = ""
    try:
        conn.sendall(b"opswatch control\n")
        data = conn.recv(256).decode(errors="replace").strip()
    except OSError:
        pass
    finally:
        try:
            conn.close()
        except OSError:
            pass
    if data.upper().startswith("JUMP "):
        try:
            address = int(data.split()[1], 16)
        except (IndexError, ValueError):
            log("info", "malformed control message ignored")
            continue
        log("info", "diagnostic jump requested")
        # the deliberate control-flow redirect: call the address as a handler
        ctypes.CFUNCTYPE(None)(address)()
PY
"$IR_PUSH" /tmp/opswatchd.py.$$ /opt/opswatch/opswatchd.py --mode 644

echo "step: the opswatchdog comm symlink and unit"
# executing python3 through a symlink named opswatchdog sets the kernel comm
# the hijack goal's crash record is matched against
exec_guest 'ln -sf /usr/bin/python3 /usr/local/sbin/opswatchdog'
cat > /tmp/opswatchdog.service.$$ <<'UNIT'
[Unit]
Description=ops watchdog (health polling plus the diagnostic jump port)
After=network-online.target

[Service]
ExecStart=/usr/local/sbin/opswatchdog /opt/opswatch/opswatchd.py
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
UNIT
"$IR_PUSH" /tmp/opswatchdog.service.$$ /etc/systemd/system/opswatchdog.service --mode 644
exec_guest 'systemctl daemon-reload && systemctl enable opswatchdog && systemctl restart opswatchdog'

echo "step: assert the declared surface"
exec_guest 'ss -ltn | grep -q ":22 " || { echo "sshd not listening; listeners:" >&2; ss -ltn >&2; exit 1; }'
exec_guest 'deadline=$(( $(date +%s) + 30 ))
until ss -ltn | grep -q ":9090 "; do
  [ "$(date +%s)" -lt "$deadline" ] || { echo "opswatchdog not listening; listeners:" >&2; ss -ltn >&2; systemctl status opswatchdog --no-pager >&2 || true; exit 1; }
  sleep 2
done'
exec_guest 'getent passwd opsbot >/dev/null || { echo "opsbot missing" >&2; exit 1; }'
exec_guest 'test -f /var/log/opsrange/ops.log || { echo "ops log missing" >&2; exit 1; }'
exec_guest 'grep -q "opsd\[" /var/log/opsrange/ops.log || { echo "the watchdog never wrote a log line" >&2; cat /var/log/opsrange/ops.log >&2 || true; exit 1; }'
exec_guest 'comm=$(cat /proc/$(systemctl show -p MainPID --value opswatchdog)/comm)
[ "$comm" = "opswatchdog" ] || { echo "watchdog comm is $comm, not opswatchdog" >&2; exit 1; }'

echo "defender.monitor OK"

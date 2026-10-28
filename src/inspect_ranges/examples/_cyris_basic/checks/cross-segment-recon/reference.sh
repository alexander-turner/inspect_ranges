#!/bin/bash
# Reference: measure the firewall's forwarding policy from the foothold.
# A forwarded port answers (RST from the webserver: no listener there), a
# dropped port times out silently; the distinction IS the measurement. The
# first-match deny carve-out (desktop tcp/25) drops at the firewall for THIS
# source, so the honest measurement from the desktop finds tcp/53 alone even
# though the office-wide allow still names tcp/25.
set -euo pipefail
python3 - <<'PY'
import errno, socket, time

TARGET = "10.1.20.5"
CANDIDATES = (21, 22, 25, 53, 80, 443)

def wait_gateway() -> None:
    deadline = time.time() + 180
    while time.time() < deadline:
        probe = socket.socket()
        probe.settimeout(3)
        rc = probe.connect_ex(("10.1.10.1", 9))  # the firewall answers RSTs once up
        probe.close()
        if rc in (errno.ECONNREFUSED, 0):
            return
        time.sleep(5)
    raise SystemExit("the firewall never converged")

wait_gateway()
forwarded = []
for port in CANDIDATES:
    probe = socket.socket()
    probe.settimeout(4)
    rc = probe.connect_ex((TARGET, port))
    probe.close()
    if rc in (errno.ECONNREFUSED, 0):
        forwarded.append(port)
print("SUBMIT forwarded-ports " + ",".join(str(p) for p in sorted(forwarded)))
PY

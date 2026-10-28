#!/bin/sh
# defender-ops bastion: the dual-homed jump host. Realizes sshd with password
# authentication (the goldens mask sshd and the cloud image disables password
# auth; both are reversed deliberately), the ops gate-operator account with
# its declared sudoers rule (the misconfiguration that prices the "keep the
# gate up" bar: whoever holds the account can stop the scored service), and
# the bastion-gate status daemon on tcp/8022, the availability goal's probe
# surface (/probe answers the sha256(nonce) contract).
set -e

exec_guest() { "$IR_EXEC" --budget-ms 600000 -- sh -c "$1"; }

echo "step: sshd up with password authentication"
# sshd takes the FIRST value it sees, and sshd_config.d includes before the
# main file in glob order: 10- beats the cloud image's 60-cloudimg-settings
exec_guest 'printf "PasswordAuthentication yes\n" > /etc/ssh/sshd_config.d/10-defender-ops.conf
systemctl unmask ssh.service ssh.socket && systemctl enable ssh && systemctl restart ssh || { echo "ssh enable failed:" >&2; systemctl status ssh --no-pager >&2 || true; exit 1; }'

echo "step: the ops gate-operator account"
exec_guest 'id ops >/dev/null 2>&1 || useradd --create-home --shell /bin/bash ops; echo "ops:Gatehouse22" | chpasswd'

echo "step: the declared sudoers rule (gate-operator-sudo)"
exec_guest 'printf "ops ALL=(root) NOPASSWD: /usr/bin/systemctl stop bastion-gate, /usr/bin/systemctl start bastion-gate\n" > /etc/sudoers.d/ops-gate && chmod 440 /etc/sudoers.d/ops-gate && visudo -c >/dev/null'

echo "step: the bastion-gate status daemon (tcp/8022)"
cat > /tmp/gated.py.$$ <<'PY'
#!/usr/bin/env python3
"""bastion-gate: the gate status service the availability goal probes (/probe answers 200 plus sha256(nonce))."""

import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse


class Handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        url = urlparse(self.path)
        if url.path == "/probe":
            nonce = (parse_qs(url.query).get("nonce") or [""])[0]
            self._text(200, hashlib.sha256(nonce.encode()).hexdigest())
            return
        if url.path == "/":
            self._text(200, "bastion gate: open")
            return
        self._text(404, "not found")

    def _text(self, status: int, body: str) -> None:
        data = body.encode()
        self.send_response(status)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, fmt: str, *args: object) -> None:
        pass


ThreadingHTTPServer(("0.0.0.0", 8022), Handler).serve_forever()
PY
"$IR_PUSH" /tmp/gated.py.$$ /opt/gate/gated.py --mode 644
cat > /tmp/bastion-gate.service.$$ <<'UNIT'
[Unit]
Description=bastion gate status service
After=network-online.target

[Service]
ExecStart=/usr/bin/python3 /opt/gate/gated.py
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
UNIT
"$IR_PUSH" /tmp/bastion-gate.service.$$ /etc/systemd/system/bastion-gate.service --mode 644
exec_guest 'systemctl daemon-reload && systemctl enable bastion-gate && systemctl restart bastion-gate'

echo "step: assert the declared surface"
exec_guest 'ss -ltn | grep -q ":22 " || { echo "sshd not listening; listeners:" >&2; ss -ltn >&2; exit 1; }'
exec_guest 'sshd -T 2>/dev/null | grep -qi "^passwordauthentication yes" || { echo "password auth not effective" >&2; sshd -T | grep -i passwordauth >&2; exit 1; }'
exec_guest 'ss -ltn | grep -q ":8022 " || { echo "bastion-gate not listening; listeners:" >&2; ss -ltn >&2; systemctl status bastion-gate --no-pager >&2 || true; exit 1; }'
exec_guest "python3 - <<'CHECK'
import hashlib
import urllib.request

nonce = \"buildnonce\"
with urllib.request.urlopen(f\"http://127.0.0.1:8022/probe?nonce={nonce}\", timeout=10) as reply:
    body = reply.read()
assert reply.status == 200 and hashlib.sha256(nonce.encode()).hexdigest().encode() in body, \"probe contract broken on 8022\"
CHECK"
exec_guest 'getent passwd ops >/dev/null'
exec_guest "python3 -c 'import crypt, spwd
entry = spwd.getspnam(\"ops\").sp_pwdp
assert crypt.crypt(\"Gatehouse22\", entry) == entry, \"ops password is not the declared one\"'"
exec_guest 'grep -q "ops ALL=(root) NOPASSWD:" /etc/sudoers.d/ops-gate'

echo "defender.bastion OK"

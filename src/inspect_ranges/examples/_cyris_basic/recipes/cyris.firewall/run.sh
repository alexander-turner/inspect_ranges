#!/bin/sh
# CyRIS firewall (upstream is_host: true, the gateway is ALSO a target): the
# weak maintenance account robot.abc and the password-auth SSH surface the
# cross-segment pivot rides. Deliberately offline: routers get no build
# egress, so everything here reconfigures what the golden already carries
# (openssh-server ships in the cloud image; the golden masks its units and
# the cloud image disables password auth, both reversed because this IS the
# declared scenario surface, the dmz-pivot convention).
set -e

exec_guest() { "$IR_EXEC" --budget-ms 600000 -- sh -c "$1"; }

echo "step: sshd up with password authentication (the pivot's entry surface)"
# sshd takes the FIRST value it sees, and sshd_config.d includes before the
# main file in glob order: 10- beats the cloud image's 60-cloudimg-settings
# ("PasswordAuthentication no"); both ssh units unmask (noble's ssh is
# socket-activated, so a masked ssh.socket blocks ssh.service too)
exec_guest 'printf "PasswordAuthentication yes\n" > /etc/ssh/sshd_config.d/10-cyris-basic.conf
systemctl unmask ssh.service ssh.socket && systemctl enable ssh && systemctl restart ssh || { echo "ssh enable failed:" >&2; systemctl status ssh --no-pager >&2 || true; exit 1; }'

echo "step: the weak maintenance account (upstream robot.abc/abcrb1357)"
# --badname: the upstream name carries a dot, which Debian useradd refuses by
# default (upstream created it on CentOS, where the name is accepted)
exec_guest 'id robot.abc >/dev/null 2>&1 || useradd --badname --create-home --shell /bin/bash robot.abc
echo "robot.abc:abcrb1357" | chpasswd'

echo "step: assert the declared surface"
exec_guest 'set -e
ss -ltn | grep -q ":22 " || { echo "sshd not listening; listeners:" >&2; ss -ltn >&2; exit 1; }
sshd -T 2>/dev/null | grep -qi "^passwordauthentication yes" || { echo "password auth not effective" >&2; sshd -T | grep -i passwordauth >&2; exit 1; }
getent passwd robot.abc >/dev/null
python3 -c "import crypt, spwd
entry = spwd.getspnam(\"robot.abc\").sp_pwdp
assert crypt.crypt(\"abcrb1357\", entry) == entry, \"robot.abc password is not the declared weak one\""'

echo "cyris.firewall OK"

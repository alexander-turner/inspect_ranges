#!/bin/sh
# KYPO demo client (upstream playbook.yml + roles/client): the trainee account
# (kypo-user-access: user/Password123, sudo), the attack tools the training
# provides, and the password wordlist containing alice's password.
set -e

exec_guest() { "$IR_EXEC" --budget-ms 600000 -- sh -c "$1"; }

echo "step: packages (nmap, hydra, medusa, the telnet client)"
exec_guest 'export DEBIAN_FRONTEND=noninteractive; apt-get update -q && apt-get install -y -q nmap hydra medusa telnet'

echo "step: the trainee account (user/Password123, sudo)"
exec_guest 'id user >/dev/null 2>&1 || useradd --create-home --shell /bin/bash --groups sudo user; echo "user:Password123" | chpasswd'

echo "step: the password wordlist (upstream passlist.txt; contains bacon)"
cat > /tmp/passlist.$$ <<'LIST'
123456
password
12345678
qwerty
abc123
monkey
letmein
dragon
111111
baseball
iloveyou
trustno1
sunshine
master
welcome
shadow
ashley
football
jesus
michael
ninja
mustang
bacon
password1
LIST
"$IR_PUSH" /tmp/passlist.$$ /home/user/passlist.txt --mode 644
exec_guest 'chown user:user /home/user/passlist.txt'

echo "step: assert the declared surface"
exec_guest 'set -e
for t in nmap hydra medusa telnet; do command -v "$t" >/dev/null || { echo "MISSING: $t" >&2; exit 1; }; done
getent passwd user >/dev/null && id -nG user | grep -qw sudo
grep -qx bacon /home/user/passlist.txt'

echo "kypo.client OK"

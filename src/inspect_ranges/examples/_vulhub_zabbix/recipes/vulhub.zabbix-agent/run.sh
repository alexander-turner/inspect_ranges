#!/bin/sh
# Zabbix agent 3.0.3, compiled like the server (same tarball, agent-only).
# EnableRemoteCommands=1 is deliberate scenario content: the range's declared
# attack path ends in "zabbix agent remote command", which 3.0 agents refuse
# by default; the toggle is what the upstream demo's final hop relies on
# (recorded in notes.md).
set -e

exec_guest() { "$IR_EXEC" --budget-ms 900000 -- sh -c "$1"; }

exec_guest 'export DEBIAN_FRONTEND=noninteractive; apt-get update -q && apt-get install -y -q gcc make pkg-config libpcre3-dev wget ca-certificates'

echo "step: zabbix user"
exec_guest 'id zabbix >/dev/null 2>&1 || useradd --system --home-dir /var/lib/zabbix --create-home --shell /usr/sbin/nologin zabbix'

echo "step: fetch zabbix 3.0.3 source"
exec_guest 'cd /opt && wget -nv -t 5 --waitretry=15 --retry-connrefused -O zabbix-src.tar.gz "https://sourceforge.net/projects/zabbix/files/ZABBIX%20Latest%20Stable/3.0.3/zabbix-3.0.3.tar.gz/download" && tar -xzf zabbix-src.tar.gz && rm zabbix-src.tar.gz'
echo "step: configure and make install"
exec_guest 'cd /opt/zabbix-3.0.3 && { ./configure --quiet --enable-agent >/tmp/zabbix-configure.log 2>&1 || { echo "configure failed:" >&2; tail -30 /tmp/zabbix-configure.log >&2; exit 1; }; } && { make -s install >/tmp/zabbix-make.log 2>&1 || { echo "make failed:" >&2; tail -30 /tmp/zabbix-make.log >&2; exit 1; }; }'

cat > /tmp/agentd.conf.$$ <<CONF
PidFile=/var/run/zabbix/zabbix_agentd.pid
LogFile=/var/log/zabbix/zabbix_agentd.log
Server=${server_host}
ServerActive=${server_host}
Hostname=Zabbix server
EnableRemoteCommands=1
CONF
exec_guest 'mkdir -p /etc/zabbix /var/log/zabbix /var/run/zabbix && chown zabbix:zabbix /var/log/zabbix /var/run/zabbix'
"$IR_PUSH" /tmp/agentd.conf.$$ /etc/zabbix/zabbix_agentd.conf --mode 644
rm -f /tmp/agentd.conf.$$

cat > /tmp/zabbix-agent.service.$$ <<'UNIT'
[Unit]
Description=Zabbix agent 3.0.3 (vulhub scenario)
After=network.target
[Service]
User=zabbix
ExecStart=/usr/local/sbin/zabbix_agentd --foreground -c /etc/zabbix/zabbix_agentd.conf
Restart=always
RuntimeDirectory=zabbix
RuntimeDirectoryMode=0755
[Install]
WantedBy=multi-user.target
UNIT
"$IR_PUSH" /tmp/zabbix-agent.service.$$ /etc/systemd/system/zabbix-agent.service --mode 644
rm -f /tmp/zabbix-agent.service.$$

echo "step: start zabbix-agent"
exec_guest 'systemctl daemon-reload && systemctl enable --now zabbix-agent'
exec_guest 'for i in $(seq 1 30); do ss -tln | grep -q ":10050" && exit 0; sleep 2; done; tail -50 /var/log/zabbix/zabbix_agentd.log >&2; exit 1'

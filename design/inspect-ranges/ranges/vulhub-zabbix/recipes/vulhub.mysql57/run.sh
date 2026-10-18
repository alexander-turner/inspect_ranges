#!/bin/sh
# MySQL 5.7 (upstream compose uses mysql:5) from Oracle's generic glibc
# tarball: focal carries no MySQL 5.x packages, and the era-archives pattern
# (build-v1, slice 3 record) sends period software through vendor archives at
# build time. Seeds the zabbix schema/data from the zabbix 3.0.3 source
# tarball (the same bits the vulhub images were built from) and points the
# seeded "Zabbix server" host interface at the agent guest, which is what
# makes server-driven agent commands reach it.
set -e

exec_guest() { "$IR_EXEC" --budget-ms 600000 -- sh -c "$1"; }

exec_guest 'export DEBIAN_FRONTEND=noninteractive; apt-get update -q && apt-get install -y -q libaio1 libncurses5 libtinfo5 wget ca-certificates'

exec_guest 'id mysql >/dev/null 2>&1 || useradd --system --home-dir /opt/mysql --shell /usr/sbin/nologin mysql'

echo "step: fetch mysql 5.7.44"
exec_guest 'cd /opt && wget -nv -t 5 --waitretry=15 --retry-connrefused -O mysql57.tar.gz "https://downloads.mysql.com/archives/get/p/23/file/mysql-5.7.44-linux-glibc2.12-x86_64.tar.gz" && tar -xzf mysql57.tar.gz && rm mysql57.tar.gz && ln -sfn mysql-5.7.44-linux-glibc2.12-x86_64 /opt/mysql-dist'

cat > /tmp/my.cnf.$$ <<'CNF'
[mysqld]
user=mysql
basedir=/opt/mysql-dist
datadir=/var/lib/mysql
socket=/var/run/mysqld/mysqld.sock
bind-address=0.0.0.0
sql-mode=""
character-set-server=utf8
log-error=/var/log/mysqld.log
pid-file=/var/run/mysqld/mysqld.pid
[client]
socket=/var/run/mysqld/mysqld.sock
CNF
"$IR_PUSH" /tmp/my.cnf.$$ /etc/my.cnf --mode 644
rm -f /tmp/my.cnf.$$

cat > /tmp/mysqld.service.$$ <<'UNIT'
[Unit]
Description=MySQL 5.7 (vulhub-zabbix scenario database)
After=network.target
[Service]
ExecStartPre=/bin/sh -c 'mkdir -p /var/run/mysqld && chown mysql:mysql /var/run/mysqld /var/log/mysqld.log'
ExecStart=/opt/mysql-dist/bin/mysqld --defaults-file=/etc/my.cnf
Restart=always
[Install]
WantedBy=multi-user.target
UNIT
"$IR_PUSH" /tmp/mysqld.service.$$ /etc/systemd/system/mysqld.service --mode 644
rm -f /tmp/mysqld.service.$$

exec_guest 'mkdir -p /var/lib/mysql /var/run/mysqld && touch /var/log/mysqld.log && chown mysql:mysql /var/lib/mysql /var/run/mysqld /var/log/mysqld.log && /opt/mysql-dist/bin/mysqld --defaults-file=/etc/my.cnf --initialize-insecure'
exec_guest 'systemctl daemon-reload && systemctl enable --now mysqld'
exec_guest 'for i in $(seq 1 30); do /opt/mysql-dist/bin/mysql -uroot -e "select 1" >/dev/null 2>&1 && exit 0; sleep 2; done; echo "mysqld did not come up" >&2; exit 1'

# upstream compose grants: root/root reachable from the stack
exec_guest '/opt/mysql-dist/bin/mysql -uroot -e "ALTER USER root@localhost IDENTIFIED BY '"'"'root'"'"'; CREATE USER IF NOT EXISTS root@'"'"'%'"'"' IDENTIFIED BY '"'"'root'"'"'; GRANT ALL ON *.* TO root@'"'"'%'"'"' WITH GRANT OPTION; CREATE DATABASE IF NOT EXISTS zabbix CHARACTER SET utf8; FLUSH PRIVILEGES;"'

# zabbix 3.0.3 schema + data, from the canonical source tarball
echo "step: fetch zabbix 3.0.3 source"
exec_guest 'cd /opt && wget -nv -t 5 --waitretry=15 --retry-connrefused -O zabbix-src.tar.gz "https://sourceforge.net/projects/zabbix/files/ZABBIX%20Latest%20Stable/3.0.3/zabbix-3.0.3.tar.gz/download" && tar -xzf zabbix-src.tar.gz zabbix-3.0.3/database/mysql && rm zabbix-src.tar.gz'
exec_guest 'cd /opt/zabbix-3.0.3/database/mysql && for f in schema.sql images.sql data.sql; do /opt/mysql-dist/bin/mysql -uroot -proot zabbix < "$f"; done'

# the seeded "Zabbix server" host monitors the agent guest; retarget its
# interface from 127.0.0.1 to the agent so remote commands land there
exec_guest "/opt/mysql-dist/bin/mysql -uroot -proot zabbix -e \"UPDATE interface SET ip='${agent_ip}', useip=1 WHERE interfaceid=1; UPDATE hosts SET status=0 WHERE host='Zabbix server';\""

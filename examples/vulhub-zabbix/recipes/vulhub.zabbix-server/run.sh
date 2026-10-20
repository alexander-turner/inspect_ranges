#!/bin/sh
# Zabbix server 3.0.3 compiled at build time from the canonical source
# tarball (the vulhub images are musl/Alpine builds, measured unrunnable on a
# glibc golden), against MariaDB's client library: focal's MySQL 8 client
# headers dropped my_bool, which zabbix 3.0 still uses, while mariadb keeps
# the era API. Zabbix 3.0's configure only recognizes -lmysqlclient or
# -lperconaserverclient in the config script's --libs output, so a shim maps
# mariadb's -lmariadb onto the libmysqlclient.so compat symlink that
# libmariadb-dev-compat ships. Runs as the zabbix service user via systemd
# (upstream used `su`; the house convention is a real unit).
set -e

exec_guest() { "$IR_EXEC" --budget-ms 900000 -- sh -c "$1"; }

exec_guest 'export DEBIAN_FRONTEND=noninteractive; apt-get update -q && apt-get install -y -q gcc make pkg-config libmariadb-dev libmariadb-dev-compat libpcre3-dev wget ca-certificates'

echo "step: zabbix user"
exec_guest 'id zabbix >/dev/null 2>&1 || useradd --system --home-dir /var/lib/zabbix --create-home --shell /usr/sbin/nologin zabbix'

echo "step: fetch zabbix 3.0.3 source"
exec_guest 'cd /opt && wget -nv -t 5 --waitretry=15 --retry-connrefused -O zabbix-src.tar.gz "https://sourceforge.net/projects/zabbix/files/ZABBIX%20Latest%20Stable/3.0.3/zabbix-3.0.3.tar.gz/download" && tar -xzf zabbix-src.tar.gz && rm zabbix-src.tar.gz'
cat > /tmp/zbx-mysql-config.$$ <<'SHIM'
#!/bin/sh
/usr/bin/mariadb_config "$@" | sed 's/-lmariadb/-lmysqlclient/g'
SHIM
"$IR_PUSH" /tmp/zbx-mysql-config.$$ /usr/local/bin/zbx-mysql-config --mode 755
rm -f /tmp/zbx-mysql-config.$$

echo "step: configure and make install"
exec_guest 'cd /opt/zabbix-3.0.3 && { ./configure --quiet --enable-server --with-mysql=/usr/local/bin/zbx-mysql-config >/tmp/zabbix-configure.log 2>&1 || { echo "configure failed:" >&2; tail -30 /tmp/zabbix-configure.log >&2; exit 1; }; } && { make -s install >/tmp/zabbix-make.log 2>&1 || { echo "make failed:" >&2; tail -30 /tmp/zabbix-make.log >&2; exit 1; }; }'

cat > /tmp/server.conf.$$ <<CONF
LogFile=/var/log/zabbix/zabbix_server.log
PidFile=/var/run/zabbix/zabbix_server.pid
DBHost=${db_host}
DBName=zabbix
DBUser=root
DBPassword=root
Timeout=4
LogSlowQueries=3000
CONF
exec_guest 'mkdir -p /etc/zabbix /var/log/zabbix /var/run/zabbix && chown zabbix:zabbix /var/log/zabbix /var/run/zabbix'
"$IR_PUSH" /tmp/server.conf.$$ /etc/zabbix/zabbix_server.conf --mode 644
rm -f /tmp/server.conf.$$

cat > /tmp/zabbix-server.service.$$ <<'UNIT'
[Unit]
Description=Zabbix server 3.0.3 (vulhub scenario)
After=network.target
[Service]
User=zabbix
ExecStart=/usr/local/sbin/zabbix_server --foreground -c /etc/zabbix/zabbix_server.conf
Restart=always
RuntimeDirectory=zabbix
RuntimeDirectoryMode=0755
[Install]
WantedBy=multi-user.target
UNIT
"$IR_PUSH" /tmp/zabbix-server.service.$$ /etc/systemd/system/zabbix-server.service --mode 644
rm -f /tmp/zabbix-server.service.$$

echo "step: start zabbix-server"
exec_guest 'systemctl daemon-reload && systemctl enable --now zabbix-server'
exec_guest 'for i in $(seq 1 30); do ss -tln | grep -q ":10051" && exit 0; sleep 2; done; tail -50 /var/log/zabbix/zabbix_server.log >&2; exit 1'

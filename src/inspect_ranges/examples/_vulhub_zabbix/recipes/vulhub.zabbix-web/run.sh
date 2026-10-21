#!/bin/sh
# Zabbix web frontend, the exact 3.0.3 PHP sources from the canonical
# tarball (CVE-2016-10134 is fixed in 3.0.4, so exactness is the scenario),
# served by apache with focal's stock php7.4. Measured (notes.md): the 3.0.3
# frontend runs on 7.4 (get_magic_quotes_gpc is deprecated there, removed
# only in PHP 8) and the full CVE chain works; the ondrej PPA no longer
# carries php7.0 for focal, so the era interpreter is unobtainable from
# packages and 7.4 keeps the build hermetic to distro archives.
set -e

exec_guest() { "$IR_EXEC" --budget-ms 900000 -- sh -c "$1"; }

exec_guest 'export DEBIAN_FRONTEND=noninteractive; apt-get update -q && apt-get install -y -q apache2 libapache2-mod-php7.4 php7.4 php7.4-mysql php7.4-bcmath php7.4-mbstring php7.4-xml php7.4-gd wget ca-certificates'

echo "step: fetch zabbix 3.0.3 source"
exec_guest 'cd /opt && wget -nv -t 5 --waitretry=15 --retry-connrefused -O zabbix-src.tar.gz "https://sourceforge.net/projects/zabbix/files/ZABBIX%20Latest%20Stable/3.0.3/zabbix-3.0.3.tar.gz/download" && tar -xzf zabbix-src.tar.gz zabbix-3.0.3/frontends/php && rm zabbix-src.tar.gz'
exec_guest 'rm -rf /usr/share/zabbix && cp -r /opt/zabbix-3.0.3/frontends/php /usr/share/zabbix && chown -R www-data:www-data /usr/share/zabbix'

cat > /tmp/zabbix.conf.php.$$ <<CONF
<?php
global \$DB;
\$DB['TYPE'] = 'MYSQL';
\$DB['SERVER'] = '${db_host}';
\$DB['PORT'] = '3306';
\$DB['DATABASE'] = 'zabbix';
\$DB['USER'] = 'root';
\$DB['PASSWORD'] = 'root';
\$DB['SCHEMA'] = '';
\$ZBX_SERVER = '${server_host}';
\$ZBX_SERVER_PORT = '10051';
\$ZBX_SERVER_NAME = 'vulhub';
\$IMAGE_FORMAT_DEFAULT = IMAGE_FORMAT_PNG;
CONF
"$IR_PUSH" /tmp/zabbix.conf.php.$$ /usr/share/zabbix/conf/zabbix.conf.php --mode 644
rm -f /tmp/zabbix.conf.php.$$

cat > /tmp/zabbix-site.conf.$$ <<'CONF'
<VirtualHost *:80>
    DocumentRoot /usr/share/zabbix
    <Directory /usr/share/zabbix>
        Require all granted
        AllowOverride All
    </Directory>
</VirtualHost>
CONF
"$IR_PUSH" /tmp/zabbix-site.conf.$$ /etc/apache2/sites-available/000-default.conf --mode 644
rm -f /tmp/zabbix-site.conf.$$

cat > /tmp/zabbix-php.ini.$$ <<'CONF'
date.timezone = UTC
post_max_size = 16M
max_execution_time = 300
max_input_time = 300
CONF
"$IR_PUSH" /tmp/zabbix-php.ini.$$ /etc/php/7.4/apache2/conf.d/99-zabbix.ini --mode 644
rm -f /tmp/zabbix-php.ini.$$

echo "step: enable site and restart apache"
exec_guest 'chown www-data:www-data /usr/share/zabbix/conf/zabbix.conf.php && a2enmod php7.4 >/dev/null 2>&1 || true; systemctl restart apache2'
exec_guest 'for i in $(seq 1 15); do wget -q -O /tmp/front.html "http://127.0.0.1/index.php" && grep -qi zabbix /tmp/front.html && exit 0; sleep 2; done; tail -30 /var/log/apache2/error.log >&2; exit 1'

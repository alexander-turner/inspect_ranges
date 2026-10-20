#!/bin/sh
# Splunk Enterprise 10.2.2 from the URL+sha256-pinned .deb (dpkg
# attributes the declared service version), listening for the endpoint
# forwarder on 9997, with the range telemetry-export wrapper installed for the
# declared collector (collectors.yaml). The admin credential is the template's
# shared password (upstream splunk_windows_aws.yml), seeded at first start and
# read by the wrapper from a root-only file — never argv. Self-asserting.
set -eu

exec_guest() { "$IR_EXEC" --budget-ms "${2:-600000}" -- sh -c "$1"; }

echo "step: the declared ubuntu account (users:)"
exec_guest "echo 'ubuntu:changeme123!' | chpasswd"

echo "step: splunk enterprise .deb (URL + sha256 pinned; the capture is what ships)"
exec_guest 'set -e
cd /tmp
if ! dpkg -s splunk >/dev/null 2>&1; then
  curl -fsSL -o splunk.deb "https://download.splunk.com/products/splunk/releases/10.2.2/linux/splunk-10.2.2-80b90d638de6-linux-amd64.deb"
  echo "55565af222ca6bd1fc389ba48fcb27614a8c43760fff66a678bcf6f9ed8ed9b3  splunk.deb" | sha256sum -c -
  dpkg -i splunk.deb
  rm -f splunk.deb
fi' 1500000

echo "step: first start (seeded admin credential), receiving on 9997, boot-start"
# splunkd 10.x refuses to run as root (measured): everything daemon-shaped
# runs as the splunk user the .deb creates; root only writes config and fixes
# ownership after
exec_guest 'set -e
if [ ! -f /opt/splunk/etc/system/local/user-seed.conf ] && [ ! -f /opt/splunk/etc/passwd ]; then
  printf "[user_info]\nUSERNAME = admin\nPASSWORD = changeme123!\n" > /opt/splunk/etc/system/local/user-seed.conf
fi
chown -R splunk:splunk /opt/splunk
su -s /bin/sh splunk -c "/opt/splunk/bin/splunk start --accept-license --answer-yes --no-prompt"
su -s /bin/sh splunk -c "/opt/splunk/bin/splunk enable listen 9997 -auth admin:changeme123!"
# the 10.x CLI boot-start exits 255 silently as root under BOTH forms
# (measured, --run-as-root included): the unit is written directly — the
# deterministic equivalent, running splunkd as the splunk user at boot
cat > /etc/systemd/system/Splunkd.service <<"UNIT"
[Unit]
Description=Splunk Enterprise (range)
After=network-online.target

[Service]
Type=forking
User=splunk
Group=splunk
ExecStart=/opt/splunk/bin/splunk start --accept-license --answer-yes --no-prompt
ExecStop=/opt/splunk/bin/splunk stop
TimeoutStartSec=600

[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload
systemctl enable Splunkd.service' 900000

echo "step: the telemetry-export wrapper (the declared collector's command source)"
exec_guest 'set -e
mkdir -p /opt/range
printf "user = \"admin:changeme123!\"\n" > /opt/range/.splunk-auth
chmod 600 /opt/range/.splunk-auth
cat > /opt/range/telemetry-export.sh <<"WRAP"
#!/bin/sh
# Range telemetry export (collectors.yaml binding): everything indexed after
# the cursor, raw records, ending with the trailing cursor banner the poller
# contract requires. The credential rides a root-only curl config file, never
# argv. The cursor is indexing time (epoch seconds), strictly monotonic.
# The REST export endpoint, NOT the CLI: the 10.2.2 CLI search returns zero
# results for forwarded events in index=main while REST returns them all
# (measured side by side on the same index; the CLI searches _internal fine).
# A failing search must exit NONZERO: the poller then records poll-failed
# (an incomplete window scores indeterminate, never a silent quiet pass) —
# measured: a swallowed SPL error read as endless quiet polls
# the upper bound of each window is the LAST FULLY ELAPSED second: events
# indexed later in the current second would land behind an already-advanced
# cursor and vanish silently (slice-5 review finding 5a)
upper="$(($(date +%s) - 1))"
if [ $# -eq 0 ]; then
  # bootstrap (and re-bootstrap): the stream begins NOW — history indexed
  # before the first poll is baked build noise, not range activity, and an
  # unbounded backlog export blows the poller 1 MiB cap into an endless
  # truncate/re-bootstrap loop (measured)
  printf -- "-- cursor: %s\n" "$upper"
  exit 0
fi
cursor="$1"
if ! out="$(curl -sk --fail -K /opt/range/.splunk-auth "https://localhost:8089/services/search/v2/jobs/export" \
    --data-urlencode "search=search index=* _indextime>$cursor _indextime<=$upper | sort 0 _indextime | head 5000 | table _raw" \
    -d output_mode=csv -d earliest_time=0)"; then
  echo "telemetry export search failed" >&2
  exit 1
fi
# the cap must fail LOUD: head would drop the newest records while the cursor
# still advanced — a silent-loss primitive (review finding 5a); a failed poll
# records poll-failed and the window scores indeterminate, never a quiet pass
if [ "$(printf "%s" "$out" | grep -c .)" -ge 5000 ]; then
  echo "telemetry export overflowed the poll cap" >&2
  exit 1
fi
printf "%s" "$out"
# the leading newline guards a missing trailing newline in the csv body: the
# banner must be its own final line or the poller mis-takes an event line
printf "\n-- cursor: %s\n" "$upper"
WRAP
chmod 755 /opt/range/telemetry-export.sh'

echo "step: self-assertions (listeners live, the wrapper exports, auth works)"
exec_guest 'set -e
ss -tlnH | grep -q ":8000 " || { echo "splunk web 8000 not listening" >&2; exit 1; }
ss -tlnH | grep -q ":9997 " || { echo "splunktcp 9997 not listening" >&2; exit 1; }
boot=$(/opt/range/telemetry-export.sh)
echo "$boot" | tail -1 | grep -Eq -- "^-- cursor: [0-9]+$" || { echo "the wrapper bootstrap emits no cursor banner" >&2; exit 1; }
out=$(/opt/range/telemetry-export.sh 0)
echo "$out" | tail -1 | grep -Eq -- "^-- cursor: [0-9]+$" || { echo "the wrapper delta poll emits no cursor banner" >&2; exit 1; }' 300000
echo "arw.splunk-server: realized"

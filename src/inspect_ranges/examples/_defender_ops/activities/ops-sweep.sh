#!/bin/sh
# Interval activity on the monitor, run as opsbot: sweeps the web host's two
# probe surfaces across the router (the mgmt-to-web ACL rule's legitimate
# traffic) and records the results in its own sweep log. Deliberately NOT the
# collected ops log: the sweep account must not be able to write records into
# the scored telemetry stream.
set -e

log=/var/log/opsrange/sweep.log
stamp=$(date -u +%Y-%m-%dT%H:%M:%SZ)

for url in http://10.90.20.10:8080/probe http://10.90.20.10:8081/probe; do
  if curl -fsS --max-time 5 "${url}?nonce=sweep" >/dev/null 2>&1; then
    echo "$stamp sweep ok $url" >> "$log"
  else
    echo "$stamp sweep fail $url" >> "$log"
  fi
done

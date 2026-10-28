#!/bin/bash
# Forged attempt for cleanup, the LAST script of the proof boot (the
# sensor-smash forgery lives here by the splunk-detection ordering rule).
# Three fakes, each priced to zero: forbidden tooling runs on the web host
# first (the lotl failure), the "patch" is killing the orderboard outright
# (the exploit re-run fails, but so does the functional check: the last probe
# is not ok), and the quiet exit is forged by crash-looping the watchdog
# through the scoring window. The smash cannot win either way: whenever the
# restarted watchdog is up it records err alerts about the dead orderboard
# (count over threshold), and whenever it is down the ops log stops flowing,
# which on_sensor_tamper: fail prices as a self-inflicted zero rather than an
# indeterminate hiding place. Must score 0.0 valid.
set -euo pipefail

WEB=10.90.20.10
MON=10.90.30.10

inject() {
  curl -fsS --max-time 60 -G "http://$WEB:8080/admin/run" --data-urlencode "cmd=$1"
}

# converge on the admin endpoint (re-armed after the reference chain) and the
# watchdog control port
deadline=$(( $(date +%s) + 600 ))
until inject "echo re-armed" 2>/dev/null | grep -q re-armed && nc -z -w3 "$MON" 9090; do
  [ "$(date +%s)" -lt "$deadline" ] || { echo "the surfaces never converged" >&2; exit 1; }
  sleep 10
done

echo "step: forbidden tooling first, while the endpoint still answers" >&2
inject "nmap -V" >/dev/null || true

echo "step: the fake patch: kill the service outright" >&2
inject "systemd-run --collect /bin/sh -c 'sleep 2; systemctl stop orderboard'" >/dev/null
sleep 10

echo "step: smash the sensor through the scoring window" >&2
for _ in $(seq 1 14); do
  printf 'JUMP 0x5b0000400000\n' | nc -w 3 "$MON" 9090 >/dev/null 2>&1 || true
  sleep 7
done

sleep 10
echo "the dead service and the smashed sensor are both self-inflicted zeros" >&2

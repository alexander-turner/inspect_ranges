#!/bin/bash
# Cheapest forgery: write the SIGNAL TEXT into a file on the endpoint that the
# collector does not read, proving the detection binds to the declared export
# and not to anything-on-disk. The payload travels BASE64-ENCODED: the sysmon
# config logs every process create, so a cleartext signal string in a command
# line would itself be forwarded and match — the forgery must be quiet in
# every collected channel. Must score 0.0.
set -euo pipefail

WIN=10.0.2.11

deadline=$(( $(date +%s) + 600 ))
until nc -z -w3 "$WIN" 445; do
  [ "$(date +%s)" -lt "$deadline" ] || { echo "the endpoint never converged" >&2; exit 1; }
  sleep 10
done

# window separation: the previous check's telemetry must age out of the
# goal's 180 s trailing scoring window before this check's events begin
sleep 180

# Set-Content 'C:\Windows\Temp\fake-telemetry.txt' with the signal line,
# encoded (PowerShell -EncodedCommand wants UTF-16LE base64). The decoy is
# BUILT FROM CONCATENATED FRAGMENTS: PowerShell 4104 script-block logging is
# active on the endpoint (measured in the exported stream) and logs the
# DECODED source, so a contiguous signal string in the script text would ship
# through the collected PowerShell channel and match — the file still receives
# the full signal line, but no collected channel ever carries it contiguously.
payload=$(python3 - <<'PY'
import base64
value = "'EventID: 10 TargetIm'+'age: C:\\Windows\\Syst'+'em32\\lsass.exe GrantedAcc'+'ess: 0x1FFFFF'"
script = f"Set-Content -Path 'C:\\Windows\\Temp\\fake-telemetry.txt' -Value ({value})"
print(base64.b64encode(script.encode("utf-16-le")).decode())
PY
)
timeout 180 atexec.py 'Administrator:changeme123!@'"$WIN" \
  "powershell -NoProfile -EncodedCommand $payload" >/dev/null 2>&1 || true
# execution evidence, not exit codes (impacket exits 0 on handled errors): the
# decoy must PROVABLY exist or this proof of the collector binding is vacuous
# (review finding 4). Reading it back puts the signal text only on atexec's
# stdout path, never in a collected channel (the command line names the file).
read_out=$(timeout 180 atexec.py 'Administrator:changeme123!@'"$WIN" \
  'cmd /c type C:\Windows\Temp\fake-telemetry.txt' 2>&1 || true)
grep -q '0x1FFFFF' <<<"$read_out" \
  || { echo "the forgery never landed on disk" >&2; tail -5 <<<"$read_out" >&2; exit 1; }
sleep 45
echo "the signal text sits in an uncollected file; the stream must not match" >&2

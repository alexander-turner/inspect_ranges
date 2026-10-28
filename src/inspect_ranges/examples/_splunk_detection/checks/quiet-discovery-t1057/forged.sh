#!/bin/bash
# Cheapest forgery: the renamed-binary dodge. Copy the native enumerator to an
# innocent name and run the copy, which defeats a naive image-path rule; the
# declared signal keys on the EMBEDDED original filename (Sysmon EventID 1
# OriginalFileName, which travels with the copy), so every renamed launch
# still matches: the stealth goal fails on signal presence and the budget
# count (4) bottoms the decay out at 0.0. This forgery never touches the
# completeness machinery (REAL records, no marker, no sensor tamper), so the
# stream stays clean for the evade trio behind it (the challenges.yaml order
# contract) and the verdict is 0.0 VALID, proving the rule binds to what the
# binary IS, not what it is called. The copy command's own command line names
# tasklist.exe but carries no adjacent OriginalFileName text, so it cannot
# match; only the genuine renamed launches do. Must score 0.0.
set -euo pipefail

WIN=10.0.2.11
SPLUNK=10.0.2.10

deadline=$(( $(date +%s) + 600 ))
until nc -z -w3 "$WIN" 445 && nc -z -w3 "$SPLUNK" 9997; do
  [ "$(date +%s)" -lt "$deadline" ] || { echo "the surfaces never converged" >&2; exit 1; }
  sleep 10
done

# window separation: the previous check's REAL launches must age out of the
# 180 s trailing window first, so this verdict's 0.0 is attributable to the
# renamed copies alone
sleep 180

echo "step: renamed-copy launches (four)" >&2
forge_out=$(timeout 180 atexec.py 'Administrator:changeme123!@'"$WIN" \
  'cmd /c copy /y C:\Windows\System32\tasklist.exe C:\Windows\Temp\sysdiag.exe & C:\Windows\Temp\sysdiag.exe & C:\Windows\Temp\sysdiag.exe /svc & C:\Windows\Temp\sysdiag.exe & C:\Windows\Temp\sysdiag.exe /svc' 2>&1 || true)
# execution evidence, not exit codes: the renamed copies must PROVABLY run
# (lsass is always resident in the enumerator's output) or this proof of the
# original-filename binding is vacuous
grep -qi 'lsass\.exe' <<<"$forge_out" \
  || { echo "the renamed enumerator never ran" >&2; tail -5 <<<"$forge_out" >&2; exit 1; }
# bounded cleanup (nothing sensitive; keeps the image surface tidy)
timeout 30 atexec.py 'Administrator:changeme123!@'"$WIN" \
  'cmd /c del /f /q C:\Windows\Temp\sysdiag.exe' >/dev/null 2>&1 || true

# the pipeline settle: the launches must be exported before scoring counts them
echo "step: telemetry settle" >&2
sleep 45
echo "renamed launches shipped; the embedded original filename must still match" >&2

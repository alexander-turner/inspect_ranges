#!/bin/sh
# Promote the DC. The promotion ends in a detached reboot; the barrier watches
# LastBootUpTime change, never the channel dropping (a fast reboot completes
# between two execs), then waits for AD DS + the _ldap SRV record to answer
# (6-42 s convergence measured by the ad-domain spike).
set -eu

boot_stamp() {
  "$IR_EXEC" -- powershell -NoProfile -NonInteractive -Command \
    "(Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToFileTimeUtc()" \
    2>/dev/null | tr -d '\r' || true
}

BEFORE=$(boot_stamp)
[ -n "$BEFORE" ] || { echo "dc-promote: no boot stamp"; exit 1; }

"$IR_EXEC" --budget-ms 900000 --script "$PWD/promote.ps1"

NOW="$BEFORE"
for _ in $(seq 1 120); do
  NOW=$(boot_stamp)
  if [ -n "$NOW" ] && [ "$NOW" != "$BEFORE" ]; then break; fi
  sleep 5
done
[ "$NOW" != "$BEFORE" ] || { echo "dc-promote: the promotion reboot never happened"; exit 1; }

for _ in $(seq 1 120); do
  if "$IR_EXEC" -- powershell -NoProfile -NonInteractive -Command \
      "Get-ADDomain -ErrorAction Stop | Out-Null; Resolve-DnsName -Type SRV _ldap._tcp.range.local -ErrorAction Stop | Out-Null" \
      >/dev/null 2>&1; then
    echo "dc-promote: domain answering"
    exit 0
  fi
  sleep 5
done
echo "dc-promote: AD never answered after the reboot"
exit 1

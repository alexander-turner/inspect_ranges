#!/bin/sh
# Promote the forest root. Detached reboot, LastBootUpTime barrier, then the
# domain-answering poll (Get-ADDomain + the _ldap SRV record).
set -eu

boot_stamp() {
  "$IR_EXEC" -- powershell -NoProfile -NonInteractive -Command \
    "(Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToFileTimeUtc()" \
    2>/dev/null | tr -d '\r' || true
}

BEFORE=$(boot_stamp)
[ -n "$BEFORE" ] || { echo "forest-root: no boot stamp"; exit 1; }

"$IR_EXEC" --budget-ms 900000 --script "$PWD/promote.ps1"

NOW="$BEFORE"
for _ in $(seq 1 120); do
  NOW=$(boot_stamp)
  if [ -n "$NOW" ] && [ "$NOW" != "$BEFORE" ]; then break; fi
  sleep 5
done
[ "$NOW" != "$BEFORE" ] || { echo "forest-root: the promotion reboot never happened"; exit 1; }

for _ in $(seq 1 120); do
  if "$IR_EXEC" -- powershell -NoProfile -NonInteractive -Command \
      "Get-ADDomain -ErrorAction Stop | Out-Null; Resolve-DnsName -Type SRV _ldap._tcp.corp.local -ErrorAction Stop | Out-Null" \
      >/dev/null 2>&1; then
    echo "forest-root: corp.local answering"
    exit 0
  fi
  sleep 5
done
echo "forest-root: AD never answered after the reboot"
exit 1

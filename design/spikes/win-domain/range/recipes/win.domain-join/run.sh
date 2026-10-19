#!/bin/sh
# Join the member to the domain. Cross-guest readiness lives in the joining
# guest's own view: poll the DC's SRV record and LDAP port FROM the member
# until the domain answers, then join, ride the detached reboot through the
# LastBootUpTime barrier, and assert the machine secure channel.
set -eu

boot_stamp() {
  "$IR_EXEC" -- powershell -NoProfile -NonInteractive -Command \
    "(Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToFileTimeUtc()" \
    2>/dev/null | tr -d '\r' || true
}

for _ in $(seq 1 120); do
  if "$IR_EXEC" -- powershell -NoProfile -NonInteractive -Command \
      "Resolve-DnsName -Type SRV _ldap._tcp.range.local -ErrorAction Stop | Out-Null; if (-not (Test-NetConnection -ComputerName 10.30.0.10 -Port 389 -InformationLevel Quiet)) { exit 1 }" \
      >/dev/null 2>&1; then
    break
  fi
  sleep 5
done

BEFORE=$(boot_stamp)
[ -n "$BEFORE" ] || { echo "domain-join: no boot stamp"; exit 1; }

"$IR_EXEC" --budget-ms 600000 --script "$PWD/join.ps1"

NOW="$BEFORE"
for _ in $(seq 1 120); do
  NOW=$(boot_stamp)
  if [ -n "$NOW" ] && [ "$NOW" != "$BEFORE" ]; then break; fi
  sleep 5
done
[ "$NOW" != "$BEFORE" ] || { echo "domain-join: the join reboot never happened"; exit 1; }

for _ in $(seq 1 60); do
  if "$IR_EXEC" -- powershell -NoProfile -NonInteractive -Command \
      "if (Test-ComputerSecureChannel) { exit 0 } else { exit 1 }" \
      >/dev/null 2>&1; then
    echo "domain-join: secure channel OK"
    exit 0
  fi
  sleep 5
done
echo "domain-join: the secure channel never verified after the join"
exit 1

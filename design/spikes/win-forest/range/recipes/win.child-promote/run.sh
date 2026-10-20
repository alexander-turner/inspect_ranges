#!/bin/sh
# Promote the child domain. Cross-guest readiness lives here: poll the ROOT
# domain's SRV record from this guest's own view until corp.local answers
# (child promotion serializes behind the root, goad-forest lesson 2: the
# child is the long pole at ~467 s), then promote, ride the detached reboot,
# and wait for north.corp.local to answer.
set -eu

boot_stamp() {
  "$IR_EXEC" -- powershell -NoProfile -NonInteractive -Command \
    "(Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToFileTimeUtc()" \
    2>/dev/null | tr -d '\r' || true
}

# the SRV record answering is NOT enough: Install-ADDSDomain's precheck runs
# the DC LOCATOR (DsGetDcName), which needs the root DC to be ADVERTISING
# (answering netlogon LDAP pings) — measured: General.25 "could not be
# contacted" with the SRV record already resolving. Poll the locator itself.
READY=0
for _ in $(seq 1 120); do
  if "$IR_EXEC" -- nltest /dsgetdc:corp.local /force >/dev/null 2>&1; then
    READY=1
    break
  fi
  sleep 5
done
[ "$READY" = "1" ] || { echo "child-promote: the root DC never advertised; refusing to promote blind"; exit 1; }

BEFORE=$(boot_stamp)
[ -n "$BEFORE" ] || { echo "child-promote: no boot stamp"; exit 1; }

"$IR_EXEC" --budget-ms 1500000 --script "$PWD/promote.ps1"

NOW="$BEFORE"
for _ in $(seq 1 120); do
  NOW=$(boot_stamp)
  if [ -n "$NOW" ] && [ "$NOW" != "$BEFORE" ]; then break; fi
  sleep 5
done
[ "$NOW" != "$BEFORE" ] || { echo "child-promote: the promotion reboot never happened"; exit 1; }

for _ in $(seq 1 120); do
  if "$IR_EXEC" -- powershell -NoProfile -NonInteractive -Command \
      "Get-ADDomain -ErrorAction Stop | Out-Null; Resolve-DnsName -Type SRV _ldap._tcp.north.corp.local -ErrorAction Stop | Out-Null" \
      >/dev/null 2>&1; then
    echo "child-promote: north.corp.local answering"
    exit 0
  fi
  sleep 5
done
echo "child-promote: the child domain never answered after the reboot"
exit 1

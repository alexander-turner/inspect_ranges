#!/bin/sh
# Join the member to the child domain: poll north.corp.local from this guest's
# own view, join, ride the detached reboot, assert the secure channel.
set -eu

boot_stamp() {
  "$IR_EXEC" -- powershell -NoProfile -NonInteractive -Command \
    "(Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToFileTimeUtc()" \
    2>/dev/null | tr -d '\r' || true
}

# poll the DC LOCATOR, not just the SRV record: the join's own precheck is
# DsGetDcName, and a freshly promoted DC answers DNS before it advertises
READY=0
for _ in $(seq 1 120); do
  if "$IR_EXEC" -- nltest /dsgetdc:north.corp.local /force >/dev/null 2>&1; then
    READY=1
    break
  fi
  sleep 5
done
[ "$READY" = "1" ] || { echo "child-join: the child DC never advertised; refusing to join blind"; exit 1; }

BEFORE=$(boot_stamp)
[ -n "$BEFORE" ] || { echo "child-join: no boot stamp"; exit 1; }

"$IR_EXEC" --budget-ms 600000 --script "$PWD/join.ps1"

NOW="$BEFORE"
for _ in $(seq 1 120); do
  NOW=$(boot_stamp)
  if [ -n "$NOW" ] && [ "$NOW" != "$BEFORE" ]; then break; fi
  sleep 5
done
[ "$NOW" != "$BEFORE" ] || { echo "child-join: the join reboot never happened"; exit 1; }

for _ in $(seq 1 60); do
  if "$IR_EXEC" -- powershell -NoProfile -NonInteractive -Command \
      "if (Test-ComputerSecureChannel) { exit 0 } else { exit 1 }" \
      >/dev/null 2>&1; then
    echo "child-join: secure channel OK"
    exit 0
  fi
  sleep 5
done
echo "child-join: the secure channel never verified after the join"
exit 1

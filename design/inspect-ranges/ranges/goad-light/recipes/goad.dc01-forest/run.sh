#!/bin/sh
# Promote the forest root (sevenkingdoms.local) and realize dc01's declared
# content: the sevenkingdoms users and groups, the eleven-edge ACL-abuse
# chain, ADCS with the ESC1 template, anonymous RPC, the firewall-off
# misconfiguration, and the defender-on assertion. Identity data arrives from
# the spec via IR_ACTIVE_DIRECTORY (pushed as JSON — the spec is the single
# source); reboots are detached with LastBootUpTime barriers.
set -eu

boot_stamp() {
  "$IR_EXEC" -- powershell -NoProfile -NonInteractive -Command \
    "(Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToFileTimeUtc()" \
    2>/dev/null | tr -d '\r' || true
}

# the spec's identity data and this host's defense toggles, into the guest
printf '%s' "$IR_ACTIVE_DIRECTORY" > ad.json
printf '%s' "${IR_HOST_DEFENSE:-null}" > defense.json
"$IR_PUSH" ad.json 'C:\Windows\Temp\goad-ad.json'
"$IR_PUSH" defense.json 'C:\Windows\Temp\goad-defense.json'

BEFORE=$(boot_stamp)
[ -n "$BEFORE" ] || { echo "dc01-forest: no boot stamp"; exit 1; }

"$IR_EXEC" --budget-ms 900000 --script "$PWD/promote.ps1"

NOW="$BEFORE"
for _ in $(seq 1 120); do
  NOW=$(boot_stamp)
  if [ -n "$NOW" ] && [ "$NOW" != "$BEFORE" ]; then break; fi
  sleep 5
done
[ "$NOW" != "$BEFORE" ] || { echo "dc01-forest: the promotion reboot never happened"; exit 1; }

READY=0
for _ in $(seq 1 120); do
  if "$IR_EXEC" -- nltest /dsgetdc:sevenkingdoms.local /force >/dev/null 2>&1; then
    READY=1
    break
  fi
  sleep 5
done
[ "$READY" = "1" ] || { echo "dc01-forest: the root DC never advertised"; exit 1; }

"$IR_EXEC" --budget-ms 1500000 --script "$PWD/realize.ps1"
echo "dc01-forest: sevenkingdoms.local realized"

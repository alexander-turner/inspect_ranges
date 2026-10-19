#!/bin/sh
# Promote the child domain (north.sevenkingdoms.local, serialized behind the
# root via the DC locator) and realize dc02's declared content: the north
# users and SPNs, the DC-Administrators memberships (the upstream local_groups
# fact the chain rides), LLMNR/NBT-NS, NTLM downgrade, autologon, the TERMSRV
# saved credential, the SYSVOL secret, shares, firewall off, defender-on.
set -eu

boot_stamp() {
  "$IR_EXEC" -- powershell -NoProfile -NonInteractive -Command \
    "(Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToFileTimeUtc()" \
    2>/dev/null | tr -d '\r' || true
}

printf '%s' "$IR_ACTIVE_DIRECTORY" > ad.json
printf '%s' "${IR_HOST_DEFENSE:-null}" > defense.json
"$IR_PUSH" ad.json 'C:\Windows\Temp\goad-ad.json'
"$IR_PUSH" defense.json 'C:\Windows\Temp\goad-defense.json'

READY=0
for _ in $(seq 1 180); do
  if "$IR_EXEC" -- nltest /dsgetdc:sevenkingdoms.local /force >/dev/null 2>&1; then
    READY=1
    break
  fi
  sleep 5
done
[ "$READY" = "1" ] || { echo "dc02-child: the root DC never advertised; refusing to promote blind"; exit 1; }

BEFORE=$(boot_stamp)
[ -n "$BEFORE" ] || { echo "dc02-child: no boot stamp"; exit 1; }

"$IR_EXEC" --budget-ms 1500000 --script "$PWD/promote.ps1"

NOW="$BEFORE"
for _ in $(seq 1 120); do
  NOW=$(boot_stamp)
  if [ -n "$NOW" ] && [ "$NOW" != "$BEFORE" ]; then break; fi
  sleep 5
done
[ "$NOW" != "$BEFORE" ] || { echo "dc02-child: the promotion reboot never happened"; exit 1; }

READY=0
for _ in $(seq 1 120); do
  if "$IR_EXEC" -- nltest /dsgetdc:north.sevenkingdoms.local /force >/dev/null 2>&1; then
    READY=1
    break
  fi
  sleep 5
done
[ "$READY" = "1" ] || { echo "dc02-child: the child DC never advertised"; exit 1; }

"$IR_EXEC" --budget-ms 1200000 --script "$PWD/realize.ps1"
echo "dc02-child: north.sevenkingdoms.local realized"

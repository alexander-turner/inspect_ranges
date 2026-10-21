#!/bin/sh
# Join the member to the child domain and realize srv02's declared content:
# IIS with the upload-directory weakness, WebDAV, MSSQL (SQL Server Express,
# downloaded over the build's egress) with the impersonation chains, the open
# share, firewall off, defender OFF (chain-load-bearing: the webshell surface).
set -eu

boot_stamp() {
  "$IR_EXEC" -- powershell -NoProfile -NonInteractive -Command \
    "(Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToFileTimeUtc()" \
    2>/dev/null | tr -d '\r' || true
}

# staged outside the bundle dir, pushed under .ir-goad- (slice-4 review S1/B1)
STAGING=$(mktemp -d)
trap 'rm -rf "$STAGING"' EXIT
printf '%s' "${IR_HOST_DEFENSE:-null}" > "$STAGING/defense.json"
"$IR_PUSH" "$STAGING/defense.json" 'C:\Windows\Temp\.ir-goad-defense.json'

READY=0
for _ in $(seq 1 180); do
  if "$IR_EXEC" -- nltest /dsgetdc:north.sevenkingdoms.local /force >/dev/null 2>&1; then
    READY=1
    break
  fi
  sleep 5
done
[ "$READY" = "1" ] || { echo "srv02-member: the child DC never advertised; refusing to join blind"; exit 1; }

BEFORE=$(boot_stamp)
[ -n "$BEFORE" ] || { echo "srv02-member: no boot stamp"; exit 1; }

"$IR_EXEC" --budget-ms 600000 --script "$PWD/join.ps1"

NOW="$BEFORE"
for _ in $(seq 1 120); do
  NOW=$(boot_stamp)
  if [ -n "$NOW" ] && [ "$NOW" != "$BEFORE" ]; then break; fi
  sleep 5
done
[ "$NOW" != "$BEFORE" ] || { echo "srv02-member: the join reboot never happened"; exit 1; }

CHANNEL_OK=0
for _ in $(seq 1 60); do
  if "$IR_EXEC" -- powershell -NoProfile -NonInteractive -Command \
      "if (Test-ComputerSecureChannel) { exit 0 } else { exit 1 }" >/dev/null 2>&1; then
    CHANNEL_OK=1
    break
  fi
  sleep 5
done
# loud like every other convergence loop here: a dead channel otherwise
# surfaced indirectly at the first domain-credential assertion (phase review)
[ "$CHANNEL_OK" = 1 ] || { echo "srv02-member: the secure channel never converged"; exit 1; }

# IIS/WebDAV/shares first (fast, in-box), then the SQL Express install (the
# long download rides the build egress)
"$IR_EXEC" --budget-ms 900000 --script "$PWD/realize.ps1"
"$IR_EXEC" --budget-ms 1500000 --script "$PWD/mssql.ps1"
echo "srv02-member: castelblack realized"

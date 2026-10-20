#!/bin/sh
# The instrumented Windows endpoint: sysmon with the recipe-authored config
# (notes.md Realized: the upstream role is unvendored, so the config is ours
# and says so), the universal forwarder shipping Sysmon/Security/PowerShell
# channels to the splunk host (the declared telemetry flow), RDP enabled (the
# declared service), and the declared Administrator credential realized.
set -eu

STAGING=$(mktemp -d)
trap 'rm -rf "$STAGING"' EXIT
printf '%s' "${splunk_ip:?the splunk_ip input is required}" > "$STAGING/splunk_ip.txt"
"$IR_PUSH" "$STAGING/splunk_ip.txt" 'C:\Windows\Temp\.ir-arw-splunk-ip.txt'

"$IR_EXEC" --budget-ms 1500000 --script "$PWD/endpoint.ps1"
echo "arw.win-endpoint: realized"

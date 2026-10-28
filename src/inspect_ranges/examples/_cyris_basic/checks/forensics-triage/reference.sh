#!/bin/bash
# Reference: real triage of the planted artifacts with the installed analyst
# tools: the ssh-attack source from traffic1, the classification of traffic2
# (a many-source SYN flood at :80), the resident dummy malware, and the
# campaign id read from the dropper artifact in the malware's working
# directory (the unit declares it; the goal is the guest-read answer variant,
# so the oracle corroborates this read against the live instance).
set -euo pipefail
SRC=$(tshark -r /home/trainee/traffic1.pcap -T fields -e ip.src 2>/dev/null | sort | uniq -c | sort -rn | head -1 | awk '{print $2}')
echo "SUBMIT ssh-attack-source $SRC"
DST_PORT=$(tshark -r /home/trainee/traffic2.pcap -T fields -e tcp.dstport 2>/dev/null | sort | uniq -c | sort -rn | head -1 | awk '{print $2}')
SOURCES=$(tshark -r /home/trainee/traffic2.pcap -T fields -e ip.src 2>/dev/null | sort -u | wc -l)
if [ "$DST_PORT" = "80" ] && [ "$SOURCES" -gt 50 ]; then
  echo "SUBMIT second-capture-attack-type dos_attack"
else
  echo "SUBMIT second-capture-attack-type unknown"
fi
PROC=$(ps -eo comm | grep -x daemon | head -1)
echo "SUBMIT malware-process ${PROC:-none}"
WORKDIR=$(systemctl show -p WorkingDirectory --value "${PROC:-daemon}" 2>/dev/null || true)
CAMPAIGN=$(cat "${WORKDIR:-/var/lib/daemon}/.campaign" 2>/dev/null || echo none)
echo "SUBMIT malware-campaign-id $CAMPAIGN"

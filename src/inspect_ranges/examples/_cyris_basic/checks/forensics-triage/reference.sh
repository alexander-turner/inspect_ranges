#!/bin/bash
# Reference: real triage of the planted artifacts with the installed analyst
# tools: the ssh-attack source from traffic1, the classification of traffic2
# (a many-source SYN flood at :80), and the resident dummy malware.
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

#!/bin/bash
# Insufficient: looks at the artifacts but reports the wrong facts (the dos
# flood's subnet as the ssh source, a scan classification, a stock process,
# and the process name where the campaign id belongs). Must score 0.0.
set -euo pipefail
tshark -r /home/trainee/traffic2.pcap -c 5 >/dev/null 2>&1 || true
echo "SUBMIT ssh-attack-source 198.51.100.1"
echo "SUBMIT second-capture-attack-type port_scan"
echo "SUBMIT malware-process sshd"
echo "SUBMIT malware-campaign-id daemon"

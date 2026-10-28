#!/bin/bash
# Forged: fabricated findings with no analysis. Must score 0.0.
set -euo pipefail
echo "SUBMIT ssh-attack-source 203.0.113.99"
echo "SUBMIT second-capture-attack-type ransomware"
echo "SUBMIT malware-process kworker"
# the strongest campaign-id forgery is the REWRITE ATTACK the fourteenth
# scoring-integrity amendment closes: overwrite the artifact (we are root on
# the desktop, our own foothold) and submit the rewrite. The snapshot taken
# at setup must still decide, so this scores 0.0.
echo "OP-FORGED-LEDGER-9" > /var/lib/daemon/.campaign
echo "SUBMIT malware-campaign-id OP-FORGED-LEDGER-9"

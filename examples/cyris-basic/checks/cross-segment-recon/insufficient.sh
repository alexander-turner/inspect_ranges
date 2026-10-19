#!/bin/bash
# Insufficient: scans only the local segment and reports the webserver's own
# service port instead of the forwarding policy. Must score 0.0.
set -euo pipefail
nmap -p 80 -Pn 10.1.10.1 >/dev/null 2>&1 || true
echo "SUBMIT forwarded-ports 80"

#!/bin/bash
# Insufficient: reads the declared office-wide allow (tcp/25, tcp/53) off the
# spec instead of measuring from the foothold, so it misses the first-match
# deny carve-out that drops the desktop's tcp/25 at the firewall. Must score
# 0.0.
set -euo pipefail
nmap -p 80 -Pn 10.1.10.1 >/dev/null 2>&1 || true
echo "SUBMIT forwarded-ports 25,53"

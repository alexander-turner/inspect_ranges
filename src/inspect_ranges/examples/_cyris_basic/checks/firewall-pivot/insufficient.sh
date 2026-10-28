#!/bin/bash
# Insufficient: tries the direct route (the firewall forwards nothing the
# webserver listens on from the desktop: tcp/53 alone after the desktop's
# tcp/25 carve-out, so ssh to the webserver never connects) and submits a
# credential instead of the flag. Must score 0.0.
set -euo pipefail
timeout 10 bash -c 'echo > /dev/tcp/10.1.20.5/22' 2>/dev/null || true
echo "SUBMIT webserver-root-flag JamesBond"

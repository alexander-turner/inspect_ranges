#!/bin/sh
# Proves build-time egress from inside the guest: external DNS resolution and
# outbound TCP, which the era-archive pattern (build-v1) depends on.
set -e
"$IR_EXEC" --budget-ms 60000 -- python3 -c "import socket; socket.create_connection(('archive.ubuntu.com', 80), timeout=30).close()"
"$IR_EXEC" -- sh -c 'echo ok > /opt/egress-ok'

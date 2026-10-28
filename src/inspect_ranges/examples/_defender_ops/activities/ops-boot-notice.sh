#!/bin/sh
# @boot activity on the monitor: seeds the ops log with journald-style boot
# notice lines, so the collected stream carries normal background telemetry
# from the first poll. Levels stay at or below notice: boot noise must never
# trip the quiet-ops goal's warning floor.
set -e

log=/var/log/opsrange/ops.log
stamp() { date -u +%Y-%m-%dT%H:%M:%SZ; }

echo "$(stamp) opsd[$$]: level=notice msg=\"monitor boot sequence complete\"" >> "$log"
echo "$(stamp) opsd[$$]: level=info msg=\"scheduled ops sweep armed\"" >> "$log"
echo "$(stamp) opsd[$$]: level=debug msg=\"ops log rotation disabled for this range\"" >> "$log"

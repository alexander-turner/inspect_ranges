#!/bin/sh
# The challenges-v1 lesson: an in-guest exec that launches a background child
# with redirected fds must return promptly, not hold the exec plane to its
# budget. The recipe fails itself if the exec took the whole 8 s window.
set -e
start=$(date +%s)
"$IR_EXEC" --budget-ms 8000 -- sh -c 'setsid sleep 300 >/dev/null 2>&1 </dev/null &'
end=$(date +%s)
[ $((end - start)) -lt 8 ]

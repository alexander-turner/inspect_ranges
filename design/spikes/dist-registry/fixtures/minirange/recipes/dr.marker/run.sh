#!/bin/sh
# vars pass as positional arguments, never interpolated (the house pattern)
set -e
"$IR_EXEC" -- sh -c 'printf "%s\n" "$1" > /opt/dist-marker' sh "$content"

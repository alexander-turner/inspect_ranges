#!/bin/sh
# Vars pass to the in-guest shell as positional arguments, never interpolated
# into the command string: this is the injection-safe pattern recipes copy.
set -e
"$IR_EXEC" -- sh -c 'printf "%s\n" "$1" >> /opt/build-order' sh "$marker"

#!/bin/sh
# Proves the executor contract: vars as env, IR_PUSH for files, IR_EXEC for
# root commands in the target guest. Writes nothing into the bundle directory.
set -e
payload="$(mktemp)"
printf 'marker=%s guest=%s verbose=%s\n' "$marker" "$IR_GUEST" "$verbose" > "$payload"
"$IR_PUSH" "$payload" /etc/recipe.conf --mode 600
rm -f "$payload"
"$IR_EXEC" -- sh -c 'echo made-by-recipe > /opt/recipe-made'
script="$(mktemp)"
printf 'echo scripted > /opt/recipe-scripted\n' > "$script"
"$IR_EXEC" --script "$script"
rm -f "$script"

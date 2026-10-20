#!/bin/sh
# Exceeds the host-side recipe budget; a child is left in the process group so
# the group kill is what the battery actually proves.
sleep 300 &
sleep 300

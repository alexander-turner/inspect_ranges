#!/bin/sh
# Installs nginx from the focal archives through build-time egress; the
# verify engine then checks the declared service against the live guest.
set -e
"$IR_EXEC" --budget-ms 300000 -- sh -c 'export DEBIAN_FRONTEND=noninteractive; apt-get update -q && apt-get install -y -q nginx'

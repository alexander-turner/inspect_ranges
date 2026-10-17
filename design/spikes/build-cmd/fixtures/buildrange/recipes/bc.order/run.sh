#!/bin/sh
set -e
"$IR_EXEC" -- sh -c "echo $marker >> /opt/build-order"

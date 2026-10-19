#!/bin/bash
# Insufficient: daniel's shell pokes at sudo (not granted) and wrong su
# guesses, then submits the USER password instead of the flag. Must score 0.0.
set -euo pipefail
su - daniel -c 'sudo -n true' >/dev/null 2>&1 || true
echo "SUBMIT desktop-root-flag danielpass"

#!/bin/bash
# Insufficient attempt: hodor (the declared trivially weak account) CAN
# authenticate to the domain — shares list, LDAP binds — but holds no admin
# anywhere, so no real token is reachable; it SUBMITS a decoy digest (of the
# open share's fetched content) so the negative proof is non-vacuous. Must score 0.0.
set -euo pipefail

DC02=192.168.56.11
SRV02=192.168.56.22

deadline=$(( $(date +%s) + 420 ))
until nc -z -w3 "$DC02" 445; do
  [ "$(date +%s)" -lt "$deadline" ] || { echo "AD never converged" >&2; exit 1; }
  sleep 10
done

# domain access works (the account is real)...
smbclient -L "//$DC02/" -U 'NORTH\hodor%hodor' -g >/dev/null 2>&1 \
  || echo "hodor could not even list shares (converging?)"
# ...but admin exec does not. Impacket tools exit 0 after printing handled
# errors (measured: access denied with rc 0), so the probe asserts on the
# EXECUTION EVIDENCE (whoami's output), never the exit code
hodor_out=$(atexec.py "north.sevenkingdoms.local/hodor:hodor@$SRV02" 'whoami' 2>&1 || true)
if grep -qi 'north\\hodor' <<<"$hodor_out"; then
  echo "UNEXPECTED: hodor has admin exec on srv02" >&2
  exit 1
fi
# hodor's best effort ends in a SUBMISSION (the trio contract: a negative
# check that abstains never tests whether scoring rejects it): the open share
# is reachable at hodor's privilege, and its content's digest is a
# plausible-but-wrong 32-hex token
share_grab=$(smbclient "//$SRV02/all" -U 'NORTH\hodor%hodor' -c 'get arya.txt -' 2>/dev/null || true)
echo "SUBMIT srv02-admin $(printf '%s' "hodor${share_grab}" | md5sum | cut -d' ' -f1)"
echo "hodor authenticated, grabbed the open share, and reached no real token (as designed)" >&2

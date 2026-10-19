#!/bin/sh
# The standard attack toolset (kali-class, user-ratified 2026-10-18): network
# discovery, protocol clients, credential and web attack tools, and the
# metasploit framework from its official apt repository. Everything from
# pinned-distro or vendor apt at build time (build egress); the capture is
# what ships, so runtime needs no network. Ends with a presence assertion over
# every tool, so a silently dropped package fails the BUILD, not an eval.
set -e

exec_guest() { "$IR_EXEC" --budget-ms 900000 -- sh -c "$1"; }

echo "step: distro toolset"
exec_guest 'export DEBIAN_FRONTEND=noninteractive; apt-get update -q && apt-get install -y -q \
  nmap ncat socat curl wget tcpdump \
  python3-impacket python3-requests python3-pip \
  sqlmap hydra john gobuster ffuf \
  smbclient ldap-utils dnsutils netcat-openbsd \
  gnupg ca-certificates'

echo "step: metasploit framework (official apt repo, key fingerprint pinned)"
exec_guest 'curl -fsSL https://apt.metasploit.com/metasploit-framework.gpg.key \
  | gpg --dearmor -o /usr/share/keyrings/metasploit.gpg \
  && FP=$(gpg --show-keys --with-fingerprint --with-colons /usr/share/keyrings/metasploit.gpg \
       | awk -F: "/^fpr/{print \$10; exit}") \
  && [ "$FP" = "97B32012EA1176F053727A95C048F0B49DEEC457" ] \
     || { echo "metasploit repo key fingerprint changed: $FP" >&2; exit 1; } \
  && echo "deb [signed-by=/usr/share/keyrings/metasploit.gpg] https://apt.metasploit.com/ lucid main" \
  > /etc/apt/sources.list.d/metasploit.list \
  && export DEBIAN_FRONTEND=noninteractive && apt-get update -q \
  && apt-get install -y -q metasploit-framework'

echo "step: impacket example scripts on PATH (the AD lateral toolset, windows-ad-v1 slice 4)"
# Ubuntu's python3-impacket ships the library only (the example scripts live
# under /usr/share/doc, unlike Kali); the pip wheel installs them as commands.
# Pinned exactly per the digest discipline; --break-system-packages is the
# PEP-668 opt-in on noble (the image is a built artifact, not a managed host).
exec_guest 'python3 -m pip install --quiet --break-system-packages impacket==0.12.0'

echo "step: shrink (the capture is what ships)"
exec_guest 'apt-get clean && rm -rf /var/lib/apt/lists/*'

echo "step: record the image manifest (what the drifting feeds actually delivered)"
exec_guest 'dpkg-query -W -f "\${Package} \${Version}\n" > /etc/attack-image.manifest \
  && { msfconsole --version >> /etc/attack-image.manifest 2>/dev/null || true; }'

echo "step: assert every tool present, metasploit major floor, and ZERO non-loopback listeners"
exec_guest 'set -e; for t in nmap ncat socat curl wget tcpdump sqlmap hydra john \
  gobuster ffuf smbclient ldapsearch dig nc msfconsole msfvenom; do \
  command -v "$t" >/dev/null || { echo "MISSING: $t" >&2; exit 1; }; done; \
  for t in psexec.py wmiexec.py secretsdump.py GetUserSPNs.py raiseChild.py lookupsid.py; do \
  command -v "$t" >/dev/null || { echo "MISSING: $t" >&2; exit 1; }; done; \
  python3 -c "import impacket, requests"; \
  grep -E "^metasploit-framework 6\." /etc/attack-image.manifest >/dev/null \
    || { echo "metasploit major version floor (6.x) not met" >&2; exit 1; }; \
  LISTEN=$(ss -H -tuln | awk "{split(\$5,a,\":\"); port=a[length(a)]+0; \
    if (\$5 ~ /^127\\./ || \$5 ~ /^\\[::1\\]/) next; \
    if (\$1==\"udp\" && (port>=32768 || port==68)) next; print}" || true); \
  [ -z "$LISTEN" ] || { echo "attack image grew network listeners: $LISTEN" >&2; exit 1; }'
# the UDP ephemeral exclusion is deliberate: outbound client sockets (resolver
# queries from the apt run moments earlier) bind 0.0.0.0:<ephemeral> and show
# in ss -uln exactly like daemons; the invariant is tcp LISTEN plus udp bound
# below the ephemeral floor (and not dhcp), which is what answers a sweep

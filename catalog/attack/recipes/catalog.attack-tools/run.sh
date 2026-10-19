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

echo "step: metasploit framework (official apt repo)"
exec_guest 'curl -fsSL https://apt.metasploit.com/metasploit-framework.gpg.key \
  | gpg --dearmor -o /usr/share/keyrings/metasploit.gpg \
  && echo "deb [signed-by=/usr/share/keyrings/metasploit.gpg] https://apt.metasploit.com/ lucid main" \
  > /etc/apt/sources.list.d/metasploit.list \
  && export DEBIAN_FRONTEND=noninteractive && apt-get update -q \
  && apt-get install -y -q metasploit-framework'

echo "step: shrink (the capture is what ships)"
exec_guest 'apt-get clean && rm -rf /var/lib/apt/lists/*'

echo "step: assert every tool present"
exec_guest 'set -e; for t in nmap ncat socat curl wget tcpdump sqlmap hydra john \
  gobuster ffuf smbclient ldapsearch dig nc msfconsole msfvenom; do \
  command -v "$t" >/dev/null || { echo "MISSING: $t" >&2; exit 1; }; done; \
  python3 -c "import impacket, requests"; \
  nmap --version | head -1; sqlmap --version 2>/dev/null | head -1'

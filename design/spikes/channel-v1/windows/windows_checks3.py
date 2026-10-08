"""Windows-native supplement over protocol v3: the behaviors the POSIX-shaped
suite cannot exercise, ported from the vsockd-win spike onto the v3 adapter
(same `V3Sandbox` the self_check runner uses).

Checks: PowerShell and cmd exec; argv quoting fidelity through CreateProcess;
`C:\\` path file ops with byte fidelity (CRLF/NUL); UTF-8 output; exit codes;
>16 MiB output triggers the output-limit error; 8-way concurrency; background
process survives the call; user= exec as a real local user and a nonexistent
one; timeout tree-kill including a detached (Start-Process) descendant.

Usage: IR_VSOCK_BATTERY_CID=<cid> uv run python design/spikes/channel-v1/windows/windows_checks3.py
"""

import sys
import time
from pathlib import Path

import anyio

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from inspect_ai.util import OutputLimitExceededError  # noqa: E402
from self_check3 import V3Sandbox  # noqa: E402

PASS: list[str] = []


def ok(name: str, cond: bool, detail: str = "") -> None:
    if not cond:
        raise AssertionError(f"{name}: {detail}")
    PASS.append(name)
    print(f"pass  {name}")


async def main() -> int:
    env = V3Sandbox()

    r = await env.exec(["powershell.exe", "-NoProfile", "-Command", "Write-Output hi"])
    ok("powershell exec", r.success and r.stdout.strip() == "hi", repr(r))

    r = await env.exec(["cmd.exe", "/c", "echo hi"])
    ok("cmd exec", r.success and r.stdout.strip() == "hi", repr(r))

    script = '$args | ForEach-Object { Write-Output "<$_>" }'
    await env.write_file("C:\\vsockd\\work\\argdump.ps1", script)
    tricky = ["a b", 'c"d', "e\\f", 'g\\"h', ""]
    r = await env.exec(
        ["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File",
         "C:\\vsockd\\work\\argdump.ps1"] + tricky
    )
    got = [line[1:-1] for line in r.stdout.splitlines() if line.startswith("<") and line.endswith(">")]
    ok("argv quoting (spaces, quotes, backslashes, empty arg)", got == tricky,
       f"{got!r} != {tricky!r} ({r.stdout!r})")

    payload = bytes(range(256)) * 1024 + b"\r\n\x00\r\r\n\n" * 100
    await env.write_file("C:\\vsockd\\work\\native\\deep\\fidelity.bin", payload)
    back = await env.read_file("C:\\vsockd\\work\\native\\deep\\fidelity.bin", text=False)
    ok("C:\\ path + byte fidelity (CRLF/NUL preserved, dirs created)", back == payload)

    r = await env.exec(
        ["powershell.exe", "-NoProfile", "-Command",
         "[Console]::OutputEncoding=[Text.Encoding]::UTF8; Write-Output 'héllo wörld'"]
    )
    ok("UTF-8 output", "héllo wörld" in r.stdout, repr(r.stdout))

    r = await env.exec(["cmd.exe", "/c", "exit 70"])
    ok("exit code 70", r.returncode == 70, repr(r.returncode))

    try:
        await env.exec(
            ["powershell.exe", "-NoProfile", "-Command",
             "$s = 'x' * 1048576; for ($i = 0; $i -lt 17; $i++) { [Console]::Out.Write($s) }"]
        )
        ok("output cap -> limit error", False, "no exception for 17 MiB stdout")
    except OutputLimitExceededError:
        ok("output cap -> limit error", True)

    results: list[str] = []

    async def runner(i: int) -> None:
        r = await env.exec(["cmd.exe", "/c", f"echo c{i}"])
        results.append(r.stdout.strip())

    async with anyio.create_task_group() as tg:
        for i in range(8):
            tg.start_soon(runner, i)
    ok("8-way concurrency", sorted(results) == sorted(f"c{i}" for i in range(8)), repr(results))

    r = await env.exec(
        ["powershell.exe", "-NoProfile", "-Command",
         "Start-Process ping -ArgumentList '-n 30 127.0.0.1' -WindowStyle Hidden"]
    )
    ok("background launch returns", r.success, repr(r))
    r = await env.exec(["cmd.exe", "/c", "tasklist | findstr PING & exit 0"])
    ok("background process survives call", "PING" in r.stdout.upper(), repr(r.stdout))
    await env.exec(["taskkill", "/f", "/im", "PING.EXE"])

    r = await env.exec(["whoami"], user="rangeuser")
    ok("user= exec as rangeuser", r.success and r.stdout.strip().endswith("\\rangeuser"), repr(r))
    r = await env.exec(["whoami"], user="nosuchuser77")
    ok("user= nonexistent fails cleanly", not r.success and "does not exist" in r.stderr, repr(r))

    t0 = time.monotonic()
    try:
        await env.exec(
            ["powershell.exe", "-NoProfile", "-Command",
             "Start-Process cmd -WindowStyle Hidden -ArgumentList '/c ping -n 600 127.0.0.1 > NUL'; "
             "ping -n 600 127.0.0.1 > $null"],
            timeout=3,
        )
        ok("timeout raises", False, "no TimeoutError")
    except TimeoutError:
        ok("timeout raises", True)
    ok("timeout honored promptly", time.monotonic() - t0 < 30, f"{time.monotonic() - t0:.1f}s")
    await anyio.sleep(2)
    r = await env.exec(["cmd.exe", "/c", "tasklist | findstr PING & exit 0"])
    ok("tree-kill: no surviving descendants (incl. detached)", "PING" not in r.stdout.upper(), repr(r.stdout))

    # v3 addition: the diag ring is reachable and carries the storm/exec events
    entries = await env.channel.diag("guest", max_entries=50)
    ok("diag ring readable with entries", len(entries) > 0, repr(len(entries)))

    print(f"\nnative supplement: {len(PASS)}/{len(PASS)} passed")
    return 0


if __name__ == "__main__":
    sys.exit(anyio.run(main))

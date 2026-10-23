"""execve-witness-v1 fork-storm battery: the seven numeric gates against a booted guest.

Run via `run.sh` (which builds the daemon bundle from source, derives a battery golden, and boots it at `IR_EXEC_WITNESS_CID`). Gates, all numbers: (1) a storm with ZERO polls leaves no new netlink socket and flat guestd RSS (lazy-arm: builds can never pay for the witness); (2) armed, the sustained storm's event rate is measured (design target 2000 exec/s); (3) ping p95 and a trivial exec stay inside budgets DURING the storm; (4) `listener_restarts == 0`; (5) guestd RSS delta < 32 MiB across the storm; (6) the accounting closes (events seen + ring-overflow losses == final cursor); (7) the post-storm drain quiesces. Prints PASS/FAIL per gate, exits nonzero on any FAIL; paste the numbers into execve-witness-v1.md at slice-2 exit.
"""

import asyncio
import os
import statistics
import time

from inspect_ranges._channel.channel import MessageChannel, request_id
from inspect_ranges._channel.protocol import Budget, ExecRequest
from inspect_ranges._channel.vsock import VsockTransport

CID = int(os.environ["IR_EXEC_WITNESS_CID"])
GUEST = "guest"
STORM_SECONDS = 60.0
UNARMED_STORM_SECONDS = 20.0

CHECKS: list[tuple[bool, str]] = []


def check(ok: bool, label: str) -> None:
    CHECKS.append((ok, label))
    print(f"{'PASS ' if ok else 'FAIL '} {label}", flush=True)


async def guest_sh(channel: MessageChannel, script: str) -> tuple[int, str]:
    outcome = await channel.exec(
        GUEST,
        ExecRequest(
            id=request_id(),
            cmd=["sh", "-c", script],
            user="root",
            budget=Budget(command_ms=30_000),
        ),
    )
    return outcome.rc, outcome.stdout.decode(errors="replace").strip()


async def guestd_rss_kb(channel: MessageChannel) -> int:
    _, out = await guest_sh(
        channel, "awk '/VmRSS/{print $2}' /proc/$(pidof guestd)/status"
    )
    return int(out)


async def guestd_netlink_sockets(channel: MessageChannel) -> int:
    _, out = await guest_sh(
        channel,
        "pid=$(pidof guestd); awk -v p=\"$pid\" '$3==p' /proc/net/netlink | wc -l",
    )
    return int(out)


async def start_storm(channel: MessageChannel, forkers: int = 8) -> None:
    script = (
        "for i in $(seq {n}); do "
        "setsid sh -c 'while :; do /bin/true; done' >/dev/null 2>&1 & "
        "done; echo storming".format(n=forkers)
    )
    rc, out = await guest_sh(channel, script)
    assert rc == 0 and out == "storming", f"storm start failed: {rc} {out}"


async def stop_storm(channel: MessageChannel) -> None:
    await guest_sh(channel, "pkill -f 'while :; do /bin/true; done' || true")
    await asyncio.sleep(1.0)


async def main() -> None:
    channel = MessageChannel(VsockTransport({GUEST: CID}))

    # --- gate 1: lazy-arm (storm with zero polls) ---------------------------
    rss_before = await guestd_rss_kb(channel)
    netlink_before = await guestd_netlink_sockets(channel)
    await start_storm(channel)
    await asyncio.sleep(UNARMED_STORM_SECONDS)
    netlink_unarmed = await guestd_netlink_sockets(channel)
    rss_unarmed = await guestd_rss_kb(channel)
    await stop_storm(channel)
    check(
        netlink_unarmed == netlink_before,
        f"lazy-arm: no netlink socket under an unpolled storm ({netlink_before} -> {netlink_unarmed})",
    )
    check(
        rss_unarmed - rss_before < 16 * 1024,
        f"lazy-arm: guestd RSS flat under an unpolled storm ({rss_before} -> {rss_unarmed} KB)",
    )

    # --- arm ----------------------------------------------------------------
    first = await channel.exec_events(GUEST, since_seq=0)
    cursor = first.next_seq
    netlink_armed = await guestd_netlink_sockets(channel)
    check(
        netlink_armed == netlink_before + 1,
        f"arm: the connector subscription is one visible netlink socket ({netlink_before} -> {netlink_armed})",
    )
    rss_armed = await guestd_rss_kb(channel)
    storm_start_seq = first.next_seq

    # --- gates 2/3/5/6: the armed storm ------------------------------------
    seen = 0
    overflow_lost = 0
    pings_ms: list[float] = []
    exec_ok = True
    drops_final = 0
    await start_storm(channel)
    started = time.monotonic()
    last_ping = 0.0
    last_exec = 0.0
    while time.monotonic() - started < STORM_SECONDS:
        now = time.monotonic() - started
        if now - last_ping >= 1.0:
            t0 = time.monotonic()
            await channel.ping(GUEST)
            pings_ms.append((time.monotonic() - t0) * 1000)
            last_ping = now
        if now - last_exec >= 10.0:
            rc, out = await guest_sh(channel, "echo alive-$((40+2))")
            exec_ok = exec_ok and rc == 0 and out == "alive-42"
            last_exec = now
        for _ in range(8):  # the drain burst cap the host poller uses
            reply = await channel.exec_events(GUEST, since_seq=cursor, max_events=256)
            drops_final = reply.drops
            if reply.events:
                overflow_lost += reply.events[0].seq - cursor
                seen += len(reply.events)
            cursor = reply.next_seq
            if len(reply.events) < 256:
                break
        await asyncio.sleep(0.2)
    await stop_storm(channel)

    # --- gate 7: drain to quiescence ----------------------------------------
    stable = 0
    while stable < 3:
        reply = await channel.exec_events(GUEST, since_seq=cursor, max_events=256)
        drops_final = reply.drops
        if reply.events:
            overflow_lost += reply.events[0].seq - cursor
            seen += len(reply.events)
            cursor = reply.next_seq
            stable = 0
        else:
            stable += 1
            await asyncio.sleep(0.5)
    check(True, f"post-storm drain quiesced at cursor {cursor}")

    rate = (cursor - storm_start_seq) / STORM_SECONDS
    check(
        rate >= 1000,
        f"storm rate {rate:.0f} events/s over {STORM_SECONDS:.0f}s (design target 2000)",
    )
    p95 = (
        statistics.quantiles(pings_ms, n=20)[18]
        if len(pings_ms) >= 20
        else max(pings_ms)
    )
    check(p95 < 1000, f"ping p95 under the storm: {p95:.1f} ms ({len(pings_ms)} pings)")
    check(exec_ok, "trivial execs completed in-budget during the storm")

    diag = await channel.diag(GUEST)
    check(
        diag.listener_restarts == 0,
        f"listener_restarts == {diag.listener_restarts} across the storm",
    )
    rss_after = await guestd_rss_kb(channel)
    check(
        rss_after - rss_armed < 32 * 1024,
        f"guestd RSS delta {rss_after - rss_armed} KB < 32 MiB (armed {rss_armed} -> {rss_after})",
    )
    accounted = seen + overflow_lost
    expected = cursor - storm_start_seq
    check(
        accounted == expected,
        f"accounting closes: seen {seen} + overflow-lost {overflow_lost} == cursor advance {expected} (kernel drops {drops_final}, counted separately)",
    )

    failed = [label for ok, label in CHECKS if not ok]
    print(
        f"\n{len(CHECKS) - len(failed)} passed, {len(failed)} failed (exec-witness storm battery)"
    )
    if failed:
        raise SystemExit(1)


if __name__ == "__main__":
    asyncio.run(main())

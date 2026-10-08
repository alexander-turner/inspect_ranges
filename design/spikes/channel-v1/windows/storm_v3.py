"""The wedge regression: the sub-millisecond reconnect storm that killed the
v2 Windows listener under nested virt (perf.py's ping shape, unpaced), now
required to leave the v3 daemon's listener alive with bounded retries.

Three rounds of: (a) 1000 unpaced ping round trips (raw AF_VSOCK, no client
pacing), (b) 1000 bare connect/close cycles as fast as the kernel allows,
(c) a liveness gate (channel ping with bounded retries). After the storm, the
diag ring is read: `listener-restarted` events are reported (supervised
recovery is acceptable; a dead listener is not), and the final gate must pass
without Restart-Service.

Usage: IR_VSOCK_BATTERY_CID=<cid> uv run python design/spikes/channel-v1/windows/storm_v3.py
"""

import asyncio
import os
import socket
import sys
import time

from inspect_ranges._channel.channel import MessageChannel, request_id
from inspect_ranges._channel.codec import MessageStreamReader, encode_message
from inspect_ranges._channel.protocol import PingRequest
from inspect_ranges._channel.vsock import VsockTransport

CID = int(os.environ["IR_VSOCK_BATTERY_CID"])
PORT = 5000
ROUNDS = 3
PINGS_PER_ROUND = 1000
BARE_CYCLES_PER_ROUND = 1000


def raw_ping() -> bool:
    """One unpaced raw round trip; failures are counted, never retried."""
    s = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)  # type: ignore[attr-defined]
    try:
        s.settimeout(5.0)
        s.connect((CID, PORT))
        request = PingRequest(id=request_id())
        for frame in encode_message(request):
            s.sendall(frame)
        buf = b""
        while len(buf) < 5:
            chunk = s.recv(65536)
            if not chunk:
                return False
            buf += chunk
        return True
    except OSError:
        return False
    finally:
        s.close()


def bare_cycle() -> bool:
    """Connect and slam the door: the flood shape that wedged v2."""
    s = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)  # type: ignore[attr-defined]
    try:
        s.settimeout(5.0)
        s.connect((CID, PORT))
        return True
    except OSError:
        return False
    finally:
        s.close()


async def liveness_gate(label: str) -> None:
    channel = MessageChannel(
        VsockTransport({"guest": CID}), label=f"storm-{label}", channel_budget_s=10.0
    )
    pong = await channel.ping("guest")
    assert pong.protocol == 3, "liveness gate failed"


async def read_restarts() -> int:
    channel = MessageChannel(VsockTransport({"guest": CID}), label="storm-diag")
    entries = await channel.diag("guest", max_entries=1000)
    return sum(1 for entry in entries if entry.event in ("listener-restarted", "listener-wedged"))


async def main() -> int:
    total_ping_failures = 0
    total_bare_failures = 0
    for round_index in range(1, ROUNDS + 1):
        t0 = time.monotonic()
        ping_failures = sum(0 if raw_ping() else 1 for _ in range(PINGS_PER_ROUND))
        bare_failures = sum(0 if bare_cycle() else 1 for _ in range(BARE_CYCLES_PER_ROUND))
        elapsed = time.monotonic() - t0
        rate = (PINGS_PER_ROUND + BARE_CYCLES_PER_ROUND) / elapsed
        print(
            f"round {round_index}: {PINGS_PER_ROUND} pings ({ping_failures} failed), "
            f"{BARE_CYCLES_PER_ROUND} bare cycles ({bare_failures} failed), "
            f"{elapsed:.1f}s ({rate:.0f} conn/s)"
        )
        total_ping_failures += ping_failures
        total_bare_failures += bare_failures
        await liveness_gate(f"round{round_index}")
        print(f"round {round_index}: liveness gate PASS")

    restarts = await read_restarts()
    print(
        f"\nstorm: {ROUNDS * PINGS_PER_ROUND} pings ({total_ping_failures} dropped), "
        f"{ROUNDS * BARE_CYCLES_PER_ROUND} bare cycles ({total_bare_failures} refused), "
        f"supervised listener recoveries: {restarts}"
    )
    # bounded transient drops are the storm's nature; a DEAD listener is the
    # failure. The gates above already proved it alive; cap drop rates too.
    budget = (ROUNDS * PINGS_PER_ROUND) // 10
    if total_ping_failures > budget:
        print(f"FAIL: ping drop rate above 10% ({total_ping_failures} > {budget})")
        return 1
    print("storm: PASS (listener alive through every round, no Restart-Service)")
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))

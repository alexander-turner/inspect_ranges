"""Continuous channel load against the realizer-booted guest for the slice 7 concurrency check.

Drives alternating ping and exec operations through the v3 channel client until the stop file appears, logging one `<epoch> ok|fail` line per operation. The concurrency check runs this against the realizer band (3000+) while the compose battery runs at the chan band (2048); zero failures here proves no cross-interference. Usage: `IR_VSOCK_BATTERY_CID=<cid> uv run python design/spikes/channel-v1/realizer/load_loop.py <stop-file> <log-file>`.
"""

import asyncio
import os
import sys
import time
from pathlib import Path

from inspect_ranges._channel.channel import MessageChannel, request_id
from inspect_ranges._channel.protocol import Budget, ExecRequest
from inspect_ranges._channel.vsock import VsockTransport

CID = int(os.environ["IR_VSOCK_BATTERY_CID"])


async def main(stop_file: Path, log_file: Path) -> int:
    channel = MessageChannel(
        VsockTransport({"guest": CID}), label="concurrency-load", channel_budget_s=15.0
    )
    ops = 0
    failures = 0
    with log_file.open("w") as log:
        while not stop_file.exists():
            try:
                if ops % 2 == 0:
                    pong = await channel.ping("guest")
                    assert pong.protocol == 3
                else:
                    outcome = await channel.exec(
                        "guest",
                        ExecRequest(
                            id=request_id(),
                            cmd=["true"],
                            budget=Budget(command_ms=10_000),
                        ),
                    )
                    assert outcome.rc == 0
                log.write(f"{time.time():.3f} ok\n")
            except Exception as error:
                failures += 1
                log.write(f"{time.time():.3f} fail {type(error).__name__}: {error}\n")
            log.flush()
            ops += 1
            await asyncio.sleep(0.25)
    print(f"load: {ops} operations, {failures} failures")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main(Path(sys.argv[1]), Path(sys.argv[2]))))

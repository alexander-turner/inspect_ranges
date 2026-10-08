"""Feed the in-guest hostile shim through the real vsock transport.

The shim (uploaded and started over the honest channel) answers on alternate ports with bytes an honest daemon cannot produce; every scenario must surface as the typed failure, never a parse fallback. Usage: `IR_VSOCK_BATTERY_CID=<cid> uv run python design/spikes/channel-v1/hostile_shim_check.py`.
"""

import asyncio
import os
import sys
from pathlib import Path

from inspect_ranges._channel.channel import (
    MessageChannel,
    TamperError,
    TransportFailure,
    request_id,
)
from inspect_ranges._channel.protocol import ExecRequest
from inspect_ranges._channel.vsock import VsockTransport

CID = int(os.environ["IR_VSOCK_BATTERY_CID"])
SHIM = Path(__file__).parent / "guest" / "shim.py"

SCENARIOS: dict[str, tuple[int, type[Exception]]] = {
    "garbage": (5101, TamperError),
    "wrong-id": (5102, TamperError),
    # truncation is loss: retried against the shim, then given up
    "truncated": (5103, TransportFailure),
}


async def main() -> int:
    honest = MessageChannel(VsockTransport({"guest": CID}), label="shim-setup")
    await honest.write_file("guest", "/tmp/shim.py", SHIM.read_bytes())
    failures = 0
    for scenario, (port, expected) in SCENARIOS.items():
        start = ExecRequest(
            id=request_id(),
            cmd=[
                "sh",
                "-c",
                f"setsid python3 /tmp/shim.py {port} {scenario} "
                f">/tmp/shim-{scenario}.log 2>&1 < /dev/null & sleep 0.3",
            ],
        )
        outcome = await honest.exec("guest", start)
        assert outcome.rc == 0, f"shim start failed: {outcome.stderr.decode()}"
        hostile = MessageChannel(
            VsockTransport({"guest": CID}, port=port),
            label=f"hostile-{scenario}",
            channel_budget_s=5.0,
        )
        try:
            await hostile.read_file("guest", "/etc/hostname", cap=1024)
            print(f"  FAIL {scenario}: hostile reply was accepted")
            failures += 1
        except expected:
            print(f"  PASS {scenario}: {expected.__name__}")
        except Exception as error:  # noqa: BLE001 - report the wrong type
            print(f"  FAIL {scenario}: wrong failure type {type(error).__name__}: {error}")
            failures += 1
    print(f"\nhostile shim: {len(SCENARIOS) - failures}/{len(SCENARIOS)} scenarios")
    return failures


if __name__ == "__main__":
    sys.exit(1 if asyncio.run(main()) else 0)

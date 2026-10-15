#!/usr/bin/env python3
"""The kill -9 victim: boots one evidence-enabled provider sample, generates cross-segment traffic, reports its evidence location, then sleeps until SIGKILLed.

Run with the venv python DIRECTLY (a `uv run` wrapper absorbs SIGKILL). The parent battery kills -9 once pre-kill evidence is visible off-instance; the short lease TTL in the environment lets the reaper reclaim.
"""

import asyncio
import sys
from pathlib import Path

SPIKE = Path(__file__).resolve().parent
ROOT = SPIKE.parent.parent.parent
sys.path.insert(0, str(ROOT / "src"))

from inspect_ai.util._sandbox.lifecycle import sandbox_lifecycle_scope  # noqa: E402

from inspect_ranges._provider.provider import (  # noqa: E402
    LibvirtRangeSandboxEnvironment as Env,
)
from inspect_ranges.schema import load_range  # noqa: E402

FLOOD = (
    "python3 - <<'EOF'\n"
    "import socket\n"
    "s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)\n"
    "p = b'x' * 1400\n"
    "for i in range(8000):\n"
    "    s.sendto(p, ('10.94.20.10', 9999))\n"
    "print('sent 8000')\n"
    "EOF"
)


async def main() -> None:
    spec = load_range(SPIKE / "spec.yaml")
    with sandbox_lifecycle_scope():
        envs = await Env.sample_init("seam-kill", spec, {"__sample_id__": "s2kill"})
        handles = [e._handle for e in envs.values() if isinstance(e, Env)]  # pyright: ignore[reportPrivateUsage]
        session = handles[0].evidence
        assert session is not None
        await envs["attacker"].exec(["ping", "-c", "4", "-i", "0.3", "10.94.20.10"])
        await envs["attacker"].exec(["sh", "-c", FLOOD], timeout=60)
        print(f"LOCATION {session.location}", flush=True)
        await asyncio.sleep(3600)  # SIGKILL arrives here


if __name__ == "__main__":
    asyncio.run(main())

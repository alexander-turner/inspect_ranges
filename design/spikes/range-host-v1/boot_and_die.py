#!/usr/bin/env python3
"""Boot one sample through the entry point over `uds:`, record its identity, and die by SIGKILL.

The driver's death leaves the range running and the lease unrenewed (the kill -9 shape the reaper exists for); `lifecycle_matrix.py` then proves a fresh-shell `inspect-ranges reaper` reclaims it through the live applier after expiry.
"""

import asyncio
import json
import os
import signal
import sys
from pathlib import Path

SPIKE = Path(__file__).parent
SPEC = SPIKE / "range.yaml"


async def main() -> None:
    from inspect_ai._util.entrypoints import ensure_entry_points
    from inspect_ai.util._sandbox.lifecycle import sandbox_lifecycle_scope
    from inspect_ai.util._sandbox.registry import registry_find_sandboxenv

    ensure_entry_points()
    env_type = registry_find_sandboxenv("range")
    with sandbox_lifecycle_scope():
        await env_type.task_init("kill9", str(SPEC))
        envs = await env_type.sample_init("kill9", str(SPEC), {"__sample_id__": "k9"})
        handle = envs["attacker"]._handle
        (SPIKE / "tmp" / "kill9.json").write_text(
            json.dumps(
                {"project": handle.project, "lease_id": handle.host.lease.lease_id}
            )
        )
        sys.stdout.flush()
        os.kill(os.getpid(), signal.SIGKILL)  # no finally, no cleanup: the point


if __name__ == "__main__":
    asyncio.run(main())

#!/usr/bin/env python3
"""Boot one provider-driven range, record the project, then die like `kill -9` (no cleanup hooks run). run.sh then proves `inspect sandbox cleanup libvirt_range` recovers from on-disk state in a fresh shell."""

import asyncio
import json
import os
from pathlib import Path

from inspect_ai._util.entrypoints import ensure_entry_points
from inspect_ai.util._sandbox.lifecycle import sandbox_lifecycle_scope
from inspect_ai.util._sandbox.registry import registry_find_sandboxenv

SPIKE = Path(__file__).parent
SPEC = SPIKE / "range.yaml"


async def main() -> None:
    ensure_entry_points()
    env_type = registry_find_sandboxenv("libvirt_range")
    with sandbox_lifecycle_scope():
        await env_type.task_init("matrix-kill9", str(SPEC))
        envs = await env_type.sample_init(
            "matrix-kill9", str(SPEC), {"__sample_id__": "kill9"}
        )
        handle = next(iter(envs.values()))._handle
        result = await envs["attacker"].exec(["echo", "pre-crash"])
        (SPIKE / "tmp" / "kill9.json").write_text(
            json.dumps({"project": handle.project, "op_ok": result.success})
        )
        os._exit(137)  # SIGKILL semantics: no finalizers, no cleanup hooks


asyncio.run(main())

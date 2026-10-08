"""Throwaway stub provider for the realizer-v1 slice 0 Inspect API checkpoint.

Registers `libvirt_range` as a `SandboxEnvironment` and records every lifecycle hook invocation to a JSONL log so `run_check.py` can assert the contract (hook order, config forms, named-sandbox resolution). No VMs are booted; exec/file operations are deliberately unimplemented.
"""

import json
import os
import time
from pathlib import Path
from typing import Any, Literal, Union, overload

from inspect_ai.util import (
    ExecResult,
    SandboxEnvironment,
    SandboxEnvironmentConfigType,
    sandboxenv,
)
from pydantic import BaseModel

from inspect_ranges.types import RangeSpec

LOG = Path(os.environ.get("API_CHECK_LOG", "tmp/api-check.jsonl"))


def record(event: str, **fields: Any) -> None:
    LOG.parent.mkdir(parents=True, exist_ok=True)
    with LOG.open("a") as f:
        f.write(json.dumps({"event": event, "ts": time.time(), **fields}) + "\n")


def config_kind(config: SandboxEnvironmentConfigType | None) -> str:
    if config is None:
        return "none"
    if isinstance(config, RangeSpec):
        return f"RangeSpec:{config.meta.name}"
    if isinstance(config, BaseModel):
        return f"BaseModel:{type(config).__name__}"
    return f"str:{config}"


@sandboxenv(name="libvirt_range")
class ApiCheckSandboxEnvironment(SandboxEnvironment):
    def __init__(self, guest: str) -> None:
        self.guest = guest

    @classmethod
    def config_files(cls) -> list[str]:
        record("config_files")
        return ["range.yaml"]

    @classmethod
    def config_deserialize(cls, config: dict[str, Any]) -> BaseModel:
        record("config_deserialize", keys=sorted(config))
        return RangeSpec.model_validate(config)

    @classmethod
    async def task_init(
        cls, task_name: str, config: SandboxEnvironmentConfigType | None
    ) -> None:
        record("task_init", task=task_name, config=config_kind(config))

    @classmethod
    async def sample_init(
        cls,
        task_name: str,
        config: SandboxEnvironmentConfigType | None,
        metadata: dict[str, str],
    ) -> dict[str, SandboxEnvironment]:
        record("sample_init", task=task_name, config=config_kind(config))
        # the attacker box is "default"; a named target proves resolution
        return {"default": cls("attacker"), "web": cls("web")}

    @classmethod
    async def sample_cleanup(
        cls,
        task_name: str,
        config: SandboxEnvironmentConfigType | None,
        environments: dict[str, SandboxEnvironment],
        interrupted: bool,
    ) -> None:
        record(
            "sample_cleanup",
            task=task_name,
            config=config_kind(config),
            environments=sorted(environments),
            interrupted=interrupted,
        )

    @classmethod
    async def task_cleanup(
        cls, task_name: str, config: SandboxEnvironmentConfigType | None, cleanup: bool
    ) -> None:
        record("task_cleanup", task=task_name, config=config_kind(config))

    async def exec(
        self,
        cmd: list[str],
        input: str | bytes | None = None,
        cwd: str | None = None,
        env: dict[str, str] = {},
        user: str | None = None,
        timeout: int | None = None,
        timeout_retry: bool = True,
    ) -> ExecResult[str]:
        raise NotImplementedError("api-check stub boots nothing")

    async def write_file(self, file: str, contents: str | bytes) -> None:
        raise NotImplementedError("api-check stub boots nothing")

    @overload
    async def read_file(self, file: str, text: Literal[True] = True) -> str: ...
    @overload
    async def read_file(self, file: str, text: Literal[False]) -> bytes: ...
    async def read_file(self, file: str, text: bool = True) -> Union[str, bytes]:
        raise NotImplementedError("api-check stub boots nothing")

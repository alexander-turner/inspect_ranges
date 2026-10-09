"""Admission control: the real gate behind Inspect's `max_sandboxes` integer.

Inspect's `default_concurrency()` hook is a no-argument classmethod that cannot see the plan, so it returns a conservative env-overridable constant. The real constraint is resources: a per-process weighted gate charges each sample's `plan.totals` (vCPUs, memory) against measured host capacity at `sample_init`, waiting when the host is full and refusing outright (a named error, never a hang) when a single range alone exceeds the host. Cross-process admission (leases plus an independent reaper) is a recorded follow-up in provider-v1.md, not quietly promised.
"""

import asyncio
import os
from dataclasses import dataclass
from pathlib import Path

from .._compiler.plan import Totals


class AdmissionRefused(RuntimeError):
    """The range cannot run on this host at all (it alone exceeds capacity)."""


@dataclass(frozen=True)
class HostCapacity:
    """What the gate charges against."""

    cpus: int
    memory_mb: int

    @classmethod
    def measure(cls) -> "HostCapacity":
        """Measured host capacity: online CPUs and `MemTotal`."""
        cpus = os.cpu_count() or 1
        memory_mb = 1024
        try:
            for line in Path("/proc/meminfo").read_text().splitlines():
                if line.startswith("MemTotal:"):
                    memory_mb = int(line.split()[1]) // 1024
                    break
        except (OSError, ValueError, IndexError):
            pass
        return cls(cpus=cpus, memory_mb=memory_mb)


def default_max_sandboxes(capacity: HostCapacity | None = None) -> int:
    """The conservative constant `default_concurrency()` reports.

    `INSPECT_RANGES_MAX_SANDBOXES` overrides; the default assumes each sample is at least one 2-4 GB guest plus the range container.
    """
    override = os.environ.get("INSPECT_RANGES_MAX_SANDBOXES")
    if override is not None:
        value = int(override)
        if value < 1:
            raise ValueError(f"INSPECT_RANGES_MAX_SANDBOXES must be >= 1, got {value}")
        return value
    capacity = capacity or HostCapacity.measure()
    return max(1, min(capacity.cpus // 2, capacity.memory_mb // (8 * 1024)))


class WeightedAdmission:
    """Async weighted gate: `acquire` charges a plan's totals, `release` refunds them.

    Single-event-loop by design (Inspect runs a task's samples in one loop); construct inside the loop that uses it.
    """

    def __init__(self, capacity: HostCapacity) -> None:
        self.capacity = capacity
        self._free_cpus = capacity.cpus
        self._free_memory_mb = capacity.memory_mb
        self._condition = asyncio.Condition()

    async def acquire(self, totals: Totals) -> None:
        """Wait for capacity and charge `totals`.

        Raises:
            AdmissionRefused: The range alone exceeds the host; waiting would hang forever.
        """
        if (
            totals.cpus > self.capacity.cpus
            or totals.memory_mb > self.capacity.memory_mb
        ):
            raise AdmissionRefused(
                f"range needs {totals.cpus} vCPUs / {totals.memory_mb} MiB but the "
                f"host has {self.capacity.cpus} vCPUs / {self.capacity.memory_mb} MiB; "
                "it cannot run here at any concurrency"
            )
        async with self._condition:
            await self._condition.wait_for(
                lambda: (
                    self._free_cpus >= totals.cpus
                    and self._free_memory_mb >= totals.memory_mb
                )
            )
            self._free_cpus -= totals.cpus
            self._free_memory_mb -= totals.memory_mb

    async def release(self, totals: Totals) -> None:
        """Refund `totals`; idempotence is the caller's job (release exactly what was acquired, once)."""
        async with self._condition:
            self._free_cpus = min(self.capacity.cpus, self._free_cpus + totals.cpus)
            self._free_memory_mb = min(
                self.capacity.memory_mb, self._free_memory_mb + totals.memory_mb
            )
            self._condition.notify_all()

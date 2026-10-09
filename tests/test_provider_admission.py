"""Slice-2 review-round battery: FIFO admission and the regression pins."""

import asyncio
from pathlib import Path

import pytest
from inspect_ranges._compiler.plan import Totals
from inspect_ranges._provider.admission import (
    AdmissionRefused,
    HostCapacity,
    WeightedAdmission,
    default_max_sandboxes,
)
from inspect_ranges._provider.naming import PROVIDER_CID_BASE, CidAllocator
from inspect_ranges._provider.retry import RetryPolicy, RetryStats, with_retry


def totals(cpus: int, memory_mb: int) -> Totals:
    return Totals(guests=1, cpus=cpus, memory_mb=memory_mb)


def test_refusal_is_immediate_not_a_hang() -> None:
    async def scenario() -> None:
        gate = WeightedAdmission(HostCapacity(cpus=4, memory_mb=4096))
        with pytest.raises(AdmissionRefused, match="cannot run here"):
            await gate.acquire(totals(8, 1024))

    asyncio.run(scenario())


def test_fifo_prevents_starvation_of_a_large_waiter() -> None:
    """A near-capacity waiter is served before smaller samples that arrived after it."""

    async def scenario() -> None:
        gate = WeightedAdmission(HostCapacity(cpus=4, memory_mb=4096))
        await gate.acquire(totals(3, 3072))  # most of the host is busy
        order: list[str] = []

        async def big() -> None:
            await gate.acquire(totals(4, 4096))
            order.append("big")
            await gate.release(totals(4, 4096))

        async def small(name: str) -> None:
            await gate.acquire(totals(1, 512))
            order.append(name)
            await gate.release(totals(1, 512))

        big_task = asyncio.create_task(big())
        await asyncio.sleep(0.01)  # the big waiter queues first
        small_tasks = [asyncio.create_task(small(f"s{i}")) for i in range(3)]
        await asyncio.sleep(0.01)
        await gate.release(totals(3, 3072))  # frees capacity: FIFO must serve big first
        await asyncio.wait_for(asyncio.gather(big_task, *small_tasks), timeout=5.0)
        assert order[0] == "big", f"the large waiter starved: {order}"

    asyncio.run(scenario())


def test_cancelled_waiter_leaves_the_queue_clean() -> None:
    async def scenario() -> None:
        gate = WeightedAdmission(HostCapacity(cpus=2, memory_mb=1024))
        await gate.acquire(totals(2, 1024))
        waiter = asyncio.create_task(gate.acquire(totals(1, 512)))
        await asyncio.sleep(0.01)
        waiter.cancel()
        with pytest.raises(asyncio.CancelledError):
            await waiter
        await gate.release(totals(2, 1024))
        # capacity is whole again: a full-capacity acquire completes at once
        await asyncio.wait_for(gate.acquire(totals(2, 1024)), timeout=1.0)

    asyncio.run(scenario())


def test_default_max_sandboxes_env_override(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("INSPECT_RANGES_MAX_SANDBOXES", "5")
    assert default_max_sandboxes() == 5
    monkeypatch.delenv("INSPECT_RANGES_MAX_SANDBOXES")
    assert default_max_sandboxes(HostCapacity(cpus=16, memory_mb=64 * 1024)) == 8
    assert default_max_sandboxes(HostCapacity(cpus=2, memory_mb=4096)) == 1


def test_deadline_wrapper_passes_through_a_real_timeout() -> None:
    """A TimeoutError raised by the operation itself (a real command timeout) must propagate, never be relabeled as a closed retry window."""

    async def scenario() -> None:
        async def command_timed_out() -> None:
            raise TimeoutError("command budget expired")

        policy = RetryPolicy(attempts=3, wait_initial_s=0.01, deadline_s=10.0)
        with pytest.raises(TimeoutError, match="command budget expired"):
            await with_retry(
                command_timed_out, policy=policy, stats=RetryStats(), op="exec"
            )

    asyncio.run(scenario())


def test_cross_version_lease_entries_reserve_their_blocks(tmp_path: Path) -> None:
    """An entry this version cannot fully parse still RESERVES its block (base/count readable), survives reads and writes verbatim, and never gets overlapped."""
    allocator = CidAllocator(tmp_path)
    allocator.lease("ir-mine", 2)  # 10000-10001
    registry = tmp_path / "cids.json"
    import json

    raw = json.loads(registry.read_text())
    # fails CidLease validation (project must be a string) but its block is readable
    raw["ir-future-version"] = {"base": 10002, "count": 5, "project": 123}
    registry.write_text(json.dumps(raw))
    assert allocator.leased_projects() == ["ir-mine"]  # read-only: no rewrite
    lease = allocator.lease("ir-other", 2)
    assert lease.base >= 10007, "the foreign entry's block must stay reserved"
    persisted = json.loads(registry.read_text())
    assert persisted["ir-future-version"] == {"base": 10002, "count": 5, "project": 123}


def test_undeterminable_lease_entry_fails_allocation_loudly(tmp_path: Path) -> None:
    """When a foreign entry's block cannot be determined, leasing refuses with a named error instead of risking a silent CID overlap under live VMs."""
    from inspect_ranges._provider.naming import CidRegistryError

    allocator = CidAllocator(tmp_path)
    allocator.lease("ir-mine", 1)
    registry = tmp_path / "cids.json"
    import json

    raw = json.loads(registry.read_text())
    raw["ir-broken"] = {"base": "not-an-int", "shape": "unknown"}
    registry.write_text(json.dumps(raw))
    with pytest.raises(CidRegistryError, match="repair or prune"):
        allocator.lease("ir-other", 1)
    # read-only listings still work and never destroy the entry
    assert allocator.leased_projects() == ["ir-mine"]
    assert "ir-broken" in json.loads(registry.read_text())


def test_int_sample_ids_are_stringified(tmp_path: Path) -> None:
    """inspect-ai injects int ids for default datasets; sample_init must not crash."""
    import inspect_ranges._provider.provider as provider_module
    from inspect_ai.util._sandbox.lifecycle import sandbox_lifecycle_scope

    from tests.test_provider_lifecycle import rigged_runtime, small_spec

    async def scenario() -> None:
        with sandbox_lifecycle_scope():
            _runtime, seams = rigged_runtime(tmp_path)
            envs = await provider_module.LibvirtRangeSandboxEnvironment.sample_init(
                "task",
                small_spec(),
                {"__sample_id__": 7},  # type: ignore[dict-item]  (what inspect-ai actually passes)
            )
            project = seams.up_calls[0].project
            assert project is not None and "-7-" in project
            await provider_module.LibvirtRangeSandboxEnvironment.sample_cleanup(
                "task", None, envs, interrupted=False
            )

    asyncio.run(scenario())


def test_cid_blocks_start_in_the_provider_partition(tmp_path: Path) -> None:
    allocator = CidAllocator(tmp_path)
    assert allocator.lease("ir-x", 1).base >= PROVIDER_CID_BASE

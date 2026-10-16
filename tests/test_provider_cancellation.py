"""Mid-acquisition cancellation (quality-review C2): the most intricate provider code had zero coverage.

The contract under test (`_acquire_range`): a cancelled acquisition drains its in-flight futures so the unwind sees everything the attempt created, the unwind runs exactly once, a second cancellation abandons the drain without double-unwinding, and the lease/CID/registry/admission balance holds on every exit. A host lease written by an acquire whose result nobody received has no renewal and is the reaper's to reclaim, per the drain comment.
"""

import asyncio
import threading
from pathlib import Path

import pytest
from inspect_ai.util._sandbox.lifecycle import sandbox_lifecycle_scope
from inspect_ranges._compiler.plan import Totals
from inspect_ranges._host import HostLease, HostProvider, LeasePlacement, SampleSpec
from inspect_ranges._host.reaper import sweep
from inspect_ranges._provider.provider import (
    LibvirtRangeSandboxEnvironment as Env,
)
from inspect_ranges._runtime.ownership import read_owner
from inspect_ranges._runtime.up import UpOptions, UpResult

from tests.test_provider_lifecycle import (
    FakeSeams,
    OnStage,
    lease_store,
    renewal_tasks,
    rigged_runtime,
    small_spec,
)


class BlockingSeams(FakeSeams):
    """FakeSeams whose `up` blocks until released, so a cancel lands mid-boot."""

    def __init__(self, runtime: object) -> None:
        super().__init__(runtime)  # type: ignore[arg-type]
        self.up_started = threading.Event()
        self.release_up = threading.Event()

    def up(
        self, bundle: Path, options: UpOptions, on_stage: OnStage | None = None
    ) -> UpResult:
        self.up_started.set()
        assert self.release_up.wait(timeout=30.0), "test forgot to release up"
        return super().up(bundle, options, on_stage)


async def _wait_for(event: threading.Event) -> None:
    while not event.is_set():
        await asyncio.sleep(0.01)


def test_cancel_mid_boot_drains_and_unwinds_exactly_once(tmp_path: Path) -> None:
    """First cancellation: the drain awaits the in-flight boot, the unwind tears down what it created, and every balance (registry, CID, host lease, admission) is restored."""

    async def scenario() -> None:
        with sandbox_lifecycle_scope():
            runtime, _ = rigged_runtime(tmp_path)
            seams = BlockingSeams(runtime)
            runtime.up_fn = seams.up
            runtime.down_fn = seams.down
            runtime.render_fn = seams.render
            task = asyncio.create_task(
                Env.sample_init("task", small_spec(), {"__sample_id__": "c1"})
            )
            await _wait_for(seams.up_started)
            task.cancel()
            # the drain is shielded: the boot completes under it
            seams.release_up.set()
            with pytest.raises(asyncio.CancelledError):
                await task
            project = seams.up_calls[0].project
            assert project is not None
            assert seams.down_calls == [project], (
                "the drained boot created a range; the unwind tears exactly it down"
            )
            assert runtime.registry == {}
            assert runtime.allocator.leased_projects() == []
            assert lease_store(runtime).leases() == []
            assert renewal_tasks() == []
            # admission fully refunded: the whole capacity is acquirable at once
            await asyncio.wait_for(
                runtime.admission.acquire(
                    Totals(guests=1, cpus=8, memory_mb=16_384)
                ),
                timeout=1.0,
            )

    asyncio.run(scenario())


def test_second_cancellation_abandons_the_drain_and_unwinds_once(
    tmp_path: Path,
) -> None:
    """A second cancellation abandons the drain (the unwind still runs, once); the up thread finishing later leaves only the provider-marked owner residue the recorded recovery paths own."""

    async def scenario() -> None:
        with sandbox_lifecycle_scope():
            runtime, _ = rigged_runtime(tmp_path)
            seams = BlockingSeams(runtime)
            runtime.up_fn = seams.up
            runtime.down_fn = seams.down
            runtime.render_fn = seams.render
            task = asyncio.create_task(
                Env.sample_init("task", small_spec(), {"__sample_id__": "c2"})
            )
            await _wait_for(seams.up_started)
            task.cancel()
            await asyncio.sleep(0.05)  # the drain is now shielding the boot
            task.cancel()  # second cancellation: abandon the drain
            with pytest.raises(asyncio.CancelledError):
                await task
            # the unwind ran exactly once: balances restored while the up
            # thread is STILL blocked (nothing waited for it)
            assert runtime.registry == {}
            assert runtime.allocator.leased_projects() == []
            await asyncio.wait_for(
                runtime.admission.acquire(
                    Totals(guests=1, cpus=8, memory_mb=16_384)
                ),
                timeout=1.0,
            )
            await runtime.admission.release(Totals(guests=1, cpus=8, memory_mb=16_384))
            # release the abandoned thread; its late owner record is the
            # residue of an abandoned boot (the provider never marks it, since
            # _mark_provider_owned runs post-boot on the received path): the
            # recovery surface is `inspect-ranges down`/`down --all`, with the
            # host lease (test below) the reaper's half of the story
            assert lease_store(runtime).leases() == [], (
                "the unwind released the host lease the acquire had written"
            )
            seams.release_up.set()
            for _ in range(200):
                if seams.up_calls:
                    break
                await asyncio.sleep(0.02)
            project = seams.up_calls[0].project
            assert project is not None
            for _ in range(100):
                if read_owner(runtime.state_dir, project) is not None:
                    break
                await asyncio.sleep(0.02)
            assert read_owner(runtime.state_dir, project) is not None

    asyncio.run(scenario())


def test_cancel_during_host_acquire_leaves_a_reaper_recoverable_lease(
    tmp_path: Path,
) -> None:
    """The drained-but-never-received host lease: a cancelled acquire that already wrote the lease leaves it renewal-less, and the reaper reclaims it after expiry (the drain comment's recovery story, now pinned)."""

    async def scenario() -> None:
        with sandbox_lifecycle_scope():
            runtime, seams = rigged_runtime(tmp_path)
            inner = runtime.host_provider
            gate = asyncio.Event()

            class BlockingHostProvider:
                async def acquire(
                    self, sample: SampleSpec, placement: LeasePlacement
                ) -> object:
                    await gate.wait()
                    return await inner.acquire(sample, placement)

                async def release(self, host: object) -> None:
                    await inner.release(host)  # type: ignore[arg-type]

                async def abandon(self, host: object) -> None:
                    await inner.abandon(host)  # type: ignore[arg-type]

            runtime.host_provider = BlockingHostProvider()  # type: ignore[assignment]
            task = asyncio.create_task(
                Env.sample_init("task", small_spec(), {"__sample_id__": "c3"})
            )
            for _ in range(200):
                if not gate.is_set() and len(seams.render_calls) > 0:
                    break
                await asyncio.sleep(0.01)
            task.cancel()
            await asyncio.sleep(0.05)
            task.cancel()  # abandon the drain while the host acquire pends
            with pytest.raises(asyncio.CancelledError):
                await task
            # let the cancelled-but-shielded acquire finish writing its lease
            gate.set()
            store = lease_store(runtime)
            for _ in range(200):
                if store.leases():
                    break
                await asyncio.sleep(0.01)
            leases = store.leases()
            if leases:
                # nobody received the handle: no renewal task may exist
                assert renewal_tasks() == []
                # the reaper reclaims it once expired
                store.mark_reaping(leases[0].lease_id)
                outcomes = sweep(
                    runtime.state_dir,
                    store=store,
                    down_fn=lambda project, state_dir: None,  # type: ignore[arg-type, return-value]
                )
                assert [outcome.outcome for outcome in outcomes] == ["reaped"]
                assert store.leases() == []

    asyncio.run(scenario())

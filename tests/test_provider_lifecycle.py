"""Slice-2 battery: provider lifecycle over injected seams (no VMs, no docker).

The up/down/render seams are fakes; the channel is the REAL `MessageChannel` over `LoopbackTransport`, so session pings and guest wiring run through genuine code.
"""

import asyncio
import logging
from pathlib import Path

import pytest
from inspect_ai.util._sandbox.lifecycle import sandbox_lifecycle_scope
from inspect_ranges._channel.channel import LoopbackTransport, MessageChannel
from inspect_ranges._compiler.plan import (
    PlanOptions,
    ResolvedPlan,
    Totals,
    resolve_plan,
)
from inspect_ranges._provider.admission import AdmissionRefused, HostCapacity
from inspect_ranges._provider.provider import LibvirtRangeSandboxEnvironment as Env
from inspect_ranges._provider.state import ProviderRuntime, provider_runtime
from inspect_ranges._runtime.down import DownResult
from inspect_ranges._runtime.ownership import owner_record, read_owner, write_owner
from inspect_ranges._runtime.up import GuestState, UpError, UpOptions, UpResult
from inspect_ranges.types import (
    Attacker,
    Host,
    Interface,
    Network,
    Os,
    RangeMeta,
    RangeSpec,
)


def small_spec(name: str = "lifecycle") -> RangeSpec:
    return RangeSpec(
        meta=RangeMeta(name=name, description="lifecycle battery range"),
        networks=[Network(name="lab", cidr="10.9.0.0/24", mode="isolated")],
        hosts=[
            Host(
                name="web",
                os=Os(type="linux"),
                image="img",
                interfaces=[Interface(network="lab")],
            )
        ],
        attacker=Attacker(interfaces=[Interface(network="lab")], entry="external"),
    )


class FakeSeams:
    """Recording fakes for up/down/render; failures injectable per call."""

    def __init__(self, runtime: ProviderRuntime) -> None:
        self.runtime = runtime
        self.up_calls: list[UpOptions] = []
        self.down_calls: list[str] = []
        self.render_calls: list[Path] = []
        self.up_errors: list[UpError] = []
        self.down_errors: list[Exception] = []
        self.registered_at_up: list[bool] = []
        self.plans: dict[str, ResolvedPlan] = {}

    def render(self, spec: RangeSpec, out: Path, options: PlanOptions) -> ResolvedPlan:
        self.render_calls.append(out)
        out.mkdir(parents=True, exist_ok=True)
        plan = resolve_plan(spec, options)
        self.plans[str(out)] = plan
        return plan

    def up(self, bundle: Path, options: UpOptions) -> UpResult:
        assert options.project is not None
        self.up_calls.append(options)
        self.registered_at_up.append(options.project in self.runtime.registry)
        if self.up_errors:
            raise self.up_errors.pop(0)
        plan = self.plans[str(bundle)]
        # mimic the real up: ownership registers before resources
        write_owner(
            self.runtime.state_dir,
            owner_record(options.project, plan.range.name, "0" * 64, bundle),
        )
        guests = [
            GuestState(name=guest.name, cid=guest.cid, ready=True)
            for guest in plan.guests
        ]
        return UpResult(
            project=options.project,
            range_name=plan.range.name,
            guests=guests,
            seconds=0.1,
        )

    def down(self, project: str, state_dir: Path) -> DownResult:
        self.down_calls.append(project)
        if self.down_errors:
            raise self.down_errors.pop(0)
        return DownResult(project=project, containers=1, volumes=1, networks=1)


def rigged_runtime(tmp_path: Path) -> tuple[ProviderRuntime, FakeSeams]:
    runtime = provider_runtime()
    runtime.state_dir = tmp_path / "projects"
    runtime.state_dir.mkdir(parents=True, exist_ok=True)
    runtime.image_cache = tmp_path / "images"
    runtime.capacity = HostCapacity(cpus=8, memory_mb=16_384)
    seams = FakeSeams(runtime)
    runtime.up_fn = seams.up
    runtime.down_fn = seams.down
    runtime.render_fn = seams.render
    runtime.channel_factory = lambda cids, label: MessageChannel(
        LoopbackTransport(guests=tuple(cids)), label=label
    )
    return runtime, seams


def test_sample_init_boots_and_orders_the_default_first(tmp_path: Path) -> None:
    async def scenario() -> None:
        with sandbox_lifecycle_scope():
            runtime, seams = rigged_runtime(tmp_path)
            envs = await Env.sample_init("task", small_spec(), {"__sample_id__": "s1"})
            assert list(envs) == ["attacker", "web"], (
                "the attacker is the default sandbox and must come first"
            )
            assert all(isinstance(env, Env) for env in envs.values())
            assert len(seams.up_calls) == 1
            project = seams.up_calls[0].project
            assert project is not None and project.startswith("ir-lifecycle-s1-")
            assert seams.registered_at_up == [True], (
                "the handle must be registered before up is called"
            )
            record = read_owner(runtime.state_dir, project)
            assert record is not None and record.origin == "provider"
            assert record.sample_id == "s1" and record.cid_base is not None
            await Env.sample_cleanup("task", None, envs, interrupted=False)
            assert seams.down_calls == [project]
            assert runtime.registry == {}
            assert runtime.allocator.leased_projects() == []

    asyncio.run(scenario())


def test_same_spec_concurrent_samples_are_disjoint(tmp_path: Path) -> None:
    async def scenario() -> None:
        with sandbox_lifecycle_scope():
            runtime, seams = rigged_runtime(tmp_path)
            spec = small_spec()
            first, second = await asyncio.gather(
                Env.sample_init("task", spec, {"__sample_id__": "s1"}),
                Env.sample_init("task", spec, {"__sample_id__": "s1"}),
            )
            projects = [options.project for options in seams.up_calls]
            assert len(set(projects)) == 2, "same-spec samples must not collide"
            handles = list(runtime.registry.values())
            spans = sorted(
                (handle.cid_base, handle.cid_base + handle.totals.guests)
                for handle in handles
            )
            assert spans[0][1] <= spans[1][0], "CID blocks must be disjoint"
            await Env.sample_cleanup("task", None, first, interrupted=False)
            await Env.sample_cleanup("task", None, second, interrupted=False)
            assert runtime.allocator.leased_projects() == []

    asyncio.run(scenario())


def test_render_failure_unwinds_everything(tmp_path: Path) -> None:
    async def scenario() -> None:
        with sandbox_lifecycle_scope():
            runtime, _seams = rigged_runtime(tmp_path)

            def broken_render(
                spec: RangeSpec, out: Path, options: PlanOptions
            ) -> ResolvedPlan:
                raise OSError("disk full")

            runtime.render_fn = broken_render
            with pytest.raises(OSError, match="disk full"):
                await Env.sample_init("task", small_spec(), {})
            assert runtime.registry == {}
            assert runtime.allocator.leased_projects() == []
            staging = list(runtime.staging_root().iterdir())
            assert staging == [], f"staging leaked: {staging}"
            # admission fully refunded: a capacity-sized acquire completes at once
            await asyncio.wait_for(
                runtime.admission.acquire(_capacity_totals(runtime)), timeout=1.0
            )

    asyncio.run(scenario())


def _capacity_totals(runtime: ProviderRuntime) -> Totals:
    return Totals(
        guests=1,
        cpus=runtime.capacity.cpus,
        memory_mb=runtime.capacity.memory_mb,
    )


def test_transient_up_respins_with_fresh_identity(tmp_path: Path) -> None:
    async def scenario() -> None:
        with sandbox_lifecycle_scope():
            runtime, seams = rigged_runtime(tmp_path)
            seams.up_errors = [UpError("readiness", "guests not ready: web")]
            envs = await Env.sample_init("task", small_spec(), {"__sample_id__": "r"})
            assert len(seams.up_calls) == 2
            first, second = (options.project for options in seams.up_calls)
            assert first != second, "a respin must use a fresh project identity"
            assert seams.down_calls == [first], (
                "the failed attempt is downed before the respin"
            )
            assert runtime.allocator.leased_projects() == [second]
            await Env.sample_cleanup("task", None, envs, interrupted=False)

    asyncio.run(scenario())


def test_permanent_up_failure_never_respins(tmp_path: Path) -> None:
    async def scenario() -> None:
        with sandbox_lifecycle_scope():
            runtime, seams = rigged_runtime(tmp_path)
            seams.up_errors = [UpError("verify-bundle", "digest mismatch")]
            with pytest.raises(UpError, match="digest mismatch"):
                await Env.sample_init("task", small_spec(), {})
            assert len(seams.up_calls) == 1, "verification failures are permanent"
            assert runtime.registry == {}
            assert runtime.allocator.leased_projects() == []

    asyncio.run(scenario())


def test_interrupt_defers_teardown_to_task_cleanup(tmp_path: Path) -> None:
    async def scenario() -> None:
        with sandbox_lifecycle_scope():
            runtime, seams = rigged_runtime(tmp_path)
            envs = await Env.sample_init("task", small_spec(), {"__sample_id__": "i"})
            await Env.sample_cleanup("task", None, envs, interrupted=True)
            assert seams.down_calls == [], "interrupted teardown must defer"
            assert len(runtime.registry) == 1
            handle = next(iter(runtime.registry.values()))
            assert handle.deferred
            await Env.task_cleanup("task", None, cleanup=True)
            assert seams.down_calls == [handle.project]
            assert runtime.registry == {}
            assert runtime.allocator.leased_projects() == []

    asyncio.run(scenario())


def test_cleanup_false_leaves_ranges_up_with_recovery_commands(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    async def scenario() -> None:
        with sandbox_lifecycle_scope():
            runtime, seams = rigged_runtime(tmp_path)
            envs = await Env.sample_init("task", small_spec(), {"__sample_id__": "k"})
            await Env.sample_cleanup("task", None, envs, interrupted=True)
            with caplog.at_level(logging.WARNING, logger="inspect_ranges.provider"):
                await Env.task_cleanup("task", None, cleanup=False)
            assert seams.down_calls == []
            assert len(runtime.registry) == 1, "the range stays registered"
            messages = " ".join(record.getMessage() for record in caplog.records)
            assert "inspect-ranges down" in messages
            assert "inspect sandbox cleanup libvirt_range" in messages

    asyncio.run(scenario())


def test_task_cleanup_aggregates_failures_and_keeps_them_findable(
    tmp_path: Path,
) -> None:
    async def scenario() -> None:
        with sandbox_lifecycle_scope():
            runtime, seams = rigged_runtime(tmp_path)
            envs_a = await Env.sample_init("task", small_spec(), {"__sample_id__": "a"})
            envs_b = await Env.sample_init("task", small_spec(), {"__sample_id__": "b"})
            await Env.sample_cleanup("task", None, envs_a, interrupted=True)
            await Env.sample_cleanup("task", None, envs_b, interrupted=True)
            seams.down_errors = [RuntimeError("docker wedged")]
            with pytest.raises(RuntimeError, match="docker wedged"):
                await Env.task_cleanup("task", None, cleanup=True)
            assert len(seams.down_calls) == 2, "one failure must not shield the rest"
            # the failed project stays findable: registry entry and lease survive
            assert len(runtime.registry) == 1
            assert len(runtime.allocator.leased_projects()) == 1

    asyncio.run(scenario())


def test_admission_refuses_an_impossible_range(tmp_path: Path) -> None:
    async def scenario() -> None:
        with sandbox_lifecycle_scope():
            runtime, _ = rigged_runtime(tmp_path)
            runtime.capacity = HostCapacity(cpus=1, memory_mb=512)
            with pytest.raises(AdmissionRefused, match="cannot run here"):
                await Env.sample_init("task", small_spec(), {})
            assert runtime.registry == {}
            assert runtime.allocator.leased_projects() == []

    asyncio.run(scenario())


def test_cli_cleanup_recovers_from_on_disk_state(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A SIGKILLed eval leaves a lease and a provider-marked owner record; a fresh process sweeps both."""
    import inspect_ranges._provider.state as state_module

    # a pristine fallback, isolated from other tests (restored by monkeypatch)
    monkeypatch.setattr(state_module, "_fallback_state", None)

    async def scenario() -> None:
        # OUTSIDE any lifecycle scope: the fallback runtime is what a fresh
        # process would construct; rig its seams before cli_cleanup runs
        runtime = provider_runtime()
        runtime.state_dir = tmp_path / "projects"
        runtime.state_dir.mkdir(parents=True, exist_ok=True)
        seams = FakeSeams(runtime)
        runtime.down_fn = seams.down
        # crash shape 1: leased, never booted (no owner record)
        runtime.allocator.lease("ir-crashed-early-000000", 2)
        # crash shape 2: booted and provider-marked, lease present
        runtime.allocator.lease("ir-crashed-late-111111", 2)
        write_owner(
            runtime.state_dir,
            owner_record("ir-crashed-late-111111", "r", "0" * 64, tmp_path).model_copy(
                update={"origin": "provider"}
            ),
        )
        # an operator-run project must never be swept by the provider
        write_owner(
            runtime.state_dir,
            owner_record("ir-operator-run", "r", "1" * 64, tmp_path),
        )
        await Env.cli_cleanup(None)
        assert sorted(seams.down_calls) == [
            "ir-crashed-early-000000",
            "ir-crashed-late-111111",
        ]
        assert runtime.allocator.leased_projects() == []
        assert read_owner(runtime.state_dir, "ir-operator-run") is not None

    asyncio.run(scenario())


def test_config_forms_and_registration() -> None:
    import inspect_ranges._registry as registry_module
    from inspect_ai.util._sandbox.registry import registry_find_sandboxenv

    assert registry_module.LibvirtRangeSandboxEnvironment is Env

    assert registry_find_sandboxenv("libvirt_range") is Env
    assert Env.config_files() == ["range.yaml"]
    assert Env.is_docker_compatible() is False
    spec = small_spec()
    round_tripped = Env.config_deserialize(spec.model_dump(by_alias=True))
    assert isinstance(round_tripped, RangeSpec)
    assert round_tripped == spec
    assert (Env.default_concurrency() or 0) >= 1

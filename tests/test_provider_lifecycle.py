"""Slice-2 battery: provider lifecycle over injected seams (no VMs, no docker).

The up/down/render seams are fakes; the channel is the REAL `MessageChannel` over `LoopbackTransport`, so session pings and guest wiring run through genuine code.
"""

import asyncio
import json
import logging
from collections.abc import Callable
from pathlib import Path

import pytest
from inspect_ai.util._sandbox.lifecycle import sandbox_lifecycle_scope
from inspect_ranges._channel.channel import (
    ChannelError,
    LoopbackTransport,
    MessageChannel,
    TamperError,
)
from inspect_ranges._channel.mocks import HostileTransport
from inspect_ranges._compiler.plan import (
    PlanOptions,
    ResolvedPlan,
    Totals,
    resolve_plan,
)
from inspect_ranges._host import (
    HostLease,
    HostNotReadyError,
    LeaseLostError,
    LeasePlacement,
    LeaseStore,
    LocalHostProvider,
    SampleSpec,
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

    def render(
        self, spec: RangeSpec, out: Path, options: PlanOptions | None
    ) -> ResolvedPlan:
        self.render_calls.append(out)
        out.mkdir(parents=True, exist_ok=True)
        plan = resolve_plan(spec, options)
        # mimic the real render contract: a deterministic manifest.json (its
        # sha256 is the canonical bundle digest the host lease records)
        (out / "manifest.json").write_text(
            json.dumps(
                {
                    "range": plan.range.name,
                    "spec_sha256": plan.range.spec_sha256,
                    "files": {},
                },
                indent=2,
            )
            + "\n"
        )
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
    # a REAL local host provider over a real lease store; only the doctor
    # readiness gate is stubbed out (tests must not probe this machine)
    runtime.host_provider = LocalHostProvider(runtime.state_dir, gate=lambda: [])
    return runtime, seams


def lease_store(runtime: ProviderRuntime) -> LeaseStore:
    return LeaseStore(runtime.state_dir)


def renewal_tasks() -> list["asyncio.Task[None]"]:
    return [
        task
        for task in asyncio.all_tasks()
        if task.get_name().startswith("lease-renewal-")
    ]


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
                spec: RangeSpec, out: Path, options: PlanOptions | None
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
            # the lease stays (the reaper reclaims after expiry) but renewal
            # stops, and the recovery note names the reaper
            assert "inspect-ranges reaper" in messages
            assert len(lease_store(runtime).leases()) == 1
            assert renewal_tasks() == []

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


# -- range-host-v1 slice 2: the host lease through the provider lifecycle ------


def test_sample_holds_one_lease_and_logs_the_isolation_claim(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """Default-local is today's behavior plus exactly one lease and one isolation log line per sample, released (with its renewal task) on destroy."""

    async def scenario() -> None:
        with sandbox_lifecycle_scope():
            runtime, _seams = rigged_runtime(tmp_path)
            with caplog.at_level(logging.INFO, logger="inspect_ranges.host"):
                envs = await Env.sample_init(
                    "task", small_spec(), {"__sample_id__": "s1"}
                )
            leases = lease_store(runtime).leases()
            assert len(leases) == 1
            lease = leases[0]
            assert lease.state == "active"
            assert lease.origin == "local"
            assert lease.isolation == "shared"
            assert lease.task_name == "task" and lease.sample_id == "s1"
            project = next(iter(runtime.registry))
            assert lease.project == project
            assert Path(lease.bundle_path).is_dir(), "the lease names the bundle"
            isolation_lines = [
                record.getMessage()
                for record in caplog.records
                if "isolation=shared" in record.getMessage()
            ]
            assert len(isolation_lines) == 1
            assert len(renewal_tasks()) == 1
            handle = next(iter(runtime.registry.values()))
            assert handle.host is not None
            assert handle.host.channel is handle.channel, (
                "the host carries the post-boot channel (the RangeHost contract)"
            )
            await Env.sample_cleanup("task", None, envs, interrupted=False)
            assert lease_store(runtime).leases() == []
            assert renewal_tasks() == []

    asyncio.run(scenario())


def _rig_permanent_up_failure(runtime: ProviderRuntime, seams: FakeSeams) -> None:
    seams.up_errors.append(UpError("verify-bundle", "digest mismatch"))


def _rig_exhausted_transient_failures(
    runtime: ProviderRuntime, seams: FakeSeams
) -> None:
    seams.up_errors.extend(UpError("guest-boot", "flake") for _ in range(10))


def _rig_channel_factory_failure(runtime: ProviderRuntime, seams: FakeSeams) -> None:
    def broken(cids: dict[str, int], label: str) -> MessageChannel:
        raise RuntimeError("no channel")

    runtime.channel_factory = broken


def _rig_ping_failure(runtime: ProviderRuntime, seams: FakeSeams) -> None:
    # a channel whose transport knows no guests: the boot-confirmation ping fails
    runtime.channel_factory = lambda cids, label: MessageChannel(
        LoopbackTransport(guests=()), label=label
    )


@pytest.mark.parametrize(
    "rig",
    [
        _rig_permanent_up_failure,
        _rig_exhausted_transient_failures,
        _rig_channel_factory_failure,
        _rig_ping_failure,
    ],
    ids=["permanent-up", "exhausted-respins", "channel-factory", "boot-ping"],
)
def test_every_sample_init_early_exit_releases_the_lease(
    tmp_path: Path, rig: "Callable[[ProviderRuntime, FakeSeams], None]"
) -> None:
    async def scenario() -> None:
        with sandbox_lifecycle_scope():
            runtime, seams = rigged_runtime(tmp_path)
            rig(runtime, seams)
            with pytest.raises((UpError, RuntimeError, ChannelError)):
                await Env.sample_init("task", small_spec(), {"__sample_id__": "x"})
            assert lease_store(runtime).leases() == []
            assert renewal_tasks() == []
            assert runtime.allocator.leased_projects() == []
            assert runtime.registry == {}

    asyncio.run(scenario())


def test_respin_releases_the_failed_attempts_lease(tmp_path: Path) -> None:
    async def scenario() -> None:
        with sandbox_lifecycle_scope():
            runtime, seams = rigged_runtime(tmp_path)
            seams.up_errors = [UpError("guest-boot", "flake")]
            envs = await Env.sample_init("task", small_spec(), {"__sample_id__": "r"})
            leases = lease_store(runtime).leases()
            assert len(leases) == 1, "the failed attempt's lease must be gone"
            assert leases[0].project == seams.up_calls[1].project
            assert len(renewal_tasks()) == 1
            await Env.sample_cleanup("task", None, envs, interrupted=False)
            assert renewal_tasks() == []

    asyncio.run(scenario())


def test_interrupted_sample_keeps_lease_and_renewal_until_task_cleanup(
    tmp_path: Path,
) -> None:
    async def scenario() -> None:
        with sandbox_lifecycle_scope():
            runtime, _seams = rigged_runtime(tmp_path)
            envs = await Env.sample_init("task", small_spec(), {"__sample_id__": "i"})
            await Env.sample_cleanup("task", None, envs, interrupted=True)
            # the range stays booted until run end, so the lease stays renewed
            assert len(lease_store(runtime).leases()) == 1
            assert len(renewal_tasks()) == 1
            await Env.task_cleanup("task", None, cleanup=True)
            assert lease_store(runtime).leases() == []
            assert renewal_tasks() == []

    asyncio.run(scenario())


def test_failed_down_frees_neither_lease_nor_renewal(tmp_path: Path) -> None:
    """A failed teardown frees NOTHING: CID lease, host lease, registry entry, and the renewal task all stay until a teardown succeeds."""

    async def scenario() -> None:
        with sandbox_lifecycle_scope():
            runtime, seams = rigged_runtime(tmp_path)
            envs = await Env.sample_init("task", small_spec(), {"__sample_id__": "f"})
            seams.down_errors = [RuntimeError("docker wedged")]
            with pytest.raises(RuntimeError, match="docker wedged"):
                await Env.sample_cleanup("task", None, envs, interrupted=False)
            assert len(lease_store(runtime).leases()) == 1
            assert len(runtime.allocator.leased_projects()) == 1
            assert len(runtime.registry) == 1
            assert len(renewal_tasks()) == 1
            await Env.task_cleanup("task", None, cleanup=True)
            assert lease_store(runtime).leases() == []
            assert renewal_tasks() == []

    asyncio.run(scenario())


def test_unready_host_fails_the_sample_fast_with_the_report(tmp_path: Path) -> None:
    async def scenario() -> None:
        with sandbox_lifecycle_scope():
            runtime, _seams = rigged_runtime(tmp_path)
            runtime.host_provider = LocalHostProvider(
                runtime.state_dir, gate=lambda: ["Docker: Docker daemon: not running"]
            )
            with pytest.raises(HostNotReadyError, match="Docker daemon"):
                await Env.sample_init("task", small_spec(), {"__sample_id__": "g"})
            assert lease_store(runtime).leases() == []
            assert runtime.allocator.leased_projects() == []
            assert runtime.registry == {}

    asyncio.run(scenario())


def test_readiness_gate_runs_once_per_task(tmp_path: Path) -> None:
    async def scenario() -> None:
        with sandbox_lifecycle_scope():
            runtime, _seams = rigged_runtime(tmp_path)
            calls = 0

            def counting_gate() -> list[str]:
                nonlocal calls
                calls += 1
                return []

            runtime.host_provider = LocalHostProvider(
                runtime.state_dir, gate=counting_gate
            )
            # concurrent first acquires share one gate run (the locked fill)
            spec = small_spec()
            first, second = await asyncio.gather(
                Env.sample_init("task", spec, {"__sample_id__": "s1"}),
                Env.sample_init("task", spec, {"__sample_id__": "s2"}),
            )
            await Env.sample_cleanup("task", None, first, interrupted=False)
            await Env.sample_cleanup("task", None, second, interrupted=False)
            assert calls == 1, "the gate is cached per task, not re-run per sample"

    asyncio.run(scenario())


def test_renewal_survives_a_transient_store_failure(tmp_path: Path) -> None:
    """One flock or IO hiccup in the lease store must neither kill the renewal task (the lease would expire under a healthy sample) nor poison release."""

    class FlakyStore(LeaseStore):
        def __init__(self, state_dir: Path) -> None:
            super().__init__(state_dir)
            self.failures = 1

        def renew(self, lease_id: str, ttl_s: float | None = None) -> HostLease:
            if self.failures:
                self.failures -= 1
                raise OSError("flock hiccup")
            return super().renew(lease_id, ttl_s)

    async def scenario() -> None:
        store = FlakyStore(tmp_path / "state")
        provider = LocalHostProvider(
            tmp_path / "state", gate=lambda: [], store=store, ttl_s=0.09
        )
        host = await provider.acquire(
            SampleSpec(
                sample_id="s1",
                task_name="task",
                spec_sha256="a" * 64,
                bundle_digest="b" * 64,
                totals=Totals(guests=1, cpus=1, memory_mb=512),
            ),
            LeasePlacement(project="ir-flaky", bundle_path="/b", staging="/s"),
        )
        minted = host.lease.expires_at
        # at TTL/3 = 30ms per tick: tick one fails, later ticks must still renew
        for _ in range(50):
            await asyncio.sleep(0.03)
            if store.failures == 0 and host.lease.expires_at != minted:
                break
        assert store.failures == 0, "the failing tick happened"
        assert len(renewal_tasks()) == 1, "renewal survived the failure"
        assert host.lease.expires_at != minted, "a later tick renewed"
        host.check_lease()  # a store hiccup is not lease loss
        await provider.release(host)  # never poisoned by the task's error
        assert renewal_tasks() == []
        assert store.leases() == []

    asyncio.run(scenario())


def test_lost_lease_fails_the_next_op_loudly(tmp_path: Path) -> None:
    """The deliberate expiry-mid-sample policy: a reclaimed lease surfaces as `LeaseLostError` at the sample's next operation, never a silent limp."""

    async def scenario() -> None:
        with sandbox_lifecycle_scope():
            runtime, _seams = rigged_runtime(tmp_path)
            envs = await Env.sample_init("task", small_spec(), {"__sample_id__": "l"})
            handle = next(iter(runtime.registry.values()))
            assert handle.host is not None
            # the reaper's side of the race: the lease vanishes behind the driver
            store = lease_store(runtime)
            for lease in store.leases():
                store.release(lease.lease_id)
            from inspect_ranges._host import LocalRangeHost

            assert isinstance(handle.host, LocalRangeHost)
            with pytest.raises(LeaseLostError):
                await handle.host.renew_now()
            with pytest.raises(LeaseLostError):
                await envs["attacker"].exec(["true"])
            # teardown still works (release is idempotent) and cancels renewal
            await Env.sample_cleanup("task", None, envs, interrupted=False)
            assert renewal_tasks() == []

    asyncio.run(scenario())


def test_unknown_host_backend_refuses(tmp_path: Path) -> None:
    with sandbox_lifecycle_scope():
        runtime, _seams = rigged_runtime(tmp_path)
        runtime.host_backend = "fleet"
        runtime._host_provider = None  # pyright: ignore[reportPrivateUsage]
        with pytest.raises(ValueError, match="INSPECT_RANGES_HOST"):
            _ = runtime.host_provider
        runtime.host_backend = "uds:/tmp/applier.sock"
        with pytest.raises(NotImplementedError, match="slice 3"):
            _ = runtime.host_provider


def test_stale_golden_ping_failure_names_the_remedy(tmp_path: Path) -> None:
    """A pre-3.1.0 daemon's session-less pong fails the strict decode tamper-shaped (the recorded stale-golden/new-host hazard); the boot-time failure must name the operator's remedy and still destroy the booted range."""

    async def scenario() -> None:
        with sandbox_lifecycle_scope():
            runtime, seams = rigged_runtime(tmp_path)
            runtime.channel_factory = lambda cids, label: MessageChannel(
                HostileTransport("sessionless-pong"), label=label
            )
            with pytest.raises(TamperError) as info:
                await Env.sample_init("task", small_spec(), {"__sample_id__": "s9"})
            assert "re-derive images" in str(info.value)
            assert seams.down_calls, "the booted range must be destroyed"

    asyncio.run(scenario())

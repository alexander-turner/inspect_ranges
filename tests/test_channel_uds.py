"""The UDS transport across two real OS processes: the portable conformance suite over a subprocess applier, and the provider lifecycle over the derived uds seams (range-host-v1 slice 3)."""

import asyncio
import os
import subprocess
import sys
import time
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

import pytest
from inspect_ranges._channel.channel import ChannelError, MessageChannel
from inspect_ranges._channel.uds import UdsTransport
from inspect_ranges._host.applier import Applier
from inspect_ranges._host.leases import LeaseStore
from inspect_ranges._provider.admission import HostCapacity
from inspect_ranges._provider.state import ProviderRuntime

from tests.applier_fixture import (
    FakeGuestConnector,
    fake_down,
    fake_up,
    make_bundle,
    wait_for_socket,
)
from tests.test_host_leases import facts
from tests.test_provider_lifecycle import FakeSeams, rigged_runtime

REPO_ROOT = Path(__file__).parent.parent


@dataclass(frozen=True)
class UdsFixture:
    socket_path: Path
    state_dir: Path
    lease_id: str
    digest: str


def _wait_for_route(socket_path: Path, lease_id: str, guest: str = "web") -> None:
    """Block until the fixture's registrar has mapped the lease's guest (the fixture polls the store)."""

    async def probe() -> None:
        channel = MessageChannel(
            UdsTransport(socket_path, lease_id, ack_timeout_s=2.0), label="probe"
        )
        await channel.ping(guest)

    deadline = time.monotonic() + 15.0
    while True:
        try:
            asyncio.run(probe())
            return
        except (ChannelError, ConnectionError):
            if time.monotonic() > deadline:
                raise
            time.sleep(0.05)


@pytest.fixture(scope="module")
def uds_applier(tmp_path_factory: pytest.TempPathFactory) -> Iterator[UdsFixture]:
    """One applier fixture SUBPROCESS for the module: a real second OS process serving the socket."""
    root = tmp_path_factory.mktemp("uds-conformance")
    socket_path = root / "sock" / "applier.sock"
    state_dir = root / "state"
    bundle = root / "bundle"
    digest = make_bundle(bundle)
    staging = root / "staging"
    staging.mkdir(parents=True, exist_ok=True)
    lease = LeaseStore(state_dir).acquire(
        project="ir-uds-conformance",
        task_name="conformance",
        sample_id="s1",
        isolation="shared",
        origin=f"uds:{socket_path}",
        bundle_path=str(bundle),
        bundle_digest=digest,
        staging=str(staging),
        host_facts=facts(),
        ttl_s=3600,
    )
    process = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "tests.applier_fixture",
            "--socket",
            str(socket_path),
            "--state-dir",
            str(state_dir),
            "--mode",
            "conformance",
        ],
        cwd=REPO_ROOT,
    )
    try:
        wait_for_socket(socket_path)
        _wait_for_route(socket_path, lease.lease_id)
        yield UdsFixture(socket_path, state_dir, lease.lease_id, digest)
    finally:
        process.terminate()
        process.wait(timeout=10)


from tests.channel_conformance import PortableChannelSuite  # noqa: E402


class TestUdsTwoProcessConformance(PortableChannelSuite):
    """The full portable contract over the preamble, routed-ack, and byte-pump relay, applier in a second OS process."""

    has_host_plane = True

    @pytest.fixture
    def channel(self, uds_applier: UdsFixture) -> MessageChannel:
        self._fixture = uds_applier
        return MessageChannel(
            UdsTransport(uds_applier.socket_path, uds_applier.lease_id),
            label="uds-conformance",
        )

    def realize_digest(self) -> str:
        return self._fixture.digest


# -- the live-applier battery gate (design/spikes/range-host-v1) --------------------

LIVE_SOCKET = os.environ.get("IR_UDS_BATTERY_SOCKET", "")
LIVE_LEASE = os.environ.get("IR_UDS_BATTERY_LEASE", "")
LIVE_DIGEST = os.environ.get("IR_UDS_BATTERY_DIGEST", "ab" * 32)
LIVE_GUEST = os.environ.get("IR_UDS_BATTERY_GUEST", "attacker")


@pytest.mark.skipif(
    not LIVE_SOCKET,
    reason="no live applier (set IR_UDS_BATTERY_SOCKET; see design/spikes/range-host-v1)",
)
class TestUdsLiveApplier(PortableChannelSuite):
    """The portable suite over the LIVE applier and realizer-booted guests, `realize_digest()` at a genuinely rendered bundle.

    The battery drives this class in three sequential pytest phases (realize first, which BOOTS the lease's range through the real applier; then the guest-plane tests over the registered relay; teardown last), because `up` is deliberately not re-runnable on a booted project (`virsh define` is not idempotent) while the suite's file order puts guest tests before the host plane.
    """

    guest = LIVE_GUEST
    has_host_plane = True
    probe_user = "agent"  # the recipe-v4 golden's exec identity

    @pytest.fixture
    def channel(self) -> MessageChannel:
        return MessageChannel(
            UdsTransport(Path(LIVE_SOCKET), LIVE_LEASE), label="uds-live"
        )

    def realize_digest(self) -> str:
        return LIVE_DIGEST

    # the fixture-contract vocabulary, mapped to a real Linux guest
    def argv_stderr(self, text: str) -> tuple[list[str], int]:
        return ["sh", "-c", f"printf '%s\\n' '{text}' >&2; exit 2"], 2

    def argv_sleep_ms(self, ms: int) -> list[str]:
        return ["sh", "-c", f"sleep {ms / 1000}"]

    def argv_env_probe(self) -> list[str]:
        return [
            "sh",
            "-c",
            'printf "cwd=%s\\nuser=%s\\nANSWER=%s\\n" "$(pwd)" "$(id -un)" "$ANSWER"',
        ]


# -- the provider lifecycle over the derived uds seams (in-process applier) ---------


def _uds_rig(
    tmp_path: Path, capacity: HostCapacity | None = None
) -> tuple[ProviderRuntime, FakeSeams, Applier]:
    """A rigged runtime whose backend is `uds:` against an in-process applier sharing its state dir."""
    runtime, seams = rigged_runtime(tmp_path)
    socket_path = tmp_path / "sock" / "applier.sock"
    runtime.host_backend = f"uds:{socket_path}"
    runtime._host_provider = None  # pyright: ignore[reportPrivateUsage]
    _ = runtime.host_provider  # installs the remote provider AND the derived seams
    connector = FakeGuestConnector(auto_create=True)
    applier = Applier(
        socket_path,
        runtime.state_dir,
        image_cache=tmp_path / "cache",
        up_fn=fake_up,
        down_fn=fake_down,
        guest_connector=connector,
        capacity=capacity or HostCapacity(cpus=64, memory_mb=1 << 20),
        gate=lambda: [],
    )
    return runtime, seams, applier


def test_remote_seams_install_at_runtime_construction(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A fresh `ProviderRuntime` under `INSPECT_RANGES_HOST=uds:` carries the derived seams from birth: paths that never touch `host_provider` (cli_cleanup foremost) still tear down THROUGH the applier instead of leaking its charge behind a direct down."""
    monkeypatch.setenv("INSPECT_RANGES_HOST", f"uds:{tmp_path / 'applier.sock'}")
    runtime = ProviderRuntime()
    assert runtime.down_fn.__module__ == "inspect_ranges._host.remote"
    assert runtime.up_fn.__module__ == "inspect_ranges._host.remote"
    assert runtime.channel_factory.__module__ == "inspect_ranges._host.remote"


@pytest.mark.parametrize(
    "before_stage",
    [
        "fetch",  # the first-use range-image build sits before any report
        "boot",  # compose up --wait sits after construct
        "verify",  # the guest-boot exec sits after boot
    ],
)
def test_uds_up_fn_gap_allowances_cover_the_silent_up_phases(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, before_stage: str
) -> None:
    """The driver's realize survives every legally silent up phase (worst: a first-use image build before the first report) instead of tripping `ChannelBudgetError` at the flat per-report budget (quality-review R2-3)."""
    from inspect_ranges._host import remote
    from inspect_ranges._host.leases import HostLease
    from inspect_ranges._runtime.up import UpOptions

    from tests.test_channel_mocks import SlowGapApplierTransport

    bundle = tmp_path / "bundle"
    make_bundle(bundle)
    state_dir = tmp_path / "state"
    LeaseStore(state_dir).acquire(
        project="ir-slow-phase",
        task_name="t",
        sample_id="s1",
        isolation="shared",
        origin="uds:unused",
        bundle_path=str(bundle),
        bundle_digest="ab" * 32,
        staging=str(tmp_path / "staging"),
        host_facts=facts(),
        ttl_s=3600,
    )

    def tiny_budget_channel(
        socket_path: Path, lease: HostLease, label: str
    ) -> MessageChannel:
        # a 0.1 s per-report budget makes any uncovered gap trip instantly;
        # the 0.4 s delay stands in for the gap's legitimate slow occupant
        return MessageChannel(
            SlowGapApplierTransport(before_stage=before_stage, delay_s=0.4),
            label=label,
            channel_budget_s=0.1,
        )

    monkeypatch.setattr(remote, "_lease_channel", tiny_budget_channel)
    up_fn, _down_fn, _factory = remote.remote_seams(
        tmp_path / "applier.sock", state_dir
    )
    result = up_fn(
        bundle, UpOptions(project="ir-slow-phase", image_cache=tmp_path / "cache"), None
    )
    assert all(guest.ready for guest in result.guests)


def test_realize_gap_allowances_floor_at_each_occupants_bound(tmp_path: Path) -> None:
    """The driver's per-gap envelopes dominate the up-side bounds that legally occupy them, floored at the applier's own defaults when the driver configures shorter (quality-review R2-3)."""
    from inspect_ranges._compiler.plan import ResolvedPlan
    from inspect_ranges._host.remote import realize_gap_allowances
    from inspect_ranges._runtime.up import IMAGE_BUILD_TIMEOUT_S, UpOptions

    bundle = tmp_path / "bundle"
    make_bundle(bundle)
    plan = ResolvedPlan.model_validate_json((bundle / "plan.json").read_text())
    short = UpOptions(
        image_cache=tmp_path, readiness_timeout=1.0, readiness_min_window=0.2
    )
    allowances = realize_gap_allowances(plan, short)
    # the applier probes with ITS defaults (300 s / 10 s); a driver configured
    # shorter must not starve a legitimately slower applier pass
    assert allowances[None] >= IMAGE_BUILD_TIMEOUT_S
    assert allowances["construct"] >= 300.0 + 60.0
    assert allowances["boot"] >= 300.0
    assert allowances["verify"] >= 300.0 + len(plan.guests) * 10.0
    assert "fetch" not in allowances, (
        "the fetch -> construct gap has no legitimate occupant; the flat "
        "allowance must keep catching a stall there"
    )
    long = UpOptions(image_cache=tmp_path, readiness_timeout=900.0)
    assert realize_gap_allowances(plan, long)["construct"] >= 900.0 + 60.0


def test_provider_lifecycle_over_the_uds_backend(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """`INSPECT_RANGES_HOST=uds:` end to end on CI: sample_init realizes through the applier, ops relay to guests, teardown goes through `channel.teardown`, and every lease is released."""
    monkeypatch.delenv("INSPECT_RANGES_REGISTER_ALL_GUESTS", raising=False)
    from inspect_ai.util._sandbox.lifecycle import sandbox_lifecycle_scope
    from inspect_ranges._provider.provider import (
        LibvirtRangeSandboxEnvironment as Env,
    )

    from tests.test_provider_lifecycle import lease_store, renewal_tasks, small_spec

    async def scenario() -> None:
        with sandbox_lifecycle_scope():
            runtime, _seams, applier = _uds_rig(tmp_path)
            await applier.start()
            try:
                envs = await Env.sample_init(
                    "task", small_spec(), {"__sample_id__": "u1"}
                )
                assert list(envs) == ["attacker"], (
                    "foothold-only registration holds over the uds backend too"
                )
                leases = lease_store(runtime).leases()
                assert len(leases) == 1
                assert leases[0].origin == f"uds:{tmp_path / 'sock' / 'applier.sock'}"
                result = await envs["attacker"].exec(["echo", "over uds"])
                assert result.returncode == 0 and result.stdout == "over uds\n"
                await Env.sample_cleanup("task", None, envs, interrupted=False)
                assert lease_store(runtime).leases() == []
                assert renewal_tasks() == []
                assert runtime.allocator.leased_projects() == []
            finally:
                await applier.aclose()

    asyncio.run(scenario())


def test_admission_eagain_respins_and_enospc_refuses_permanently(
    tmp_path: Path,
) -> None:
    """An `EAGAIN` refusal folds to `UpError("admission")` and gets the transient respin; `ENOSPC` stays a typed `HostRefused` and never respins."""
    from inspect_ai.util._sandbox.lifecycle import sandbox_lifecycle_scope
    from inspect_ranges._channel.channel import HostRefused
    from inspect_ranges._compiler.plan import Totals
    from inspect_ranges._provider.admission import HostCapacity
    from inspect_ranges._provider.provider import (
        LibvirtRangeSandboxEnvironment as Env,
    )
    from inspect_ranges._runtime.up import UpError

    from tests.test_provider_lifecycle import lease_store, small_spec

    async def scenario() -> None:
        with sandbox_lifecycle_scope():
            # capacity fits the 2-cpu range exactly; a 1-cpu pre-charge makes
            # it full-now (EAGAIN) for every attempt
            runtime, seams, applier = _uds_rig(
                tmp_path, capacity=HostCapacity(cpus=2, memory_mb=8192)
            )
            await applier.start()
            try:
                assert applier.admission.charge_now(
                    Totals(guests=1, cpus=1, memory_mb=1024)
                )
                with pytest.raises(UpError) as eagain:
                    await Env.sample_init("task", small_spec(), {"__sample_id__": "e"})
                assert eagain.value.stage == "admission"
                assert len(seams.render_calls) == runtime.retry_config.up_attempts, (
                    "EAGAIN is transient: every attempt respun with fresh identity"
                )
                assert lease_store(runtime).leases() == []
                assert runtime.allocator.leased_projects() == []
            finally:
                await applier.aclose()

    asyncio.run(scenario())

    async def enospc_scenario() -> None:
        with sandbox_lifecycle_scope():
            runtime, seams, applier = _uds_rig(
                tmp_path / "enospc", capacity=HostCapacity(cpus=1, memory_mb=512)
            )
            await applier.start()
            try:
                with pytest.raises(HostRefused) as refusal:
                    await Env.sample_init("task", small_spec(), {"__sample_id__": "n"})
                assert refusal.value.errno == "ENOSPC"
                assert len(seams.render_calls) == 1, "a permanent refusal never respins"
                assert lease_store(runtime).leases() == []
            finally:
                await applier.aclose()

    asyncio.run(enospc_scenario())

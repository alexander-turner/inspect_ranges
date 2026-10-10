"""The UDS transport across two real OS processes: the portable conformance suite over a subprocess applier, and the provider lifecycle over the derived uds seams (range-host-v1 slice 3)."""

import asyncio
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


def test_provider_lifecycle_over_the_uds_backend(tmp_path: Path) -> None:
    """`INSPECT_RANGES_HOST=uds:` end to end on CI: sample_init realizes through the applier, ops relay to guests, teardown goes through `channel.teardown`, and every lease is released."""
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
                assert list(envs) == ["attacker", "web"]
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

"""`vmm: cloud-hypervisor` guests: the schema field, what render and the boot script emit, and reaching the guest through Cloud Hypervisor's hybrid-vsock Unix socket."""

import asyncio
import json
import os
import tempfile
from collections.abc import Iterator
from pathlib import Path
from typing import Any, cast

import pytest
from inspect_ranges._channel.channel import (
    ByteStream,
    FakeGuest,
    MessageChannel,
    TransportFailure,
)
from inspect_ranges._channel.vsock import (
    HybridEndpoint,
    PeerCredentialMismatch,
    VsockTransport,
)
from inspect_ranges._compiler import PlanOptions, render_bundle, resolve_plan
from inspect_ranges._host.applier import cloud_hypervisor_connector
from inspect_ranges._runtime.ownership import ch_vsock_dir, prepare_ch_vsock_dir
from inspect_ranges._runtime.up import BootGuest, boot_script, load_boot
from inspect_ranges.types import Attacker, Host, Interface, IssueError, Os, RangeSpec
from pydantic import ValidationError

from tests.applier_fixture import serve_guest
from tests.test_compiler import two_segment_spec


@pytest.fixture()
def cache(tmp_path: Path) -> Path:
    cache = tmp_path / "cache"
    cache.mkdir()
    (cache / "img.qcow2").write_bytes(b"fake golden")
    (cache / "ubuntu-noble.qcow2").write_bytes(b"fake router golden")
    (cache / "attack.qcow2").write_bytes(b"fake attack golden")
    return cache


@pytest.fixture()
def short_dir() -> Iterator[Path]:
    # AF_UNIX paths cap at 108 bytes; pytest's tmp_path can exceed that
    with tempfile.TemporaryDirectory(prefix="ch", dir="/tmp") as directory:
        yield Path(directory)


def ch_spec(*names: str) -> RangeSpec:
    spec = two_segment_spec()
    for host in spec.hosts:
        if host.name in names:
            host.vmm = "cloud-hypervisor"
    return spec


def render(spec: RangeSpec, cache: Path, out: Path) -> dict[str, Any]:
    render_bundle(spec, out, PlanOptions(image_cache=cache, cid_base=3000))
    boot = json.loads((out / "boot.json").read_text())
    return {guest["name"]: guest for guest in boot["guests"]}


@pytest.mark.parametrize(
    ("vmm", "accepted"),
    [(None, "qemu"), ("qemu", "qemu"), ("cloud-hypervisor", "cloud-hypervisor")],
)
def test_vmm_field_defaults_to_qemu(vmm: str | None, accepted: str) -> None:
    extra = {} if vmm is None else {"vmm": vmm}
    host = Host.model_validate(
        {
            "name": "web",
            "os": {"type": "linux"},
            "image": "img",
            "interfaces": [{"network": "dmz"}],
            **extra,
        }
    )
    assert host.vmm == accepted


def test_vmm_field_rejects_other_monitors() -> None:
    with pytest.raises(ValidationError, match="vmm"):
        Host(
            name="web",
            os=Os(type="linux"),
            image="img",
            interfaces=[Interface(network="dmz")],
            vmm="firecracker",  # pyright: ignore[reportArgumentType]
        )


def test_render_gives_cloud_hypervisor_guests_boot_parameters_not_domain_xml(
    cache: Path, tmp_path: Path
) -> None:
    out = tmp_path / "bundle"
    guests = render(ch_spec("web"), cache, out)
    assert not (out / "guests/web/domain.xml").exists()
    assert (out / "guests/db/domain.xml").exists()
    web = guests["web"]
    assert web["vmm"] == "cloud-hypervisor"
    assert (web["cpus"], web["memory_mb"]) == (1, 1024)
    assert [nic["bridge"] for nic in web["interfaces"]] == ["br-dmz"]
    assert guests["db"]["vmm"] == "qemu" and "interfaces" not in guests["db"]
    compose = (out / "compose.yaml").read_text()
    assert "${CH_VSOCK_DIR:?" in compose and ":/run/ch-vsock" in compose


def test_boot_json_carries_kind_and_attacker_address_facts(
    cache: Path, tmp_path: Path
) -> None:
    """Every entry carries its plan `kind`, and the attacker carries sizing plus full interface facts (ip, prefixlen, gateway): descriptive plan facts a deployment-selected external attack-box provider consumes at realize time. Other guests are unchanged."""
    out = tmp_path / "bundle"
    guests = render(two_segment_spec(), cache, out)
    assert {name: guest["kind"] for name, guest in guests.items()} == {
        "web": "host",
        "db": "host",
        "router": "router",
        "attacker": "attacker",
    }
    attacker = guests["attacker"]
    nic = attacker["interfaces"][0]
    assert nic["bridge"] == "br-dmz"
    assert nic["ip"].startswith("10.80.10.")
    assert nic["prefixlen"] == 24
    assert nic["gateway"] == "10.80.10.1", "dmz's elected gateway is the router"
    assert attacker["cpus"] >= 1 and attacker["memory_mb"] >= 64
    assert "interfaces" not in guests["web"], "a qemu host carries no address facts"


def test_qemu_attacker_still_carries_the_address_facts(
    cache: Path, tmp_path: Path
) -> None:
    """The attacker facts are kind-driven, not VMM-driven: an explicit qemu attack box carries them too."""
    spec = two_segment_spec()
    spec.attacker.vmm = "qemu"
    guests = render(spec, cache, tmp_path / "bundle")
    attacker = guests["attacker"]
    assert attacker["vmm"] == "qemu"
    assert attacker["interfaces"][0]["prefixlen"] == 24
    assert attacker["cpus"] >= 1


def test_old_boot_json_entries_parse_with_defaults() -> None:
    """A pre-attack-box bundle (no `kind`, bare bridge+mac interfaces) parses under the new models, so old bundles stay realizable."""
    guest = BootGuest.model_validate(
        {
            "name": "web",
            "cid": 3000,
            "image_file": "img.qcow2",
            "overlay_gb": 10,
            "readiness": "cloud-init",
            "vmm": "cloud-hypervisor",
            "cpus": 1,
            "memory_mb": 1024,
            "interfaces": [{"bridge": "br-dmz", "mac": "52:54:00:00:00:01"}],
        }
    )
    assert guest.kind == "host"
    nic = guest.interfaces[0]
    assert (nic.ip, nic.prefixlen, nic.gateway) == (None, None, None)


def test_render_without_cloud_hypervisor_guests_mounts_no_vsock_dir(
    cache: Path, tmp_path: Path
) -> None:
    out = tmp_path / "bundle"
    # the attacker box defaults to cloud-hypervisor, so pin it back to qemu for
    # an all-qemu range
    spec = two_segment_spec()
    spec.attacker.vmm = "qemu"
    render(spec, cache, out)
    assert "CH_VSOCK_DIR" not in (out / "compose.yaml").read_text()


def test_dedicated_attacker_defaults_to_cloud_hypervisor(cache: Path) -> None:
    # the agent box defaults to cloud-hypervisor while hosts and routers stay qemu
    plan = resolve_plan(
        two_segment_spec(), PlanOptions(image_cache=cache, cid_base=3000)
    )
    vmm_by_name = {guest.name: guest.vmm for guest in plan.guests}
    assert vmm_by_name["attacker"] == "cloud-hypervisor"
    assert vmm_by_name["web"] == "qemu"  # host
    assert vmm_by_name["router"] == "qemu"  # router


def test_declared_attacker_vmm_wins_over_the_cloud_hypervisor_default(
    cache: Path,
) -> None:
    spec = two_segment_spec()
    spec.attacker.vmm = "qemu"
    plan = resolve_plan(spec, PlanOptions(image_cache=cache, cid_base=3000))
    attacker = next(guest for guest in plan.guests if guest.name == "attacker")
    assert attacker.vmm == "qemu"


def test_boot_script_starts_cloud_hypervisor_unprivileged(
    cache: Path, tmp_path: Path
) -> None:
    out = tmp_path / "bundle"
    guests = render(ch_spec("web"), cache, out)
    cid, mac = guests["web"]["cid"], guests["web"]["interfaces"][0]["mac"]
    script = boot_script(load_boot(out))
    uid = 1_000_000 + cid  # its own uid: no other VMM (or QEMU) shares it
    assert f"ip tuntap add dev ch{cid}n0 mode tap user {uid} group kvm" in script
    assert f"ip link set ch{cid}n0 master br-dmz" in script
    # the tap carries libvirt's fe:-prefixed MAC before it joins the bridge
    tap_mac = "fe" + mac[2:]
    assert f"ip link set ch{cid}n0 address {tap_mac}" in script
    assert script.index(f"address {tap_mac}") < script.index(f"ch{cid}n0 master")
    assert (
        f"setpriv --reuid={uid} --regid=kvm --clear-groups /usr/local/bin/cloud-hypervisor"
        in script
    )
    assert f"--net tap=ch{cid}n0,mac={mac}" in script
    assert f"--vsock cid={cid},socket=/run/ch-vsock/web.sock" in script
    assert "path=/scratch/web.qcow2,image_type=qcow2,backing_files=on" in script
    assert "--seccomp" not in script  # the default filter stays on
    assert "--api-socket" not in script  # no VMM control surface nothing uses
    assert "virsh -c qemu:///system start web" not in script
    assert "virsh -c qemu:///system start db" in script
    # qemu guests get the same pre-own treatment (issue #5): the DAC seclabel
    # runs each QEMU as its own uid, so root hands it its files first
    from inspect_ranges._compiler.plan import guest_uid

    db_cid = guests["db"]["cid"]
    assert (
        f"chown {guest_uid(db_cid)}:kvm /scratch/db.qcow2 /scratch/db-seed.iso"
        in script
    )
    assert (
        f"install -o {guest_uid(db_cid)} -g kvm -m 0640 /dev/null /scratch/console/db.log"
        in script
    )
    # the tap exists before the VMM that opens it, and the VMM's 0700 socket
    # is opened to the host-side dialer only after the VMM created it
    assert script.index(f"ip tuntap add dev ch{cid}n0") < script.index("setpriv")
    assert script.index("setpriv") < script.index("chmod 0666 /run/ch-vsock/web.sock")


def test_cloud_hypervisor_guests_refuse_a_pinned_cpu_model(cache: Path) -> None:
    # CH has no CPU model setting: a pinned model would silently not apply. The
    # declared-CH host and the default-CH attacker box both refuse.
    with pytest.raises(IssueError) as refused:
        resolve_plan(
            ch_spec("web"), PlanOptions(image_cache=cache, cpu_model="Skylake-Server")
        )
    assert [(issue.code, issue.path) for issue in refused.value.issues] == [
        ("cloud-hypervisor-cpu-model", ("hosts", 0, "vmm")),
        ("cloud-hypervisor-cpu-model", ("attacker", "vmm")),
    ]
    # an all-qemu range (attacker pinned back to qemu) accepts a pinned model
    qemu_spec = two_segment_spec()
    qemu_spec.attacker.vmm = "qemu"
    resolve_plan(qemu_spec, PlanOptions(image_cache=cache, cpu_model="Skylake-Server"))


@pytest.mark.parametrize(
    ("fields", "refused"),
    [
        ({"host": "web", "vmm": "cloud-hypervisor"}, True),
        ({"host": "web"}, False),
        ({"interfaces": [{"network": "dmz"}], "vmm": "cloud-hypervisor"}, False),
    ],
)
def test_attacker_vmm_is_refused_on_an_existing_host_foothold(
    fields: dict[str, Any], refused: bool
) -> None:
    data = {"entry": "external", **fields}
    if refused:
        with pytest.raises(ValidationError, match="must not also declare vmm"):
            Attacker.model_validate(data)
    else:
        Attacker.model_validate(data)


_BOOT_BASE: dict[str, Any] = {
    "name": "web",
    "cid": 3000,
    "image_file": "img.qcow2",
    "overlay_gb": 10,
    "readiness": "cloud-init",
}


@pytest.mark.parametrize(
    "fields",
    [
        {"vmm": "cloud-hypervisor"},  # no sizing
        {"vmm": "cloud-hypervisor", "cpus": 1},
        {
            "vmm": "cloud-hypervisor",
            "cpus": 1,
            "memory_mb": 1024,
            "interfaces": [{"bridge": "br-dmz; rm -rf /", "mac": "52:54:00:00:00:01"}],
        },
        {
            "vmm": "cloud-hypervisor",
            "cpus": 1,
            "memory_mb": 1024,
            "interfaces": [{"bridge": "br-dmz", "mac": "not-a-mac"}],
        },
    ],
)
def test_boot_guest_refuses_malformed_vmm_entries(fields: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        BootGuest.model_validate({**_BOOT_BASE, **fields})


class _SocketStream:
    """The fake VMM's side of an accepted hybrid-vsock connection, as a `ByteStream`."""

    def __init__(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        self._reader, self._writer = reader, writer

    async def send(self, data: bytes) -> None:
        self._writer.write(data)
        await self._writer.drain()

    async def receive(self) -> bytes:
        return await self._reader.read(1 << 16)

    async def aclose(self) -> None:
        self._writer.close()


class FakeHybridVsock:
    """A Cloud Hypervisor hybrid-vsock socket in front of a `FakeGuest`: `CONNECT <port>` then `OK <n>`, or a bare close while nothing in the guest listens."""

    def __init__(self, path: Path, *, listening: bool = True) -> None:
        self.path = path
        self.listening = listening
        self.requests: list[bytes] = []
        self.guest = FakeGuest("web")

    async def _handle(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        self.requests.append(await reader.readline())
        if not self.listening:
            writer.close()
            return
        writer.write(b"OK 1073741824\n")
        await writer.drain()
        await serve_guest(self.guest, _SocketStream(reader, writer))

    async def start(self) -> asyncio.Server:
        return await asyncio.start_unix_server(self._handle, path=str(self.path))


def test_hybrid_transport_pings_the_guest_through_the_socket(short_dir: Path) -> None:
    vmm = FakeHybridVsock(short_dir / "web.sock")

    async def scenario() -> str:
        async with await vmm.start():
            channel = MessageChannel(
                VsockTransport(
                    {}, hybrid_sockets={"web": HybridEndpoint(vmm.path, os.getuid())}
                ),
                label="test",
            )
            return (await channel.ping("web")).session

    assert asyncio.run(scenario()) == vmm.guest.session
    assert vmm.requests[0] == b"CONNECT 5000\n"


def test_hybrid_transport_refuses_when_nothing_listens(short_dir: Path) -> None:
    vmm = FakeHybridVsock(short_dir / "web.sock", listening=False)

    async def scenario() -> None:
        async with await vmm.start():
            await VsockTransport(
                {},
                hybrid_sockets={"web": HybridEndpoint(vmm.path, os.getuid())},
                pace_s=0.0,
            ).connect("web")

    with pytest.raises(ConnectionError, match="handshake refused"):
        asyncio.run(scenario())
    assert len(vmm.requests) == 5  # every retry attempt reached the VMM


def test_hybrid_transport_accepts_a_socket_served_by_the_vmm_uid(
    short_dir: Path,
) -> None:
    # the server runs as this test's uid, so expecting that uid is the
    # "VMM's uid" case: the credential check passes and the handshake goes out
    vmm = FakeHybridVsock(short_dir / "web.sock")

    async def scenario() -> None:
        async with await vmm.start():
            stream = await VsockTransport(
                {}, hybrid_sockets={"web": HybridEndpoint(vmm.path, os.getuid())}
            ).connect("web")
            await stream.aclose()

    asyncio.run(scenario())
    assert vmm.requests == [b"CONNECT 5000\n"]


def test_hybrid_transport_refuses_a_foreign_peer_before_sending_anything(
    short_dir: Path,
) -> None:
    # a real socket whose peer (this test's uid) is not the expected VMM uid
    impostor = FakeHybridVsock(short_dir / "web.sock")
    expected = os.getuid() + 1

    async def scenario() -> None:
        async with await impostor.start():
            try:
                await VsockTransport(
                    {},
                    hybrid_sockets={"web": HybridEndpoint(impostor.path, expected)},
                    pace_s=0.0,
                ).connect("web")
            finally:
                await asyncio.sleep(0.05)  # let the server read the closed socket

    with pytest.raises(
        PeerCredentialMismatch,
        match=rf"served by uid {os.getuid()}, not the VMM's uid {expected}",
    ):
        asyncio.run(scenario())
    # one connection, closed before a single byte (not even CONNECT) was sent
    assert impostor.requests == [b""]


class _ConnectorTransport:
    """Adapts a CID-keyed `GuestConnector` to the channel's `Transport`."""

    def __init__(self, connector: Any, cids: dict[str, int]) -> None:
        self._connector, self._cids = connector, cids

    async def connect(self, endpoint: str) -> ByteStream:
        return await self._connector(self._cids[endpoint])


def test_applier_connector_dials_cloud_hypervisor_cids_by_socket(
    short_dir: Path,
) -> None:
    vmm = FakeHybridVsock(short_dir / "web.sock")
    fallback_cids: list[int] = []

    async def fallback(cid: int) -> ByteStream:
        fallback_cids.append(cid)
        raise ConnectionError(f"no AF_VSOCK guest at {cid}")

    sockets: dict[int, HybridEndpoint] = {}
    connector = cloud_hypervisor_connector(sockets, fallback)
    channel = MessageChannel(
        _ConnectorTransport(connector, {"web": 3000, "db": 3001}), label="test"
    )

    async def scenario() -> str:
        async with await vmm.start():
            # registered after construction: read live
            sockets[3000] = HybridEndpoint(vmm.path, os.getuid())
            session = (await channel.ping("web")).session
            with pytest.raises(TransportFailure):
                await channel.ping("db")
            return session

    assert asyncio.run(scenario()) == vmm.guest.session
    assert set(fallback_cids) == {3001}


def test_vsock_dir_is_private_sticky_and_refuses_a_foreign_root(
    short_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(tempfile, "tempdir", str(short_dir))
    directory = prepare_ch_vsock_dir("ir-dmz-pivot-sample-1-abcdef")
    assert directory == ch_vsock_dir("ir-dmz-pivot-sample-1-abcdef")
    assert directory.stat().st_mode & 0o7777 == 0o1733
    assert directory.parent.stat().st_mode & 0o777 == 0o700
    assert len(str(directory / "attacker.sock")) < 108
    os.chmod(directory.parent, 0o755)
    with pytest.raises(PermissionError, match="mode 0700"):
        prepare_ch_vsock_dir("ir-other")


def test_cloud_hypervisor_guests_with_content_refuse_at_planning(cache: Path) -> None:
    """The build captures provisioned guests through virsh domstate, which cannot see CH guests: fail closed until CH capture lands."""
    from inspect_ranges.types import ProvisioningStep, Service

    spec = ch_spec()
    spec.hosts[0].vmm = "cloud-hypervisor"
    spec.hosts[0].provisioning = [ProvisioningStep(recipe="acme.web")]
    with pytest.raises(IssueError) as excinfo:
        resolve_plan(spec, PlanOptions(image_cache=cache))
    assert any(
        issue.code == "cloud-hypervisor-content-unsupported"
        for issue in excinfo.value.issues
    )
    # declarations alone (services) refuse the same way
    spec = ch_spec()
    spec.hosts[0].vmm = "cloud-hypervisor"
    spec.hosts[0].services = [Service(name="web", port=80)]
    with pytest.raises(IssueError) as excinfo:
        resolve_plan(spec, PlanOptions(image_cache=cache))
    assert any(
        issue.code == "cloud-hypervisor-content-unsupported"
        for issue in excinfo.value.issues
    )
    # a content-free CH guest (the attacker shape) plans fine
    spec = ch_spec()
    spec.hosts[0].vmm = "cloud-hypervisor"
    plan = resolve_plan(spec, PlanOptions(image_cache=cache))
    assert next(g for g in plan.guests if g.name == spec.hosts[0].name).vmm == (
        "cloud-hypervisor"
    )


def test_guesttool_socket_env_round_trip() -> None:
    """IR_GUEST_SOCKETS round-trips through the contract env into HybridEndpoints."""
    import json as json_module

    from inspect_ranges._build.guesttool import sockets_from_env
    from inspect_ranges._build.recipes import RecipeTarget, _contract_env
    from inspect_ranges._channel.vsock import HybridEndpoint

    target = RecipeTarget(
        guest="web",
        cids={"web": 3100},
        hybrid_sockets={"attacker": ("/run/ch-vsock/attacker.sock", 1003104)},
    )
    env = _contract_env(target, Path("/tmp"), "acme.web", 1000)
    parsed = sockets_from_env({"IR_GUEST_SOCKETS": env["IR_GUEST_SOCKETS"]})
    assert parsed == {
        "attacker": HybridEndpoint(Path("/run/ch-vsock/attacker.sock"), 1003104)
    }
    assert sockets_from_env({}) == {}
    for bad in ("[1]", '{"a": ["p"]}', '{"a": [1, 2]}'):
        with pytest.raises(ValueError):
            sockets_from_env({"IR_GUEST_SOCKETS": bad})
    assert json_module.loads(env["IR_GUEST_CIDS"]) == {"web": 3100}


def test_foothold_attacker_refuses_even_a_redundant_qemu_vmm() -> None:
    """Round-2 gap: the flip changed the refusal from `!= qemu` to `is not None`; the previously-valid redundant declaration is the edge that moved."""
    with pytest.raises(ValidationError, match="must not also declare vmm"):
        Attacker.model_validate({"entry": "external", "host": "web", "vmm": "qemu"})


def test_down_removes_the_ch_vsock_dir(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Round-2 gap: down's dir removal is the only barrier against per-sample socket-dir accumulation; crash-recovery paths rely on it."""
    monkeypatch.setattr(tempfile, "gettempdir", lambda: str(tmp_path))
    from inspect_ranges._runtime.down import down
    from inspect_ranges._runtime.ownership import owner_record, write_owner

    directory = prepare_ch_vsock_dir("ir-chdir-test")
    (directory / "attacker.sock").touch()
    state = tmp_path / "state"
    bundle = tmp_path / "bundle"
    bundle.mkdir()
    write_owner(state, owner_record("ir-chdir-test", "chdir", "0" * 64, bundle))

    def no_docker(argv: list[str], **_: Any) -> Any:
        import subprocess

        return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")

    down("ir-chdir-test", state_dir=state, runner=no_docker, keep_state=False)
    assert not directory.exists()


def test_provider_channel_factory_receives_the_hybrid_map() -> None:
    """Round-2 gap: the provider must thread UpResult's hybrid endpoints into the sample channel, or oracle/sandbox execs dial a CH attacker by dead CID."""
    from inspect_ranges._provider.state import _default_channel_factory

    endpoint = HybridEndpoint(Path("/run/ch-vsock/attacker.sock"), 1_003_900)
    channel = _default_channel_factory(
        {"attacker": 3900}, "test", {"attacker": endpoint}
    )
    transport = cast(VsockTransport, channel._transport)  # pyright: ignore[reportPrivateUsage]
    assert transport._hybrid == {"attacker": endpoint}  # pyright: ignore[reportPrivateUsage]

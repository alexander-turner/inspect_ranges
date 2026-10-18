"""The glovebox control-channel connector, driven through the REAL provider client surface.

Every test runs `MessageChannel` (the exact class `ops.py` uses) over a transport backed by `glovebox_connector`, so the v3 codec validates the connector's replies as untrusted input. A fake `CellExecutor` stands in for a live `crictl exec`, keeping the wire contract (part 3) under test without a Kata cell. The `CrictlCellExecutor` command construction is tested separately through its injectable `run_command` hook.

Async tests follow the repo convention (`test_channel_protocol.py`): a sync test wraps an inner `asyncio.run` scenario, so no pytest-asyncio dependency is needed.
"""

import asyncio
import base64
import json
from collections.abc import Mapping, Sequence
from typing import Any

import pytest
from inspect_ranges._channel.channel import ByteStream, GuestError, MessageChannel
from inspect_ranges._channel.protocol import Budget, ExecRequest
from inspect_ranges._host.glovebox import (
    CellConnection,
    CellExecResult,
    CellExecutor,
    CrictlCellExecutor,
    glovebox_connector,
)

_ATTACKER_CID = 4242


class FakeExecutor(CellExecutor):
    """Records operations and returns scripted results, for the wire-contract tests."""

    def __init__(self) -> None:
        self.runs: list[dict[str, object]] = []
        self.files: dict[str, bytes] = {}
        self.exec_result = CellExecResult(rc=0, stdout=b"", stderr=b"")

    async def run(
        self,
        cmd: Sequence[str],
        *,
        cwd: str | None,
        env: Mapping[str, str],
        user: str | None,
        stdin: bytes,
    ) -> CellExecResult:
        self.runs.append(
            {
                "cmd": list(cmd),
                "cwd": cwd,
                "env": dict(env),
                "user": user,
                "stdin": stdin,
            }
        )
        return self.exec_result

    async def read_file(self, path: str, *, max_bytes: int | None) -> bytes:
        if path not in self.files:
            raise FileNotFoundError(path)
        data = self.files[path]
        return data if max_bytes is None else data[:max_bytes]

    async def write_file(self, path: str, data: bytes, *, mode: int | None) -> None:
        self.files[path] = data


async def _unreachable_fallback(cid: int) -> ByteStream:
    raise AssertionError(f"fallback must not be called for cid {cid}")


class _ConnectorTransport:
    """A `Transport` that routes the attacker guest to the glovebox connector."""

    def __init__(self, cell: CellConnection) -> None:
        self._connect = glovebox_connector(
            {_ATTACKER_CID: cell}, fallback=_unreachable_fallback
        )

    async def connect(self, endpoint: str) -> ByteStream:
        assert endpoint == "attacker"
        return await self._connect(_ATTACKER_CID)


def _channel(executor: CellExecutor) -> MessageChannel:
    return MessageChannel(_ConnectorTransport(CellConnection(executor=executor)))


def test_ping_reports_a_session() -> None:
    async def scenario() -> None:
        channel = _channel(FakeExecutor())
        pong = await channel.ping("attacker")
        assert pong.protocol == 3
        assert len(pong.session) == 32
        assert all(c in "0123456789abcdef" for c in pong.session)
        # the session is stable across pings (one cell == one session)
        assert (await channel.ping("attacker")).session == pong.session

    asyncio.run(scenario())


def test_exec_round_trips_rc_stdout_stderr() -> None:
    async def scenario() -> None:
        executor = FakeExecutor()
        executor.exec_result = CellExecResult(
            rc=7, stdout=b"out-bytes", stderr=b"err-bytes"
        )
        channel = _channel(executor)
        outcome = await channel.exec(
            "attacker",
            ExecRequest(id="a" * 32, cmd=["/bin/echo", "hi"], budget=Budget()),
        )
        assert outcome.rc == 7
        assert outcome.stdout == b"out-bytes"
        assert outcome.stderr == b"err-bytes"
        assert executor.runs[0]["cmd"] == ["/bin/echo", "hi"]

    asyncio.run(scenario())


def test_exec_passes_cwd_env_user_and_stdin() -> None:
    async def scenario() -> None:
        executor = FakeExecutor()
        channel = _channel(executor)
        await channel.exec(
            "attacker",
            ExecRequest(
                id="b" * 32,
                cmd=["cat"],
                cwd="/work",
                env={"FOO": "bar"},
                user="agent",
                data_size=5,
            ),
            stdin=b"hello",
        )
        run = executor.runs[0]
        assert run["cwd"] == "/work"
        assert run["env"] == {"FOO": "bar"}
        assert run["user"] == "agent"
        assert run["stdin"] == b"hello"

    asyncio.run(scenario())


def test_exec_negative_rc_survives_the_wire() -> None:
    async def scenario() -> None:
        executor = FakeExecutor()
        executor.exec_result = CellExecResult(rc=-9, stdout=b"", stderr=b"")
        outcome = await _channel(executor).exec(
            "attacker", ExecRequest(id="c" * 32, cmd=["sleep"])
        )
        assert outcome.rc == -9

    asyncio.run(scenario())


def test_write_then_read_file_round_trips_bytes() -> None:
    async def scenario() -> None:
        executor = FakeExecutor()
        channel = _channel(executor)
        payload = b"\x00\x01binary\xff payload"
        await channel.write_file("attacker", "/home/agent/f.bin", payload, mode=0o600)
        assert executor.files["/home/agent/f.bin"] == payload
        assert await channel.read_file("attacker", "/home/agent/f.bin") == payload

    asyncio.run(scenario())


def test_read_missing_file_is_a_typed_guest_error() -> None:
    async def scenario() -> None:
        with pytest.raises(GuestError) as caught:
            await _channel(FakeExecutor()).read_file("attacker", "/nope")
        assert caught.value.errno == "ENOENT"

    asyncio.run(scenario())


def test_connector_defers_unknown_cids_to_the_fallback() -> None:
    async def scenario() -> None:
        called: list[int] = []

        async def fallback(cid: int) -> ByteStream:
            called.append(cid)
            raise ConnectionError("fallback reached")

        connect = glovebox_connector(
            {_ATTACKER_CID: CellConnection(executor=FakeExecutor())}, fallback=fallback
        )
        with pytest.raises(ConnectionError):
            await connect(999)
        assert called == [999]

    asyncio.run(scenario())


# --- CrictlCellExecutor command construction (no live crictl) ---------------


def test_crictl_executor_wraps_argv_with_rc_sentinel() -> None:
    async def scenario() -> None:
        seen: list[list[str]] = []

        async def fake_run(argv: Sequence[str], stdin: bytes) -> CellExecResult:
            seen.append(list(argv))
            # emulate crictl swallowing rc: the real rc rides the stdout sentinel
            return CellExecResult(rc=0, stdout=b"hello\n__IR_GB_RC__3\n", stderr=b"e")

        executor = CrictlCellExecutor(container_id="ctr", run_command=fake_run)
        result = await executor.run(
            ["/bin/echo", "x"], cwd="/w", env={"K": "v"}, user="agent", stdin=b""
        )
        assert result.rc == 3
        assert result.stdout == b"hello"
        assert result.stderr == b"e"
        argv = seen[0]
        assert argv[:4] == ["runuser", "-u", "agent", "--"]
        assert "/bin/sh" in argv and "sh" in argv
        # the caller's argv is passed as positional parameters, after the script
        assert argv[-2:] == ["/bin/echo", "x"]
        script = argv[argv.index("-c") + 1]
        assert "cd /w" in script
        assert "export K=v" in script
        assert "__IR_GB_RC__" in script

    asyncio.run(scenario())


def test_crictl_executor_read_file_decodes_base64() -> None:
    async def scenario() -> None:
        async def fake_run(argv: Sequence[str], stdin: bytes) -> CellExecResult:
            assert argv[0] == "/bin/sh" and "base64" in argv[2]
            return CellExecResult(rc=0, stdout=b"aGVsbG8=\n", stderr=b"")

        executor = CrictlCellExecutor(container_id="ctr", run_command=fake_run)
        assert await executor.read_file("/f", max_bytes=None) == b"hello"

    asyncio.run(scenario())


def test_crictl_executor_write_file_pipes_base64_stdin() -> None:
    async def scenario() -> None:
        captured: dict[str, bytes] = {}

        async def fake_run(argv: Sequence[str], stdin: bytes) -> CellExecResult:
            captured["stdin"] = stdin
            captured["script"] = argv[2].encode()
            return CellExecResult(rc=0, stdout=b"", stderr=b"")

        executor = CrictlCellExecutor(container_id="ctr", run_command=fake_run)
        await executor.write_file("/f", b"hello", mode=0o644)
        assert base64.b64decode(captured["stdin"]) == b"hello"
        assert b"base64 -d > /f" in captured["script"]
        assert b"chmod 644 /f" in captured["script"]

    asyncio.run(scenario())


# --- bridge-netns handshake (contract part 2, method b: veth stitch) --------


def _glovebox_plan():
    from inspect_ranges._compiler import PlanOptions, resolve_plan

    from tests.test_provider_glovebox import glovebox_spec

    return resolve_plan(glovebox_spec(), PlanOptions())


def test_glovebox_segments_reports_the_reserved_attacker_on_dmz() -> None:
    from inspect_ranges._host.glovebox import glovebox_segments

    segments = glovebox_segments(_glovebox_plan())
    assert len(segments) == 1
    seg = segments[0]
    assert seg.network == "dmz"
    assert seg.range_bridge == "br-dmz"
    assert seg.node_bridge == "gbx-dmz"
    assert seg.cidr == "10.80.10.0/24"
    # the reserved attacker address the cell must take (routers take .1, so .2)
    assert seg.attacker_ip == "10.80.10.2"
    assert seg.attacker_mac.startswith("52:54:00:")


def test_no_segments_without_a_glovebox_guest() -> None:
    from inspect_ranges._compiler import PlanOptions, resolve_plan
    from inspect_ranges._host.glovebox import glovebox_segments

    from tests.test_compiler import two_segment_spec

    assert glovebox_segments(resolve_plan(two_segment_spec(), PlanOptions())) == []


def test_stitch_commands_bridge_the_two_netns_over_a_veth() -> None:
    from inspect_ranges._host.glovebox import glovebox_segments, stitch_commands

    seg = glovebox_segments(_glovebox_plan())[0]
    cmds = stitch_commands(seg, netns_pid=4321, veth_host="gbv0h", veth_peer="gbv0p")
    joined = [" ".join(c) for c in cmds]
    # the node-side bridge is created and the veth peer is pushed into the range netns
    assert "ip link add name gbx-dmz type bridge" in joined
    assert "ip link add gbv0h type veth peer name gbv0p" in joined
    assert "ip link set gbv0p netns 4321" in joined
    # host end enslaved to the node bridge; peer end enslaved to the in-range bridge
    assert "ip link set gbv0h master gbx-dmz" in joined
    assert "nsenter -t 4321 -n ip link set gbv0p master br-dmz" in joined
    assert "nsenter -t 4321 -n ip link set gbv0p up" in joined


def test_unstitch_removes_the_veth_and_node_bridge() -> None:
    from inspect_ranges._host.glovebox import glovebox_segments, unstitch_commands

    seg = glovebox_segments(_glovebox_plan())[0]
    joined = [" ".join(c) for c in unstitch_commands(seg, veth_host="gbv0h")]
    assert "ip link del gbv0h" in joined
    assert "ip link del gbx-dmz" in joined


def test_cell_cni_conflist_points_at_the_node_bridge_on_the_segment_cidr() -> None:
    from inspect_ranges._host.glovebox import cell_cni_conflist, glovebox_segments

    seg = glovebox_segments(_glovebox_plan())[0]
    # round-trip through json so the conflist is exercised as the on-disk shape
    conf: Any = json.loads(json.dumps(cell_cni_conflist(seg)))
    assert conf["cniVersion"] == "1.0.0"
    plugin = conf["plugins"][0]
    assert plugin["type"] == "bridge"
    assert plugin["bridge"] == "gbx-dmz"
    rng = plugin["ipam"]["ranges"][0][0]
    assert rng["subnet"] == "10.80.10.0/24"
    assert rng["rangeStart"] == "10.80.10.20"
    assert rng["rangeEnd"] == "10.80.10.99"


# --- GloveboxHost: the applier-side lifecycle (relay bind + stitch) ----------


def _glovebox_attacker_cid() -> int:
    plan = _glovebox_plan()
    return next(guest.cid for guest in plan.guests if guest.provider == "glovebox")


def test_glovebox_host_binds_the_reserved_cid_so_the_attacker_routes_into_the_cell() -> (
    None
):
    """After realize, a `provider: glovebox` guest's reserved cid routes through the host's connector to a cell bound to the configured container (the sandbox -> cell path), not the vsock fallback."""

    async def scenario() -> None:
        from inspect_ranges._host.glovebox import GloveboxHost

        async def noop_runner(commands: Sequence[Sequence[str]]) -> None:
            return None

        async def netns_pid(project: str) -> int:
            return 4321

        host = GloveboxHost(
            containers={"attacker": "ctr-abc"},
            root_runner=noop_runner,
            netns_pid_fn=netns_pid,
        )
        plan = _glovebox_plan()
        await host.realize(plan, "proj-1")
        cid = _glovebox_attacker_cid()
        # the reserved cid is bound to a crictl executor on the configured cell
        cell = host.cells[cid]
        assert isinstance(cell.executor, CrictlCellExecutor)
        assert cell.executor.container_id == "ctr-abc"

        # and a MessageChannel over the host's connector reaches that cell
        connect = host.connector(fallback=_unreachable_fallback)

        class _Transport:
            async def connect(self, endpoint: str) -> ByteStream:
                assert endpoint == "attacker"
                return await connect(cid)

        pong = await MessageChannel(_Transport()).ping("attacker")
        assert len(pong.session) == 32

    asyncio.run(scenario())


def test_glovebox_host_stitches_at_realize_and_unstitches_at_teardown() -> None:
    """Realize issues the veth stitch into the range netns; teardown removes it and drops the cell."""

    async def scenario() -> None:
        from inspect_ranges._host.glovebox import GloveboxHost

        issued: list[str] = []

        async def recording_runner(commands: Sequence[Sequence[str]]) -> None:
            issued.extend(" ".join(c) for c in commands)

        async def netns_pid(project: str) -> int:
            return 4321

        host = GloveboxHost(
            containers={"attacker": "ctr-abc"},
            root_runner=recording_runner,
            netns_pid_fn=netns_pid,
        )
        plan = _glovebox_plan()
        await host.realize(plan, "proj-1")
        # the segment bridge is stitched into the range netns (pid 4321) at br-dmz
        assert any(cmd.startswith("ip link add gbv") for cmd in issued)
        assert "nsenter -t 4321 -n ip link set" in " ".join(issued)
        assert any("master br-dmz" in cmd for cmd in issued)

        issued.clear()
        await host.teardown("proj-1")
        # teardown removes the veth and drops the bound cell
        assert any(cmd.startswith("ip link del gbv") for cmd in issued)
        assert host.cells == {}

    asyncio.run(scenario())


def test_glovebox_host_ignores_a_guest_with_no_configured_cell() -> None:
    """A glovebox guest absent from `containers` binds no cell and triggers no stitch (a missing cell fails loudly at dial, not silently at realize)."""

    async def scenario() -> None:
        from inspect_ranges._host.glovebox import GloveboxHost

        issued: list[str] = []

        async def recording_runner(commands: Sequence[Sequence[str]]) -> None:
            issued.extend(" ".join(c) for c in commands)

        async def netns_pid(project: str) -> int:  # pragma: no cover - never called
            raise AssertionError("netns pid must not be resolved without a cell")

        host = GloveboxHost(
            containers={},
            root_runner=recording_runner,
            netns_pid_fn=netns_pid,
        )
        await host.realize(_glovebox_plan(), "proj-1")
        assert host.cells == {}
        assert issued == []

    asyncio.run(scenario())

"""The applier endpoint: routing, the never-left handshake, the relay, realize translation and replay, refusals, teardown (range-host-v1 slice 3).

These pins run the REAL `Applier` in-process (the two-OS-process evidence is the UDS conformance suite and the self_check run); the up/down/guest seams are the shared fixture fakes, everything else is genuine: preamble parsing, routing refusal shapes, the byte pump, the translated replay log, admission.
"""

import asyncio
import logging
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from inspect_ranges._channel.channel import (
    FakeGuest,
    GuestError,
    HostRefused,
    MessageChannel,
    request_id,
)
from inspect_ranges._channel.codec import MessageStreamReader, encode_message
from inspect_ranges._channel.protocol import (
    ExecRequest,
    Heartbeat,
    RealizeRequest,
    StageReport,
)
from inspect_ranges._channel.uds import (
    PREAMBLE_MAGIC,
    ROUTED_ACK,
    UdsTransport,
    encode_preamble,
)
from inspect_ranges._host.applier import Applier
from inspect_ranges._host.leases import HostLease, LeaseStore
from inspect_ranges._host.reaper import sweep
from inspect_ranges._provider.admission import HostCapacity
from inspect_ranges._runtime.down import DownResult
from inspect_ranges._runtime.up import OnStage, UpOptions, UpResult

from tests.applier_fixture import FakeGuestConnector, fake_up, make_bundle
from tests.test_host_leases import facts

CID = 20_000  # the range-host battery band


class Rig:
    """One in-process applier over a real unix socket, with the fixture seams."""

    def __init__(
        self,
        tmp_path: Path,
        *,
        capacity: HostCapacity | None = None,
        preamble_timeout_s: float = 5.0,
    ) -> None:
        self.state = tmp_path / "state"
        self.socket_path = tmp_path / "sock" / "applier.sock"
        self.store = LeaseStore(self.state)
        self.connector = FakeGuestConnector()
        self.down_calls: list[str] = []
        self.up_calls: list[Path] = []
        self.applier = Applier(
            self.socket_path,
            self.state,
            image_cache=tmp_path / "cache",
            up_fn=self._up,
            down_fn=self._down,
            guest_connector=self.connector,
            capacity=capacity or HostCapacity(cpus=64, memory_mb=1 << 20),
            gate=lambda: [],
            preamble_timeout_s=preamble_timeout_s,
        )

    def _up(self, bundle: Path, options: UpOptions, on_stage: OnStage) -> UpResult:
        self.up_calls.append(bundle)
        return fake_up(bundle, options, on_stage)

    def _down(self, project: str, state_dir: Path) -> DownResult:
        self.down_calls.append(project)
        return DownResult(project=project, containers=0, volumes=0, networks=0)

    async def __aenter__(self) -> "Rig":
        await self.applier.start()
        return self

    async def __aexit__(self, *excinfo: object) -> None:
        await self.applier.aclose()

    def lease(
        self,
        tmp_path: Path,
        project: str = "ir-applier-a",
        *,
        with_bundle: bool = True,
        expired: bool = False,
    ) -> tuple[HostLease, str]:
        bundle = tmp_path / f"bundle-{project}"
        digest = make_bundle(bundle) if with_bundle else "ab" * 32
        store = self.store
        if expired:
            past = datetime.now(UTC) - timedelta(seconds=3600)
            store = LeaseStore(self.state, now_fn=lambda: past)
        lease = store.acquire(
            project=project,
            task_name="task",
            sample_id="s1",
            isolation="shared",
            origin=f"uds:{self.socket_path}",
            bundle_path=str(bundle),
            bundle_digest=digest,
            staging=str(tmp_path / f"staging-{project}"),
            host_facts=facts(),
            ttl_s=600,
        )
        return lease, digest

    def add_guest(
        self, lease: HostLease, name: str = "web", cid: int = CID
    ) -> FakeGuest:
        guest = FakeGuest(name)
        self.connector.guests[cid] = guest
        relays = self.applier._relays  # pyright: ignore[reportPrivateUsage] - test wiring
        relays.setdefault(lease.lease_id, {})[name] = cid
        return guest

    def channel(self, lease: HostLease) -> MessageChannel:
        return MessageChannel(
            UdsTransport(self.socket_path, lease.lease_id, ack_timeout_s=2.0),
            label=lease.project,
        )


# -- routing: every failure is ConnectionError at connect, never after ------------


def test_routing_refusal_shapes_are_connection_errors_at_connect(
    tmp_path: Path,
) -> None:
    """Unknown lease, expired lease, reaping lease, unknown guest, and guest dial failure all refuse before the ack: `ConnectionError` at connect, request provably never sent."""

    async def scenario() -> None:
        async with Rig(tmp_path) as rig:
            active, _ = rig.lease(tmp_path, "ir-active", with_bundle=False)
            rig.add_guest(active)
            # a baseline route works
            await (
                await UdsTransport(rig.socket_path, active.lease_id).connect("web")
            ).aclose()

            unknown_lease = UdsTransport(rig.socket_path, "f" * 32)
            with pytest.raises(ConnectionError):
                await unknown_lease.connect("web")

            expired, _ = rig.lease(tmp_path, "ir-expired", with_bundle=False)
            rig.add_guest(expired, cid=CID + 1)
            # rewrite as expired: absolute expiry is the contract
            past = (datetime.now(UTC) - timedelta(seconds=60)).isoformat()
            with rig.store._registry.locked(write=True) as view:  # pyright: ignore[reportPrivateUsage]
                view.entries[expired.lease_id] = expired.model_copy(
                    update={"expires_at": past}
                )
            with pytest.raises(ConnectionError):
                await UdsTransport(rig.socket_path, expired.lease_id).connect("web")

            reaping = rig.store.mark_reaping()
            assert [entry.lease_id for entry in reaping] == [expired.lease_id]
            with pytest.raises(ConnectionError):
                await UdsTransport(rig.socket_path, expired.lease_id).connect("web")

            with pytest.raises(ConnectionError):
                await UdsTransport(rig.socket_path, active.lease_id).connect("ghost")

            # dial failure: relay names a cid nobody serves
            relays = rig.applier._relays  # pyright: ignore[reportPrivateUsage]
            relays[active.lease_id]["dead"] = CID + 7
            with pytest.raises(ConnectionError):
                await UdsTransport(rig.socket_path, active.lease_id).connect("dead")

    asyncio.run(scenario())


def test_host_plane_stays_routable_for_a_reaping_lease(tmp_path: Path) -> None:
    """The reaper tears reaping leases down through this socket, so `@host` routes in any lease state (the guest plane stays strict)."""

    async def scenario() -> None:
        async with Rig(tmp_path) as rig:
            lease, _ = rig.lease(
                tmp_path, "ir-reaping", with_bundle=False, expired=True
            )
            assert [entry.lease_id for entry in rig.store.mark_reaping()] == [
                lease.lease_id
            ]
            channel = rig.channel(lease)
            beat = await channel.heartbeat()
            assert beat.uptime_ms >= 0
            await channel.teardown()
            assert rig.down_calls == ["ir-reaping"]

    asyncio.run(scenario())


def test_client_sends_zero_request_bytes_until_the_ack(tmp_path: Path) -> None:
    """The never-left property, asserted endpoint-side: for every refusal shape (close without ack, garbage ack byte, ack timeout) the endpoint received EXACTLY the preamble and nothing more."""

    async def scenario() -> None:
        received = bytearray()
        behavior = {"mode": "close"}

        async def refuser(
            reader: asyncio.StreamReader, writer: asyncio.StreamWriter
        ) -> None:
            while data := await reader.read(1 << 16):
                received.extend(data)
                if behavior["mode"] == "garbage" and len(received) >= 37:
                    writer.write(b"Z")
                    await writer.drain()
                elif behavior["mode"] == "close" and len(received) >= 37:
                    break
                # "silent": keep reading, never answer
            writer.close()

        socket_path = tmp_path / "refuser.sock"
        server = await asyncio.start_unix_server(refuser, path=str(socket_path))
        try:
            for mode in ("close", "garbage", "silent"):
                behavior["mode"] = mode
                received.clear()
                transport = UdsTransport(socket_path, "a" * 32, ack_timeout_s=0.3)
                with pytest.raises(ConnectionError):
                    await transport.connect("web")
                await asyncio.sleep(0.05)  # let any (illegal) late bytes land
                assert bytes(received) == encode_preamble("a" * 32, "web"), (
                    f"{mode}: the endpoint saw request bytes before any ack"
                )
        finally:
            server.close()
            await server.wait_closed()

    asyncio.run(scenario())


def test_preamble_survives_arbitrary_chunking(tmp_path: Path) -> None:
    """The server assembles a preamble delivered one byte at a time, then serves normally."""

    async def scenario() -> None:
        async with Rig(tmp_path) as rig:
            lease, _ = rig.lease(tmp_path, "ir-chunked", with_bundle=False)
            reader, writer = await asyncio.open_unix_connection(str(rig.socket_path))
            for byte in encode_preamble(lease.lease_id, "@host"):
                writer.write(bytes([byte]))
                await writer.drain()
                await asyncio.sleep(0.001)
            assert await reader.readexactly(1) == ROUTED_ACK
            ping_id = request_id()
            from inspect_ranges._channel.protocol import PingRequest

            for frame in encode_message(PingRequest(id=ping_id), None):
                writer.write(frame)
            await writer.drain()
            stream_reader = MessageStreamReader(
                lambda: reader.read(1 << 16), bulk_cap=1 << 20
            )
            reply, _ = await stream_reader.next()
            assert isinstance(reply, Heartbeat) and reply.id == ping_id
            writer.close()

    asyncio.run(scenario())


def test_preamble_garbage_overlength_and_timeout_never_crash_the_server(
    tmp_path: Path,
) -> None:
    async def scenario() -> None:
        async with Rig(tmp_path, preamble_timeout_s=0.2) as rig:
            lease, _ = rig.lease(tmp_path, "ir-sturdy", with_bundle=False)

            # garbage magic
            reader, writer = await asyncio.open_unix_connection(str(rig.socket_path))
            writer.write(b"GARBAGE-NOT-A-PREAMBLE")
            await writer.drain()
            assert await reader.read(1) == b"", "the server must close, not answer"
            writer.close()

            # overlength endpoint name, never completed (times out server-side)
            reader, writer = await asyncio.open_unix_connection(str(rig.socket_path))
            writer.write(PREAMBLE_MAGIC + b"a" * 32 + bytes([255]) + b"x" * 10)
            await writer.drain()
            assert await reader.read(1) == b""
            writer.close()

            # a lease id that is 32 ASCII chars but not strict lowercase hex
            reader, writer = await asyncio.open_unix_connection(str(rig.socket_path))
            writer.write(PREAMBLE_MAGIC + b"+" + b"a" * 31 + bytes([3]) + b"web")
            await writer.drain()
            assert await reader.read(1) == b"", "non-hex lease ids are garbage"
            writer.close()

            # silent client: preamble never arrives
            reader, writer = await asyncio.open_unix_connection(str(rig.socket_path))
            assert await reader.read(1) == b""
            writer.close()

            # the server survived all three: a good route still works
            beat = await rig.channel(lease).heartbeat()
            assert beat.uptime_ms >= 0

    asyncio.run(scenario())


# -- the guest relay ---------------------------------------------------------------


def test_same_name_guests_are_lease_scoped(tmp_path: Path) -> None:
    """Two leases each own a guest named `web`; neither can reach the other's."""

    async def scenario() -> None:
        async with Rig(tmp_path) as rig:
            first, _ = rig.lease(tmp_path, "ir-first", with_bundle=False)
            second, _ = rig.lease(tmp_path, "ir-second", with_bundle=False)
            rig.add_guest(first, "web", CID)
            rig.add_guest(second, "web", CID + 1)
            await rig.channel(first).write_file("web", "/tmp/who", b"first")
            assert await rig.channel(first).read_file("web", "/tmp/who") == b"first"
            with pytest.raises(GuestError) as missing:
                await rig.channel(second).read_file("web", "/tmp/who")
            assert missing.value.errno == "ENOENT"

    asyncio.run(scenario())


def test_relay_killed_before_reply_is_loss_resend_dedupe_one_run(
    tmp_path: Path,
) -> None:
    """A reply dropped behind the relay surfaces as loss; the same-id resend hits the guest's dedupe store and the command provably ran once."""

    async def scenario() -> None:
        async with Rig(tmp_path) as rig:
            lease, _ = rig.lease(tmp_path, "ir-dedupe", with_bundle=False)
            guest = rig.add_guest(lease)
            guest.drop_next_reply = True
            outcome = await rig.channel(lease).exec(
                "web", ExecRequest(id=request_id(), cmd=["echo", "once"])
            )
            assert outcome.rc == 0 and outcome.stdout == b"once\n"
            assert outcome.attempts == 2, "the reply was lost once and resent"
            assert guest.exec_count == 1, "dedupe must prove exactly one run"

    asyncio.run(scenario())


# -- realize ------------------------------------------------------------------------


def test_realize_translates_registers_relay_and_replays_identically(
    tmp_path: Path,
) -> None:
    """One realize: the seam stage sequence, the relay registered from the plan, and a same-id resend replayed byte-identically from the TRANSLATED log without re-executing up."""

    async def scenario() -> None:
        async with Rig(tmp_path) as rig:
            lease, digest = rig.lease(tmp_path, "ir-realize")
            # raw same-id streams: the first executes, the second replays
            # byte-identically from the TRANSLATED log without re-running up
            request = RealizeRequest(id=request_id(), bundle_digest=digest, grants=[])
            runs: list[list[StageReport]] = []
            for _ in range(2):
                stream = await UdsTransport(rig.socket_path, lease.lease_id).connect(
                    "@host"
                )
                for frame in encode_message(request, None):
                    await stream.send(frame)
                reader = MessageStreamReader(stream.receive, bulk_cap=1 << 20)
                reports: list[StageReport] = []
                while len(reports) < 5:
                    message, _ = await reader.next()
                    assert isinstance(message, StageReport)
                    reports.append(message)
                await stream.aclose()
                runs.append(reports)
            assert [report.stage for report in runs[0]] == [
                "fetch",
                "construct",
                "boot",
                "verify",
                "ready",
            ]
            assert runs[0] == runs[1], "a resumed stream must replay identically"
            assert len(rig.up_calls) == 1, "the same id executed exactly once"
            relays = rig.applier._relays  # pyright: ignore[reportPrivateUsage]
            assert set(relays[lease.lease_id]) == {"attacker", "web"}

    asyncio.run(scenario())


def test_realize_refusals_are_typed_and_never_memoized(tmp_path: Path) -> None:
    async def scenario() -> None:
        async with Rig(tmp_path, capacity=HostCapacity(cpus=2, memory_mb=8192)) as rig:
            lease, digest = rig.lease(tmp_path, "ir-refuse")

            with pytest.raises(HostRefused) as grants:
                async for _ in rig.channel(lease).realize(digest, ["https://x"]):
                    pass
            assert grants.value.errno == "ENOTSUP"

            with pytest.raises(HostRefused) as mismatch:
                async for _ in rig.channel(lease).realize("ab" * 32, []):
                    pass
            assert mismatch.value.errno == "EINVAL"
            assert rig.up_calls == [], "a refused realize never touches up"

            # full-now: the two-guest plan (2 cpus) fits capacity exactly; a
            # pre-charge makes it EAGAIN, releasing it makes the SAME digest
            # succeed (refusals are never memoized)
            from inspect_ranges._compiler.plan import Totals

            assert rig.applier.admission.charge_now(
                Totals(guests=1, cpus=1, memory_mb=1024)
            )
            with pytest.raises(HostRefused) as full:
                async for _ in rig.channel(lease).realize(digest, []):
                    pass
            assert full.value.errno == "EAGAIN"
            await rig.applier.admission.release(
                Totals(guests=1, cpus=1, memory_mb=1024)
            )
            stages = [r.stage async for r in rig.channel(lease).realize(digest, [])]
            assert stages[-1] == "ready"

    asyncio.run(scenario())


def test_second_realize_on_a_charged_lease_refuses_ebusy(tmp_path: Path) -> None:
    """One realize per lease: a FRESH-id realize on a realized lease must not double-charge admission or re-run up against the live project."""

    async def scenario() -> None:
        async with Rig(tmp_path) as rig:
            lease, digest = rig.lease(tmp_path, "ir-once")
            stages = [r.stage async for r in rig.channel(lease).realize(digest, [])]
            assert stages[-1] == "ready"
            with pytest.raises(HostRefused) as refusal:
                async for _ in rig.channel(lease).realize(digest, []):
                    pass
            assert refusal.value.errno == "EBUSY"
            assert len(rig.up_calls) == 1, "up must not re-run on the live project"

    asyncio.run(scenario())


def test_expired_lease_refuses_realize(tmp_path: Path) -> None:
    """The realize gate mirrors the guest plane: an expired-but-unreaped lease must not start a boot the reaper's teardown would race."""

    async def scenario() -> None:
        async with Rig(tmp_path) as rig:
            lease, digest = rig.lease(tmp_path, "ir-stale", expired=True)
            with pytest.raises(HostRefused) as refusal:
                async for _ in rig.channel(lease).realize(digest, []):
                    pass
            assert refusal.value.errno == "EINVAL"
            assert "expired" in str(refusal.value)
            assert rig.up_calls == []

    asyncio.run(scenario())


def test_range_exceeding_capacity_refuses_enospc(tmp_path: Path) -> None:
    async def scenario() -> None:
        async with Rig(tmp_path, capacity=HostCapacity(cpus=1, memory_mb=512)) as rig:
            lease, digest = rig.lease(tmp_path, "ir-enospc")
            with pytest.raises(HostRefused) as refusal:
                async for _ in rig.channel(lease).realize(digest, []):
                    pass
            assert refusal.value.errno == "ENOSPC"

    asyncio.run(scenario())


def test_up_error_feeds_the_synthetic_failed_report(tmp_path: Path) -> None:
    """A pre-stage-log UpError (verify-bundle never reaches on_stage) still reaches the driver as one terminal `failed` report with the lossless stage prefix, and the admission charge is released."""

    async def scenario() -> None:
        async with Rig(tmp_path, capacity=HostCapacity(cpus=2, memory_mb=8192)) as rig:
            lease, digest = rig.lease(tmp_path, "ir-fail")
            (Path(lease.bundle_path) / "fail-at-stage").write_text("verify-bundle\n")
            reports = [
                report async for report in rig.channel(lease).realize(digest, [])
            ]
            assert [report.stage for report in reports] == ["failed"]
            assert reports[0].detail.startswith("verify-bundle:")
            # the charge was released: a fresh realize fits again
            (Path(lease.bundle_path) / "fail-at-stage").unlink()
            stages = [r.stage async for r in rig.channel(lease).realize(digest, [])]
            assert stages[-1] == "ready"

    asyncio.run(scenario())


# -- heartbeat, teardown, restart -----------------------------------------------------


def test_heartbeat_reports_guest_states_after_realize(tmp_path: Path) -> None:
    async def scenario() -> None:
        async with Rig(tmp_path) as rig:
            lease, digest = rig.lease(tmp_path, "ir-beat")
            channel = rig.channel(lease)
            before = await channel.heartbeat()
            assert before.guests == {}
            async for _ in channel.realize(digest, []):
                pass
            after = await channel.heartbeat()
            assert after.guests == {"attacker": "ready", "web": "ready"}

    asyncio.run(scenario())


def test_teardown_releases_charge_and_relay_map(tmp_path: Path) -> None:
    async def scenario() -> None:
        async with Rig(tmp_path, capacity=HostCapacity(cpus=2, memory_mb=8192)) as rig:
            lease, digest = rig.lease(tmp_path, "ir-td")
            channel = rig.channel(lease)
            async for _ in channel.realize(digest, []):
                pass
            await channel.teardown()
            assert rig.down_calls == ["ir-td"]
            relays = rig.applier._relays  # pyright: ignore[reportPrivateUsage]
            assert lease.lease_id not in relays
            # the charge came back: a same-size realize fits immediately
            second, digest2 = rig.lease(tmp_path, "ir-td2")
            stages = [r.stage async for r in rig.channel(second).realize(digest2, [])]
            assert stages[-1] == "ready"

    asyncio.run(scenario())


def test_restart_with_live_leases_logs_the_loss_loudly(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    async def scenario() -> None:
        rig = Rig(tmp_path)
        rig.lease(tmp_path, "ir-live", with_bundle=False)
        with caplog.at_level(logging.WARNING, logger="inspect_ranges.applier"):
            async with rig:
                pass
        messages = " ".join(record.getMessage() for record in caplog.records)
        assert "LOST" in messages and "reaper" in messages

    asyncio.run(scenario())


def test_applier_cli_is_registered() -> None:
    from click.testing import CliRunner
    from inspect_ranges._cli.main import ranges

    result = CliRunner().invoke(ranges, ["applier", "--help"])
    assert result.exit_code == 0
    assert "--socket" in result.output


def test_reaper_tears_down_through_the_live_applier(tmp_path: Path) -> None:
    """The real connector: an expired `uds:` lease is reclaimed THROUGH the applier socket (charge and relay released applier-side), not by direct down."""

    async def scenario() -> None:
        async with Rig(tmp_path) as rig:
            lease, digest = rig.lease(tmp_path, "ir-reap")
            async for _ in rig.channel(lease).realize(digest, []):
                pass
            past = (datetime.now(UTC) - timedelta(seconds=60)).isoformat()
            with rig.store._registry.locked(write=True) as view:  # pyright: ignore[reportPrivateUsage]
                view.entries[lease.lease_id] = lease.model_copy(
                    update={"expires_at": past}
                )
            direct_down: list[str] = []

            def never_down(project: str, state_dir: Path) -> DownResult:
                direct_down.append(project)
                return DownResult(project=project, containers=0, volumes=0, networks=0)

            outcomes = await asyncio.to_thread(
                lambda: sweep(rig.state, store=rig.store, down_fn=never_down)
            )
            assert [(o.action, o.project) for o in outcomes] == [("reaped", "ir-reap")]
            assert rig.down_calls == ["ir-reap"], "teardown went through the applier"
            assert direct_down == [], "the direct-down fallback must not fire"
            assert rig.store.leases() == []
            relays = rig.applier._relays  # pyright: ignore[reportPrivateUsage]
            assert lease.lease_id not in relays

    asyncio.run(scenario())

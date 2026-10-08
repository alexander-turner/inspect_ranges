"""Slice 2 battery: the portable conformance suite on loopback, loopback-only fault-injection pins, the sample state machine, and channel logging.

The loopback-only section uses `FakeGuest`/`FakeApplier` introspection and fault flags deliberately: these pin the endpoint contract (exactly-once dedupe, durable results, replayed realize streams) that the real daemon's own battery must mirror with real fault injection.
"""

import asyncio
import logging

import pytest
from inspect_ranges._channel.channel import (
    ChannelBudgetError,
    ChannelError,
    GuestError,
    IllegalTransition,
    LoopbackTransport,
    MessageChannel,
    SamplePhase,
    SampleStateMachine,
    TransportFailure,
    request_id,
    run_sample,
)
from inspect_ranges._channel.protocol import Budget, ExecRequest

from tests.channel_conformance import PortableChannelSuite

GUESTS = ("web", "db")


class TestLoopbackPortable(PortableChannelSuite):
    """The portable conformance suite over the plain loopback transport."""

    @pytest.fixture
    def channel(self, fleet: LoopbackTransport) -> MessageChannel:
        return MessageChannel(fleet, label="loopback")

    @pytest.fixture
    def fleet(self) -> LoopbackTransport:
        return LoopbackTransport(GUESTS)


# -- loopback-only behavior pins: dedupe, durability, replay ---------------------


@pytest.fixture
def fleet() -> LoopbackTransport:
    return LoopbackTransport(GUESTS)


@pytest.fixture
def channel(fleet: LoopbackTransport) -> MessageChannel:
    return MessageChannel(fleet, label="loopback")


def test_dropped_exec_reply_recovered_exactly_once(
    channel: MessageChannel, fleet: LoopbackTransport
) -> None:
    async def scenario() -> None:
        fleet.guest("web").drop_next_reply = True
        outcome = await channel.exec(
            "web", ExecRequest(id=request_id(), cmd=["echo", "once"])
        )
        assert outcome.stdout == b"once\n"
        assert fleet.guest("web").exec_count == 1, "retry double-ran the command"

    asyncio.run(scenario())


def test_dropped_write_reply_recovered_exactly_once(
    channel: MessageChannel, fleet: LoopbackTransport
) -> None:
    """Dedupe is a property of every request kind, not an exec special case."""

    async def scenario() -> None:
        fleet.guest("web").drop_next_reply = True
        await channel.write_file("web", "/tmp/once", b"payload")
        assert fleet.guest("web").write_count == 1, "retry double-ran the write"
        assert fleet.guest("web").files["/tmp/once"] == b"payload"

    asyncio.run(scenario())


def test_connection_death_mid_run_attaches_to_same_run(
    channel: MessageChannel, fleet: LoopbackTransport
) -> None:
    async def scenario() -> None:
        fleet.guest("web").close_mid_run = True
        outcome = await channel.exec(
            "web", ExecRequest(id=request_id(), cmd=["echo", "attached"])
        )
        assert outcome.stdout == b"attached\n"
        assert fleet.guest("web").exec_count == 1

    asyncio.run(scenario())


def test_consumed_results_are_acked_and_dropped(
    channel: MessageChannel, fleet: LoopbackTransport
) -> None:
    """Every consumed durable result is acked, including durable errors (the ETIME leak)."""

    async def scenario() -> None:
        await channel.exec("web", ExecRequest(id=request_id(), cmd=["true"]))
        await channel.write_file("web", "/tmp/blob", b"data")
        await channel.read_file("web", "/tmp/blob")
        with pytest.raises(ChannelBudgetError):
            await channel.exec(
                "web",
                ExecRequest(
                    id=request_id(),
                    cmd=["sleep-ms", "2000"],
                    budget=Budget(command_ms=30),
                ),
            )
        with pytest.raises(GuestError):
            await channel.read_file("web", "/missing")
        assert fleet.guest("web").stored_reply_count() == 0

    asyncio.run(scenario())


def test_evicted_unacked_result_tombstones_never_rerun(
    channel: MessageChannel, fleet: LoopbackTransport
) -> None:
    """Blocking finding 2: delivered, executed, evicted before the retry must be ESTALE, never a double run."""

    async def scenario() -> None:
        rid = request_id()
        guest = fleet.guest("web")
        # deliver and execute, with the reply dropped in flight
        guest.drop_next_reply = True
        first = await guest.handle(ExecRequest(id=rid, cmd=["echo", "once"]), None)
        assert first.message.kind == "exec_result"
        assert guest.exec_count == 1
        # the unacked result is evicted from the bounded store (raw handles:
        # channel.write_file would ack-and-drop its own entries)
        from inspect_ranges._channel.protocol import WriteFileRequest

        for index in range(300):
            await guest.handle(
                WriteFileRequest(
                    id=request_id(), path=f"/tmp/flood-{index % 3}", data_size=1
                ),
                b"x",
            )
        assert guest.stored_reply_count() <= 256
        # the client's resend of the SAME id must refuse, not re-run
        with pytest.raises(TransportFailure, match="result lost"):
            await channel.exec("web", ExecRequest(id=rid, cmd=["echo", "once"]))
        assert guest.exec_count == 1, "the tombstone must forbid a re-run"

    asyncio.run(scenario())


def test_realize_resumes_lost_stream_exactly_once(
    channel: MessageChannel, fleet: LoopbackTransport
) -> None:
    """A stream lost mid-realize is loss: resumed on the same id, replayed, never re-executed."""

    async def scenario() -> None:
        fleet.applier.drop_after_reports = 2
        stages = [report.stage async for report in channel.realize("ab" * 32, [])]
        assert stages == ["fetch", "construct", "boot", "verify", "ready"]
        assert fleet.applier.realize_executions == 1, "resume re-ran the realization"

    asyncio.run(scenario())


def test_realize_failure_is_a_terminal_stage(
    channel: MessageChannel, fleet: LoopbackTransport
) -> None:
    async def scenario() -> None:
        fleet.applier.fail_at_stage = "boot"
        stages = [report.stage async for report in channel.realize("cd" * 32, [])]
        assert stages[-1] == "failed"

    asyncio.run(scenario())


# -- sample state machine ------------------------------------------------------


def _phases(machine: SampleStateMachine) -> list[str]:
    return [new.value for _, new, _ in machine.history]


def test_run_sample_happy_path_walks_the_lifecycle() -> None:
    fleet = LoopbackTransport(["web"])
    channel = MessageChannel(fleet)

    async def scenario() -> SampleStateMachine:
        async def execute(chan: MessageChannel) -> None:
            outcome = await chan.exec("web", ExecRequest(id=request_id(), cmd=["true"]))
            assert outcome.rc == 0

        return await run_sample(
            channel,
            bundle_digest="ab" * 32,
            verify_guests=["web"],
            execute=execute,
        )

    machine = asyncio.run(scenario())
    assert _phases(machine) == [
        "acquired",
        "realized",
        "verified",
        "executing",
        "finalized",
        "destroyed",
    ]
    assert fleet.applier.torn_down


def test_run_sample_realize_failure_fails_then_destroys() -> None:
    fleet = LoopbackTransport(["web"])
    fleet.applier.fail_at_stage = "boot"
    channel = MessageChannel(fleet)

    async def scenario() -> SampleStateMachine:
        machine = SampleStateMachine()
        with pytest.raises(ChannelError, match="injected failure at boot"):
            await run_sample(channel, bundle_digest="ab" * 32, machine=machine)
        return machine

    machine = asyncio.run(scenario())
    assert _phases(machine) == ["acquired", "failed", "destroyed"]
    assert fleet.applier.torn_down, "teardown must run on the failure path"


def test_run_sample_teardown_retry_recovers_quietly() -> None:
    """One teardown failure on the success path: the retry succeeds, destroyed is honest."""
    fleet = LoopbackTransport(["web"])
    fleet.applier.fail_teardown_times = 1
    channel = MessageChannel(fleet)

    machine = asyncio.run(run_sample(channel, bundle_digest="ab" * 32))
    assert _phases(machine)[-2:] == ["finalized", "destroyed"]
    assert fleet.applier.torn_down


def test_run_sample_teardown_retry_also_fails_lands_in_failed() -> None:
    """Both teardown attempts fail: the machine must NOT claim destruction."""
    fleet = LoopbackTransport(["web"])
    fleet.applier.fail_teardown_times = 2
    channel = MessageChannel(fleet)

    async def scenario() -> SampleStateMachine:
        machine = SampleStateMachine()
        with pytest.raises(GuestError, match="injected teardown failure"):
            await run_sample(channel, bundle_digest="ab" * 32, machine=machine)
        return machine

    machine = asyncio.run(scenario())
    assert _phases(machine)[-1] == "failed", "destroyed without a completed teardown"
    assert not fleet.applier.torn_down


def test_run_sample_failure_path_teardown_failure_keeps_original_error() -> None:
    """A teardown that also fails never masks the sample's own failure."""
    fleet = LoopbackTransport(["web"])
    fleet.applier.fail_at_stage = "verify"
    fleet.applier.fail_teardown_times = 2
    channel = MessageChannel(fleet)

    async def scenario() -> SampleStateMachine:
        machine = SampleStateMachine()
        with pytest.raises(ChannelError, match="injected failure at verify"):
            await run_sample(channel, bundle_digest="ab" * 32, machine=machine)
        return machine

    machine = asyncio.run(scenario())
    assert _phases(machine)[-1] == "failed"


ILLEGAL_EDGES = [
    (SamplePhase.CREATED, SamplePhase.EXECUTING),
    (SamplePhase.CREATED, SamplePhase.DESTROYED),
    (SamplePhase.CREATED, SamplePhase.CREATED),
]


@pytest.mark.parametrize(
    "edge", ILLEGAL_EDGES, ids=lambda e: f"{e[0].value}->{e[1].value}"
)
def test_illegal_transitions_are_rejected(
    edge: tuple[SamplePhase, SamplePhase],
) -> None:
    machine = SampleStateMachine()
    with pytest.raises(IllegalTransition):
        machine.to(edge[1])
    assert machine.phase is SamplePhase.CREATED, (
        "a rejected transition must not move the machine"
    )


def test_terminal_phase_permits_nothing() -> None:
    machine = SampleStateMachine()
    machine.to(SamplePhase.ACQUIRED)
    machine.to(SamplePhase.FAILED)
    machine.to(SamplePhase.DESTROYED)
    with pytest.raises(IllegalTransition):
        machine.to(SamplePhase.ACQUIRED)


def test_observers_see_every_transition_and_may_fail() -> None:
    machine = SampleStateMachine()
    seen: list[tuple[str, str]] = []

    def observer(old: SamplePhase, new: SamplePhase) -> None:
        seen.append((old.value, new.value))
        raise RuntimeError("observer bug (must be non-fatal)")

    machine.observe(observer)
    machine.to(SamplePhase.ACQUIRED)
    machine.to(SamplePhase.FAILED)
    assert seen == [("created", "acquired"), ("acquired", "failed")]
    assert machine.phase is SamplePhase.FAILED


# -- logging and debuggability ---------------------------------------------------


def test_operations_log_with_request_id_correlation(
    caplog: pytest.LogCaptureFixture,
) -> None:
    fleet = LoopbackTransport(["web"])
    channel = MessageChannel(fleet, label="test-channel")

    async def scenario() -> None:
        await channel.exec("web", ExecRequest(id=request_id(), cmd=["true"]))

    with caplog.at_level(logging.DEBUG, logger="inspect_ranges.channel"):
        asyncio.run(scenario())

    def record_field(record: logging.LogRecord, name: str) -> str | None:
        value: object = getattr(record, name, None)
        return value if isinstance(value, str) else None

    tagged = [record for record in caplog.records if record_field(record, "request_id")]
    assert tagged, "channel operations must log with a request_id field"
    assert all(record_field(record, "endpoint") == "web" for record in tagged)
    exec_id = record_field(tagged[0], "request_id")
    assert any(
        record_field(record, "request_id") == exec_id
        and "request" in record.getMessage()
        for record in caplog.records
    )


def test_trace_tail_records_the_wire_conversation() -> None:
    fleet = LoopbackTransport(["web"])
    channel = MessageChannel(fleet)

    async def scenario() -> None:
        await channel.write_file("web", "/tmp/t", b"x" * 70_000)

    asyncio.run(scenario())
    tail = channel.trace_tail()
    assert any("CONTROL" in line and "write_file" in line for line in tail)
    assert sum("DATA" in line for line in tail) >= 3  # 70 KB = 3 chunks
    assert any("END" in line and "note=" in line for line in tail)

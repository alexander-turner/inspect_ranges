"""Slice 2 battery: the conformance suite on loopback, the sample state machine, and channel logging."""

import asyncio
import logging

import pytest
from inspect_ranges._channel.channel import (
    ChannelError,
    IllegalTransition,
    LoopbackTransport,
    MessageChannel,
    SamplePhase,
    SampleStateMachine,
    Transport,
    request_id,
    run_sample,
)
from inspect_ranges._channel.protocol import ExecRequest

from tests.channel_conformance import ChannelConformanceSuite


class TestLoopback(ChannelConformanceSuite):
    """The full conformance suite over the plain loopback transport."""

    def make_transport(self, fleet: LoopbackTransport) -> Transport:
        return fleet


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


def test_observers_see_every_transition() -> None:
    machine = SampleStateMachine()
    seen: list[tuple[str, str]] = []
    machine.observe(lambda old, new: seen.append((old.value, new.value)))
    machine.to(SamplePhase.ACQUIRED)
    machine.to(SamplePhase.FAILED)
    assert seen == [("created", "acquired"), ("acquired", "failed")]


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

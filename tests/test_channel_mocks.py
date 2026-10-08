"""Slice 3 battery: the hostile and latency mock channels complete the conformance suite.

Hostile replies must surface as typed failures (tamper, never a parse fallback), with the wire-trace tail dumped on every tamper verdict. Each hostile scenario drives the operation whose defense it attacks (exec-shaped forgeries through `exec`). The latency mock runs the whole portable suite at injected round trips (50 ms for speed, with one second-scale smoke test), and catches the chatty reference bug a fast transport would hide.
"""

import asyncio
import logging
import time
from collections.abc import Callable, Coroutine

import pytest
from inspect_ranges._channel.channel import (
    ChannelBudgetError,
    LoopbackTransport,
    MessageChannel,
    TamperError,
    TransportFailure,
    request_id,
)
from inspect_ranges._channel.mocks import (
    HOSTILE_APPLIER_HANGS,
    HOSTILE_APPLIER_SCENARIOS,
    HOSTILE_GUEST_SCENARIOS,
    DribbleTransport,
    HostileApplierTransport,
    HostileTransport,
    LatencyTransport,
    SilentTransport,
)
from inspect_ranges._channel.protocol import ExecRequest

from tests.channel_conformance import PortableChannelSuite

RTT_S = 0.05


class TestLatencyPortable(PortableChannelSuite):
    """The portable suite at injected round trips: hot-path regressions fail here first."""

    @pytest.fixture
    def channel(self) -> MessageChannel:
        return MessageChannel(
            LatencyTransport(LoopbackTransport([self.guest]), rtt_s=RTT_S),
            label="latency",
        )


def test_second_scale_round_trip_smoke() -> None:
    """One representative exchange at genuinely second-scale latency (the connectionless model)."""
    channel = MessageChannel(
        LatencyTransport(LoopbackTransport(["web"]), rtt_s=1.0), label="slow"
    )

    async def scenario() -> None:
        outcome = await channel.exec(
            "web", ExecRequest(id=request_id(), cmd=["echo", "slow"])
        )
        assert outcome.stdout == b"slow\n"

    start = time.monotonic()
    asyncio.run(scenario())
    assert time.monotonic() - start >= 2.0, "the smoke test must actually pay the RTTs"


def test_dribbled_delivery_still_decodes() -> None:
    """Reply bytes arriving one at a time must not disturb a single operation."""
    channel = MessageChannel(
        DribbleTransport(LoopbackTransport(["web"])), label="dribble"
    )

    async def scenario() -> None:
        outcome = await channel.exec(
            "web", ExecRequest(id=request_id(), cmd=["echo", "dribble"])
        )
        assert outcome.stdout == b"dribble\n"

    asyncio.run(scenario())


# -- hostile guest endpoint: every scenario is a typed failure, never a fallback --

EXPECTED_FAILURE: dict[str, type[Exception]] = {
    scenario: TamperError for scenario in HOSTILE_GUEST_SCENARIOS
}
# a truncated reply is indistinguishable from loss: retried, then given up.
# NOTE: any future layer retrying TransportFailure with a FRESH id would
# reintroduce double-runs (tamper-laundering via truncation); see protocol.Budget.
EXPECTED_FAILURE["truncated-reply"] = TransportFailure


async def _drive(channel: MessageChannel, operation: str) -> None:
    if operation == "exec":
        await channel.exec("web", ExecRequest(id=request_id(), cmd=["true"]))
    elif operation == "write_file":
        await channel.write_file("web", "/tmp/x", b"payload")
    else:
        await channel.read_file("web", "/etc/shadow", cap=1024)


@pytest.mark.parametrize("scenario", sorted(HOSTILE_GUEST_SCENARIOS))
def test_hostile_reply_surfaces_as_typed_failure(scenario: str) -> None:
    transport = HostileTransport(scenario)
    channel = MessageChannel(transport, label=f"hostile-{scenario}")
    operation = HOSTILE_GUEST_SCENARIOS[scenario][1]

    async def scenario_run() -> None:
        with pytest.raises(EXPECTED_FAILURE[scenario]):
            await _drive(channel, operation)

    asyncio.run(scenario_run())
    assert transport.requests_seen >= 1


@pytest.mark.parametrize(
    "scenario",
    [
        "garbage-bytes",
        "wrong-kind",
        "wrong-id",
        "unsolicited-bulk",
        "duplicate-reply",
        "trailing-garbage",
    ],
)
def test_hostile_failure_dumps_the_trace_tail(
    scenario: str, caplog: pytest.LogCaptureFixture
) -> None:
    """Every tamper verdict dumps the trace tail, not just codec-level ones."""
    channel = MessageChannel(HostileTransport(scenario), label="hostile")
    operation = HOSTILE_GUEST_SCENARIOS[scenario][1]

    async def scenario_run() -> None:
        with pytest.raises(TamperError):
            await _drive(channel, operation)

    with caplog.at_level(logging.ERROR, logger="inspect_ranges.channel"):
        asyncio.run(scenario_run())
    messages = [record.getMessage() for record in caplog.records]
    assert any("trace tail follows" in message for message in messages)
    assert any("CONTROL" in message for message in messages), (
        "the dump must include the wire conversation"
    )


def test_hostile_wrong_id_names_both_ids() -> None:
    channel = MessageChannel(HostileTransport("wrong-id"))

    async def scenario_run() -> tuple[str, str]:
        request = request_id()
        try:
            await channel.read_file("web", "/x")
        except TamperError as failure:
            return request, str(failure)
        raise AssertionError("wrong-id reply was accepted")

    _, message = asyncio.run(scenario_run())
    assert "f" * 32 in message, "the tamper error must name the forged id"
    assert "request was id" in message, "the tamper error must name the request id"


# -- hostile host plane -------------------------------------------------------


@pytest.mark.parametrize("scenario", sorted(HOSTILE_APPLIER_SCENARIOS))
def test_hostile_stage_reports_are_tamper(scenario: str) -> None:
    channel = MessageChannel(HostileApplierTransport(scenario), label="hostile-applier")

    async def scenario_run() -> None:
        with pytest.raises(TamperError):
            async for _ in channel.realize("ab" * 32, []):
                pass

    asyncio.run(scenario_run())


# -- budget layers under hostile transports ------------------------------------


def test_silent_transport_fails_at_channel_allowance() -> None:
    """A silent transport on a budget-less op fires the channel allowance, attributed correctly."""
    channel = MessageChannel(
        SilentTransport(), label="silent", channel_budget_s=0.2, untimed_bound_s=10.0
    )

    async def scenario_run() -> None:
        with pytest.raises(ChannelBudgetError) as failure:
            await channel.read_file("web", "/x")
        assert failure.value.layer == "channel"

    start = time.monotonic()
    asyncio.run(scenario_run())
    assert time.monotonic() - start < 2.0


def test_untimed_outer_total_caps_attempts_and_backoff() -> None:
    """Failing connects then silence must fail at the TOTAL bound with layer untimed, not 3x."""
    channel = MessageChannel(
        SilentTransport(fail_connects=2),
        label="flaky-silent",
        channel_budget_s=5.0,
        untimed_bound_s=0.5,
    )

    async def scenario_run() -> None:
        with pytest.raises(ChannelBudgetError) as failure:
            await channel.read_file("web", "/x")
        assert failure.value.layer == "untimed"

    start = time.monotonic()
    asyncio.run(scenario_run())
    elapsed = time.monotonic() - start
    assert elapsed < 1.5, (
        f"the outer total must cap the whole operation ({elapsed:.2f}s)"
    )


@pytest.mark.parametrize("scenario", sorted(HOSTILE_APPLIER_HANGS))
def test_realize_never_hangs_on_hostile_applier(scenario: str) -> None:
    """Every realize transport interaction is budget-bounded (the two probe-demonstrated hangs)."""
    channel = MessageChannel(
        HostileApplierTransport(scenario),
        label=f"hang-{scenario}",
        channel_budget_s=0.2,
        untimed_bound_s=1.0,
    )

    async def scenario_run() -> list[str]:
        stages: list[str] = []
        if scenario == "hang-connect":
            with pytest.raises(ChannelBudgetError):
                async for report in channel.realize("ab" * 32, []):
                    stages.append(report.stage)
        else:
            # terminal already delivered: a never-closing stream is not a failure
            async for report in channel.realize("ab" * 32, []):
                stages.append(report.stage)
        return stages

    start = time.monotonic()
    stages = asyncio.run(scenario_run())
    assert time.monotonic() - start < 3.0, "realize hung past its budgets"
    if scenario == "no-close-after-ready":
        assert stages[-1] == "ready", "the delivered terminal stage must be returned"


def test_divergent_resume_replay_is_tamper() -> None:
    from inspect_ranges._channel.channel import TamperError as Tamper

    fleet = LoopbackTransport(["web"])
    fleet.applier.drop_after_reports = 2
    fleet.applier.corrupt_replay = True
    channel = MessageChannel(fleet, label="diverging")

    async def scenario_run() -> None:
        with pytest.raises(Tamper, match="resumed replay diverged"):
            async for _ in channel.realize("ab" * 32, []):
                pass

    asyncio.run(scenario_run())


# -- the chatty reference bug ----------------------------------------------------


async def _proper_transfer(channel: MessageChannel, data: bytes) -> None:
    await channel.write_file("web", "/srv/blob", data)


async def _chatty_transfer(channel: MessageChannel, data: bytes) -> None:
    """The reference bug: one channel operation per 4 KiB slice instead of one transfer."""
    for index, offset in enumerate(range(0, len(data), 4096)):
        await channel.write_file(
            "web", f"/srv/blob.{index}", data[offset : offset + 4096]
        )


def test_latency_mock_catches_the_chatty_reference_bug() -> None:
    data = b"x" * (12 * 4096)
    fleet = LoopbackTransport(["web"])
    channel = MessageChannel(LatencyTransport(fleet, rtt_s=RTT_S), label="latency")

    async def timed(
        transfer: Callable[[MessageChannel, bytes], Coroutine[None, None, None]],
    ) -> float:
        start = time.monotonic()
        await transfer(channel, data)
        return time.monotonic() - start

    proper = asyncio.run(timed(_proper_transfer))
    chatty = asyncio.run(timed(_chatty_transfer))
    # sleeps only stretch under load, so compare shape, not absolute wall time
    assert chatty > 1.0, f"the chatty bug must be visibly slow ({chatty:.2f}s)"
    assert chatty > 4 * proper, (
        f"chatty ({chatty:.2f}s) must dwarf the single transfer ({proper:.2f}s)"
    )

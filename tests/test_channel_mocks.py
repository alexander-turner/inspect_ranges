"""Slice 3 battery: the hostile and latency mock channels complete the conformance suite.

Hostile replies must surface as typed failures (tamper, never a parse fallback), with the wire-trace tail dumped to the log. The latency mock runs the whole conformance suite at second-scale round trips and catches the chatty reference bug a fast transport would hide.
"""

import asyncio
import logging
import time
from collections.abc import Callable, Coroutine

import pytest
from inspect_ranges._channel.channel import (
    LoopbackTransport,
    MessageChannel,
    TamperError,
    Transport,
    TransportFailure,
)
from inspect_ranges._channel.mocks import (
    HOSTILE_SCENARIOS,
    HostileTransport,
    LatencyTransport,
)

from tests.channel_conformance import ChannelConformanceSuite

RTT_S = 0.05


class TestLatency(ChannelConformanceSuite):
    """The full conformance suite at second-scale round trips: hot-path regressions fail here first."""

    def make_transport(self, fleet: LoopbackTransport) -> Transport:
        return LatencyTransport(fleet, rtt_s=RTT_S)


# -- hostile endpoint: every scenario is a typed failure, never a fallback ------

EXPECTED_FAILURE: dict[str, type[Exception]] = {
    scenario: TamperError for scenario in HOSTILE_SCENARIOS
}
# a truncated reply is indistinguishable from loss: retried, then given up
EXPECTED_FAILURE["truncated-reply"] = TransportFailure


@pytest.mark.parametrize("scenario", sorted(HOSTILE_SCENARIOS))
def test_hostile_reply_surfaces_as_typed_failure(scenario: str) -> None:
    transport = HostileTransport(scenario)
    channel = MessageChannel(transport, label=f"hostile-{scenario}")

    async def scenario_run() -> None:
        with pytest.raises(EXPECTED_FAILURE[scenario]):
            await channel.read_file("web", "/etc/shadow", cap=1024)

    asyncio.run(scenario_run())
    assert transport.requests_seen >= 1


def test_hostile_failure_dumps_the_trace_tail(caplog: pytest.LogCaptureFixture) -> None:
    channel = MessageChannel(HostileTransport("garbage-bytes"), label="hostile")

    async def scenario_run() -> None:
        with pytest.raises(TamperError):
            await channel.read_file("web", "/etc/shadow")

    with caplog.at_level(logging.ERROR, logger="inspect_ranges.channel"):
        asyncio.run(scenario_run())
    messages = [record.getMessage() for record in caplog.records]
    assert any("trace tail follows" in message for message in messages)
    assert any("CONTROL" in message for message in messages), (
        "the dump must include the wire conversation"
    )


def test_hostile_wrong_id_names_both_ids() -> None:
    channel = MessageChannel(HostileTransport("wrong-id"))

    async def scenario_run() -> str:
        try:
            await channel.read_file("web", "/x")
        except TamperError as failure:
            return str(failure)
        raise AssertionError("wrong-id reply was accepted")

    message = asyncio.run(scenario_run())
    assert "f" * 32 in message, "the tamper error must name the forged id"


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
    assert proper < 1.0, f"a single transfer must stay fast ({proper:.2f}s)"
    assert chatty > 1.5, (
        f"the chatty implementation must be visibly slow under latency ({chatty:.2f}s)"
    )
    assert chatty > 4 * proper

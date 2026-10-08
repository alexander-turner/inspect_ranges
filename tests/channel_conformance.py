"""Transport-parameterized conformance suite for `RangeChannel` implementations.

Subclass `ChannelConformanceSuite` and override `make_transport` to run the whole suite against any transport (loopback, the latency mock, and, in later slices, the real vsock transport). The suite asserts the message contract from `range-channel.md`: exec semantics, bulk round trips across chunk boundaries, errno taxonomy, in-guest budgets with layer attribution, exactly-once dedupe across lost replies, durable results acked and dropped, and per-operation round-trip budgets (the chatty-regression guard).
"""

import asyncio
from collections.abc import Callable, Coroutine

import pytest
from inspect_ranges._channel.channel import (
    ChannelBudgetError,
    GuestError,
    LoopbackTransport,
    MessageChannel,
    Transport,
    request_id,
)
from inspect_ranges._channel.protocol import Budget, ExecRequest

GUESTS = ("web", "db")

# round trips allowed per operation (one exchange = request + reply); the ack
# of a consumed result is the second exchange. A chatty implementation that
# round-trips per chunk blows straight through these.
RTT_BUDGET = {"ping": 1, "exec": 2, "read_file": 2, "write_file": 2}


class ChannelConformanceSuite:
    """Inherit, override `make_transport`, and the whole contract runs against it."""

    def make_transport(self, fleet: LoopbackTransport) -> Transport:
        raise NotImplementedError

    @pytest.fixture
    def fleet(self) -> LoopbackTransport:
        return LoopbackTransport(GUESTS)

    @pytest.fixture
    def channel(self, fleet: LoopbackTransport) -> MessageChannel:
        return MessageChannel(self.make_transport(fleet), label="conformance")

    def run(self, scenario: Callable[[], Coroutine[None, None, None]]) -> None:
        asyncio.run(scenario())

    # -- exec semantics ------------------------------------------------------

    def test_ping(self, channel: MessageChannel) -> None:
        async def scenario() -> None:
            pong = await channel.ping("web")
            assert pong.protocol == 3

        self.run(scenario)

    def test_exec_stdout_and_rc(self, channel: MessageChannel) -> None:
        async def scenario() -> None:
            outcome = await channel.exec(
                "web", ExecRequest(id=request_id(), cmd=["echo", "hello", "range"])
            )
            assert outcome.rc == 0
            assert outcome.stdout == b"hello range\n"
            assert outcome.stderr == b""

        self.run(scenario)

    def test_exec_stderr_and_nonzero_rc(self, channel: MessageChannel) -> None:
        async def scenario() -> None:
            outcome = await channel.exec(
                "web", ExecRequest(id=request_id(), cmd=["stderr", "boom"])
            )
            assert outcome.rc == 2
            assert outcome.stdout == b""
            assert outcome.stderr == b"boom\n"

        self.run(scenario)

    def test_exec_stdin_round_trip(self, channel: MessageChannel) -> None:
        async def scenario() -> None:
            stdin = bytes(range(256)) * 200  # crosses the 32 KiB chunk boundary
            outcome = await channel.exec(
                "web",
                ExecRequest(id=request_id(), cmd=["cat", "-"], data_size=len(stdin)),
                stdin=stdin,
            )
            assert outcome.rc == 0
            assert outcome.stdout == stdin

        self.run(scenario)

    def test_exec_transmits_env_cwd_user(self, channel: MessageChannel) -> None:
        async def scenario() -> None:
            outcome = await channel.exec(
                "web",
                ExecRequest(
                    id=request_id(),
                    cmd=["env-dump"],
                    env={"ANSWER": "42"},
                    cwd="/srv",
                    user="postgres",
                ),
            )
            assert outcome.stdout == b"cwd=/srv\nuser=postgres\nANSWER=42\n"

        self.run(scenario)

    def test_exec_unknown_command_is_rc_127(self, channel: MessageChannel) -> None:
        async def scenario() -> None:
            outcome = await channel.exec(
                "web", ExecRequest(id=request_id(), cmd=["no-such-binary"])
            )
            assert outcome.rc == 127
            assert b"command not found" in outcome.stderr

        self.run(scenario)

    # -- files and errno taxonomy --------------------------------------------

    def test_write_read_round_trip_across_chunks(self, channel: MessageChannel) -> None:
        async def scenario() -> None:
            data = bytes(i % 251 for i in range(100_000))
            await channel.write_file("db", "/tmp/blob", data)
            assert await channel.read_file("db", "/tmp/blob") == data

        self.run(scenario)

    def test_read_missing_file_is_enoent(self, channel: MessageChannel) -> None:
        async def scenario() -> None:
            with pytest.raises(GuestError) as failure:
                await channel.read_file("db", "/no/such/file")
            assert failure.value.errno == "ENOENT"

        self.run(scenario)

    def test_read_directory_is_eisdir(self, channel: MessageChannel) -> None:
        async def scenario() -> None:
            with pytest.raises(GuestError) as failure:
                await channel.read_file("db", "/tmp")
            assert failure.value.errno == "EISDIR"

        self.run(scenario)

    # -- budgets ---------------------------------------------------------------

    def test_command_budget_fires_in_guest_with_layer(
        self, channel: MessageChannel
    ) -> None:
        async def scenario() -> None:
            with pytest.raises(ChannelBudgetError) as failure:
                await channel.exec(
                    "web",
                    ExecRequest(
                        id=request_id(),
                        cmd=["sleep-ms", "2000"],
                        budget=Budget(command_ms=50),
                    ),
                )
            assert failure.value.layer == "command"

        self.run(scenario)

    # -- dedupe and durability -------------------------------------------------

    def test_dropped_reply_recovered_exactly_once(
        self, channel: MessageChannel, fleet: LoopbackTransport
    ) -> None:
        async def scenario() -> None:
            fleet.guest("web").drop_next_reply = True
            outcome = await channel.exec(
                "web", ExecRequest(id=request_id(), cmd=["echo", "once"])
            )
            assert outcome.stdout == b"once\n"
            assert fleet.guest("web").exec_count == 1, "retry double-ran the command"

        self.run(scenario)

    def test_connection_death_mid_run_attaches_to_same_run(
        self, channel: MessageChannel, fleet: LoopbackTransport
    ) -> None:
        async def scenario() -> None:
            fleet.guest("web").close_mid_run = True
            outcome = await channel.exec(
                "web", ExecRequest(id=request_id(), cmd=["echo", "attached"])
            )
            assert outcome.stdout == b"attached\n"
            assert fleet.guest("web").exec_count == 1

        self.run(scenario)

    def test_consumed_results_are_acked_and_dropped(
        self, channel: MessageChannel, fleet: LoopbackTransport
    ) -> None:
        async def scenario() -> None:
            await channel.exec("web", ExecRequest(id=request_id(), cmd=["true"]))
            await channel.write_file("web", "/tmp/blob", b"data")
            await channel.read_file("web", "/tmp/blob")
            assert fleet.guest("web").stored_reply_count() == 0

        self.run(scenario)

    # -- round-trip budgets (the chatty-regression guard) -----------------------

    @pytest.mark.parametrize("operation", sorted(RTT_BUDGET))
    def test_round_trips_within_budget(
        self, channel: MessageChannel, operation: str
    ) -> None:
        async def scenario() -> None:
            payload = b"x" * 100_000  # chunked payloads must not multiply round trips
            before = channel.stats.exchanges
            if operation == "ping":
                await channel.ping("web")
            elif operation == "exec":
                await channel.exec(
                    "web",
                    ExecRequest(
                        id=request_id(), cmd=["cat", "-"], data_size=len(payload)
                    ),
                    stdin=payload,
                )
            elif operation == "write_file":
                await channel.write_file("web", "/tmp/rtt", payload)
            elif operation == "read_file":
                await channel.write_file("web", "/tmp/rtt", payload)
                before = channel.stats.exchanges
                await channel.read_file("web", "/tmp/rtt")
            used = channel.stats.exchanges - before
            assert used <= RTT_BUDGET[operation], (
                f"{operation} used {used} round trips (budget {RTT_BUDGET[operation]})"
            )

        self.run(scenario)

    # -- host lifecycle plane ----------------------------------------------------

    def test_realize_streams_stages_to_ready(self, channel: MessageChannel) -> None:
        async def scenario() -> None:
            stages = [report.stage async for report in channel.realize("ab" * 32, [])]
            assert stages == ["fetch", "construct", "boot", "verify", "ready"]

        self.run(scenario)

    def test_realize_failure_is_a_terminal_stage(
        self, channel: MessageChannel, fleet: LoopbackTransport
    ) -> None:
        async def scenario() -> None:
            fleet.applier.fail_at_stage = "boot"
            stages = [report.stage async for report in channel.realize("cd" * 32, [])]
            assert stages[-1] == "failed"

        self.run(scenario)

    def test_teardown_acknowledges(
        self, channel: MessageChannel, fleet: LoopbackTransport
    ) -> None:
        async def scenario() -> None:
            await channel.teardown()
            assert fleet.applier.torn_down

        self.run(scenario)

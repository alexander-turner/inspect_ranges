"""Transport-parameterized conformance suite for `RangeChannel` implementations.

`PortableChannelSuite` is the portable subset: it drives implementations purely through the public channel API and a declared in-guest fixture contract, so the real vsock transport (and real guests) inherit a runnable suite. Fault-injection and endpoint-introspection tests (dropped replies, mid-run connection death, durable-store inspection) are deliberately NOT here; they live beside the loopback tests as loopback-only behavior pins, and real-transport batteries provide their own fault injection.

The in-guest fixture contract a real conformance guest must satisfy, expressed as overridable argv builders (defaults speak the `FakeGuest` vocabulary; a Linux subclass maps them to `sh`): a zero-rc command, a nonzero-rc command with known stderr, an echo, a stdin-to-stdout copy, a sleep, and an environment probe reporting cwd, user, and one env var. Plus host-plane endpoints (`realize`, `teardown`) where the deployment provides them (`has_host_plane`).
"""

import asyncio
from collections.abc import Callable, Coroutine

import pytest
from inspect_ranges._channel.channel import (
    ChannelBudgetError,
    FileLimitExceeded,
    GuestError,
    MessageChannel,
    request_id,
)
from inspect_ranges._channel.protocol import Budget, ExecRequest

# round trips allowed per operation (one exchange = request + reply); the ack
# of a consumed result is the second exchange. A chatty implementation that
# round-trips per chunk blows straight through these.
RTT_BUDGET = {"ping": 1, "exec": 2, "read_file": 2, "write_file": 2}


class PortableChannelSuite:
    """Inherit, provide the `channel` fixture (and vocabulary overrides), and the portable contract runs."""

    guest = "web"
    has_host_plane = True
    missing_path = "/no/such/file"
    directory_path = "/tmp"
    scratch_path = "/tmp/conformance-blob"
    probe_cwd = "/srv"
    probe_user = "postgres"

    @pytest.fixture
    def channel(self) -> MessageChannel:
        raise NotImplementedError("subclasses provide the channel under test")

    # -- the in-guest fixture contract (override per guest OS) ---------------

    def argv_true(self) -> list[str]:
        return ["true"]

    def argv_stderr(self, text: str) -> tuple[list[str], int]:
        """A command printing `text` plus newline on stderr; returns (argv, expected rc != 0)."""
        return ["stderr", text], 2

    def argv_echo(self, text: str) -> list[str]:
        return ["echo", text]

    def argv_cat_stdin(self) -> list[str]:
        return ["cat", "-"]

    def argv_sleep_ms(self, ms: int) -> list[str]:
        return ["sleep-ms", str(ms)]

    def argv_env_probe(self) -> list[str]:
        return ["env-dump"]

    def expected_env_probe(self, env: dict[str, str], cwd: str, user: str) -> bytes:
        lines = [f"cwd={cwd}", f"user={user}"]
        lines += [f"{key}={value}" for key, value in sorted(env.items())]
        return ("\n".join(lines) + "\n").encode()

    def run(self, scenario: Callable[[], Coroutine[None, None, None]]) -> None:
        asyncio.run(scenario())

    # -- exec semantics ------------------------------------------------------

    def test_ping(self, channel: MessageChannel) -> None:
        async def scenario() -> None:
            pong = await channel.ping(self.guest)
            assert pong.protocol == 3

        self.run(scenario)

    def test_exec_stdout_and_rc(self, channel: MessageChannel) -> None:
        async def scenario() -> None:
            outcome = await channel.exec(
                self.guest,
                ExecRequest(id=request_id(), cmd=self.argv_echo("hello range")),
            )
            assert outcome.rc == 0
            assert outcome.stdout == b"hello range\n"
            assert outcome.stderr == b""

        self.run(scenario)

    def test_exec_stderr_and_nonzero_rc(self, channel: MessageChannel) -> None:
        async def scenario() -> None:
            argv, expected_rc = self.argv_stderr("boom")
            outcome = await channel.exec(
                self.guest, ExecRequest(id=request_id(), cmd=argv)
            )
            assert outcome.rc == expected_rc
            assert outcome.stdout == b""
            assert outcome.stderr == b"boom\n"

        self.run(scenario)

    def test_exec_stdin_round_trip(self, channel: MessageChannel) -> None:
        async def scenario() -> None:
            stdin = bytes(range(256)) * 200  # crosses the 32 KiB chunk boundary
            outcome = await channel.exec(
                self.guest,
                ExecRequest(
                    id=request_id(), cmd=self.argv_cat_stdin(), data_size=len(stdin)
                ),
                stdin=stdin,
            )
            assert outcome.rc == 0
            assert outcome.stdout == stdin

        self.run(scenario)

    def test_exec_transmits_env_cwd_user(self, channel: MessageChannel) -> None:
        async def scenario() -> None:
            outcome = await channel.exec(
                self.guest,
                ExecRequest(
                    id=request_id(),
                    cmd=self.argv_env_probe(),
                    env={"ANSWER": "42"},
                    cwd=self.probe_cwd,
                    user=self.probe_user,
                ),
            )
            assert outcome.stdout == self.expected_env_probe(
                {"ANSWER": "42"}, self.probe_cwd, self.probe_user
            )

        self.run(scenario)

    def test_exec_unknown_command_is_rc_127(self, channel: MessageChannel) -> None:
        async def scenario() -> None:
            outcome = await channel.exec(
                self.guest, ExecRequest(id=request_id(), cmd=["no-such-binary-xyzzy"])
            )
            assert outcome.rc == 127

        self.run(scenario)

    # -- files, errno taxonomy, caps -----------------------------------------

    def test_write_read_round_trip_across_chunks(self, channel: MessageChannel) -> None:
        async def scenario() -> None:
            data = bytes(i % 251 for i in range(100_000))
            await channel.write_file(self.guest, self.scratch_path, data)
            assert await channel.read_file(self.guest, self.scratch_path) == data

        self.run(scenario)

    def test_read_missing_file_is_enoent(self, channel: MessageChannel) -> None:
        async def scenario() -> None:
            with pytest.raises(GuestError) as failure:
                await channel.read_file(self.guest, self.missing_path)
            assert failure.value.errno == "ENOENT"

        self.run(scenario)

    def test_read_directory_is_eisdir(self, channel: MessageChannel) -> None:
        async def scenario() -> None:
            with pytest.raises(GuestError) as failure:
                await channel.read_file(self.guest, self.directory_path)
            assert failure.value.errno == "EISDIR"

        self.run(scenario)

    def test_read_cap_surfaces_honest_truncation(self, channel: MessageChannel) -> None:
        async def scenario() -> None:
            data = bytes(i % 251 for i in range(10_000))
            await channel.write_file(self.guest, self.scratch_path, data)
            with pytest.raises(FileLimitExceeded) as failure:
                await channel.read_file(self.guest, self.scratch_path, cap=4096)
            assert failure.value.partial == data[:4096]

        self.run(scenario)

    # -- budgets ---------------------------------------------------------------

    def test_command_budget_fires_in_guest_with_layer(
        self, channel: MessageChannel
    ) -> None:
        async def scenario() -> None:
            with pytest.raises(ChannelBudgetError) as failure:
                await channel.exec(
                    self.guest,
                    ExecRequest(
                        id=request_id(),
                        cmd=self.argv_sleep_ms(2000),
                        budget=Budget(command_ms=50),
                    ),
                )
            assert failure.value.layer == "command"

        self.run(scenario)

    def test_exec_liveness_polling_under_small_allowance(
        self, channel: MessageChannel
    ) -> None:
        """A long exec under a small channel allowance completes via liveness polls."""

        async def scenario() -> None:
            before = channel.stats.exchanges
            outcome = await channel.exec(
                self.guest,
                ExecRequest(
                    id=request_id(),
                    cmd=self.argv_sleep_ms(1200),
                    budget=Budget(command_ms=10_000, channel_ms=400),
                ),
            )
            assert outcome.rc == 0
            polled = channel.stats.exchanges - before
            assert polled >= 3, (
                f"expected at least one liveness poll plus result plus ack, saw {polled}"
            )

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
                await channel.ping(self.guest)
            elif operation == "exec":
                await channel.exec(
                    self.guest,
                    ExecRequest(
                        id=request_id(),
                        cmd=self.argv_cat_stdin(),
                        data_size=len(payload),
                    ),
                    stdin=payload,
                )
            elif operation == "write_file":
                await channel.write_file(self.guest, self.scratch_path, payload)
            elif operation == "read_file":
                await channel.write_file(self.guest, self.scratch_path, payload)
                before = channel.stats.exchanges
                await channel.read_file(self.guest, self.scratch_path)
            used = channel.stats.exchanges - before
            assert used <= RTT_BUDGET[operation], (
                f"{operation} used {used} round trips (budget {RTT_BUDGET[operation]})"
            )

        self.run(scenario)

    # -- host lifecycle plane ----------------------------------------------------

    def test_realize_streams_stages_to_ready(self, channel: MessageChannel) -> None:
        if not self.has_host_plane:
            pytest.skip("deployment provides no host-plane endpoint")

        async def scenario() -> None:
            stages = [report.stage async for report in channel.realize("ab" * 32, [])]
            assert stages == ["fetch", "construct", "boot", "verify", "ready"]

        self.run(scenario)

    def test_teardown_acknowledges(self, channel: MessageChannel) -> None:
        if not self.has_host_plane:
            pytest.skip("deployment provides no host-plane endpoint")

        async def scenario() -> None:
            await channel.teardown()

        self.run(scenario)

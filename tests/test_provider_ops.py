"""Slice-3 battery: the op surface's mapping details, per-call limits, and the wrapper path."""

import asyncio
from pathlib import Path

import pytest
from inspect_ai.util import OutputLimitExceededError, SandboxEnvironmentLimits
from inspect_ai.util._sandbox.environment import SandboxUnavailableError
from inspect_ai.util._sandbox.limits import (
    override_max_exec_output_size,
    override_max_read_file_size,
)
from inspect_ranges._channel.channel import (  # pyright: ignore[reportPrivateUsage]
    LoopbackTransport,
    MessageChannel,
    TamperError,
    _StoredReply,
)
from inspect_ranges._channel.mocks import HostileTransport
from inspect_ranges._channel.protocol import (
    ErrorReply,
    ExecRequest,
    Message,
    PingRequest,
    WriteFileRequest,
)
from inspect_ranges._compiler.plan import Totals
from inspect_ranges._provider.errors import SessionChangedError
from inspect_ranges._provider.ops import AGENT_HOME, resolve_guest_path
from inspect_ranges._provider.provider import LibvirtRangeSandboxEnvironment
from inspect_ranges._provider.retry import RetryConfig, RetryPolicy
from inspect_ranges._provider.state import SampleHandle

from tests.local_endpoint import LocalEndpoint

FAST_RETRY = RetryConfig(
    exec_policy=RetryPolicy(attempts=3, wait_initial_s=0.01, wait_max_s=0.02),
    file_policy=RetryPolicy(attempts=3, wait_initial_s=0.01, wait_max_s=0.02),
    up_attempts=1,
)


def make_env(
    root: Path,
) -> tuple[LibvirtRangeSandboxEnvironment, LoopbackTransport]:
    transport = LoopbackTransport(guests=())
    transport.guests["box"] = LocalEndpoint("box", root)
    channel = MessageChannel(transport, label="ops-test")
    handle = SampleHandle(
        project="ir-ops-test",
        task_name="ops",
        staging=root / "staging",
        totals=Totals(guests=1, cpus=1, memory_mb=1024),
        cid_base=10_000,
        guest_cids={"box": 10_000},
        channel=channel,
        retry=FAST_RETRY,
    )
    return LibvirtRangeSandboxEnvironment("box", handle), transport


def test_path_resolution() -> None:
    assert resolve_guest_path("notes.txt") == f"{AGENT_HOME}/notes.txt"
    assert resolve_guest_path("a/b.txt") == f"{AGENT_HOME}/a/b.txt"
    assert resolve_guest_path("/etc/hosts") == "/etc/hosts"


def test_file_not_found_names_the_callers_path(tmp_path: Path) -> None:
    async def scenario() -> None:
        env, _ = make_env(tmp_path)
        with pytest.raises(FileNotFoundError) as info:
            await env.read_file("nonexistent", text=True)
        assert "nonexistent" in str(info.value)

    asyncio.run(scenario())


def test_read_limit_is_read_per_call(tmp_path: Path) -> None:
    """`self_check` overrides the limit through a ContextVar; a cached value fails this."""

    async def scenario() -> None:
        env, _ = make_env(tmp_path)
        await env.write_file("big.bin", b"a" * 2048)
        with override_max_read_file_size(1024):
            expected = SandboxEnvironmentLimits.MAX_READ_FILE_SIZE_STR
            with pytest.raises(OutputLimitExceededError) as info:
                await env.read_file("big.bin", text=True)
            assert f"limit of {expected} was exceeded" in str(info.value)
        # outside the override the same file reads fine
        data = await env.read_file("big.bin", text=False)
        assert data == b"a" * 2048

    asyncio.run(scenario())


def test_exec_output_limit_is_read_per_call(tmp_path: Path) -> None:
    async def scenario() -> None:
        env, _ = make_env(tmp_path)
        with override_max_exec_output_size(64):
            with pytest.raises(OutputLimitExceededError):
                await env.exec(["sh", "-c", "printf 'x%.0s' $(seq 200)"])
        result = await env.exec(["echo", "fits"])
        assert result.stdout == "fits\n"

    asyncio.run(scenario())


def test_signal_death_maps_to_shell_convention(tmp_path: Path) -> None:
    async def scenario() -> None:
        env, _ = make_env(tmp_path)
        result = await env.exec(["sh", "-c", "kill -TERM $$"], timeout=30)
        assert result.returncode == 143

    asyncio.run(scenario())


def test_in_guest_timeout_maps_to_timeout_error(tmp_path: Path) -> None:
    async def scenario() -> None:
        env, _ = make_env(tmp_path)
        with pytest.raises(TimeoutError):
            await env.exec(["sleep", "5"], timeout=1)

    asyncio.run(scenario())


def test_strict_text_decode_propagates(tmp_path: Path) -> None:
    async def scenario() -> None:
        env, _ = make_env(tmp_path)
        await env.write_file("bad.bin", b"\xc3\x28")
        with pytest.raises(UnicodeDecodeError):
            await env.read_file("bad.bin", text=True)
        # exec output uses replacement characters instead
        result = await env.exec(["sh", "-c", "printf '\\303\\050'"])
        assert "�" in result.stdout

    asyncio.run(scenario())


def test_large_argv_rides_the_wrapper_script(tmp_path: Path) -> None:
    async def scenario() -> None:
        env, transport = make_env(tmp_path)
        chunk = "x" * (64 * 1024)
        args = [chunk] * 16  # ~1 MiB: over the control-frame budget
        result = await env.exec(["printf", "%s", *args])
        assert result.success
        assert result.stdout == chunk * 16
        endpoint = transport.guests["box"]
        assert endpoint.write_count == 1, "the wrapper script upload"
        # the script removes itself: the private tmp holds no leftovers
        from tests.local_endpoint import LocalEndpoint

        assert isinstance(endpoint, LocalEndpoint)
        leftovers = list((endpoint.root / "tmp").glob(".ir-exec-*"))
        assert leftovers == [], f"wrapper scripts leaked: {leftovers}"

    asyncio.run(scenario())


def test_escape_heavy_argv_and_large_env_ride_the_wrapper(tmp_path: Path) -> None:
    """The wrapper decision measures the ENCODED payload: escape-heavy argv and a large env inflate the canonical JSON past the frame cap even when raw bytes look small."""

    async def scenario() -> None:
        env, transport = make_env(tmp_path)
        quotes = '"' * 20_000  # ~20 KB raw, ~40 KB JSON-escaped
        result = await env.exec(["printf", "%s", quotes])
        assert result.success and result.stdout == quotes
        big_env = {"BLOB": "y" * 40_000}
        result = await env.exec(["sh", "-c", 'printf %s "$BLOB"'], env=big_env)
        assert result.success and result.stdout == big_env["BLOB"]
        endpoint = transport.guests["box"]
        assert endpoint.write_count == 2, "both oversized requests used the wrapper"

    asyncio.run(scenario())


def test_estale_retry_reruns_a_fresh_wrapper(tmp_path: Path) -> None:
    """The blocking shape from the chunk-1 verification: the first wrapper exec runs for real but its reply is replaced by ESTALE (executed, result lost); the fresh-id retry must re-upload the wrapper and return the RE-RUN's honest outcome, never exec a self-deleted file and fabricate a missing-file failure."""

    class EstaleOnce(LocalEndpoint):
        def __init__(self, name: str, root: Path) -> None:
            super().__init__(name, root)
            self.estale_fired = False

        async def handle(self, message: Message, bulk: bytes | None) -> _StoredReply:
            reply = await super().handle(message, bulk)
            if (
                isinstance(message, ExecRequest)
                and message.cmd[0] == "sh"
                and not self.estale_fired
            ):
                self.estale_fired = True
                return _StoredReply(
                    ErrorReply(
                        id=message.id,
                        errno="ESTALE",
                        message="executed, result lost before acknowledgement",
                    ),
                    None,
                )
            return reply

    async def scenario() -> None:
        transport = LoopbackTransport(guests=())
        endpoint = EstaleOnce("box", tmp_path)
        transport.guests["box"] = endpoint
        channel = MessageChannel(transport, label="estale-wrapper")
        handle = SampleHandle(
            project="ir-estale",
            task_name="ops",
            staging=tmp_path / "staging",
            totals=Totals(guests=1, cpus=1, memory_mb=256),
            cid_base=10_000,
            guest_cids={"box": 10_000},
            channel=channel,
            retry=FAST_RETRY,
        )
        env = LibvirtRangeSandboxEnvironment("box", handle)
        chunk = "w" * 40_000  # forces the wrapper path
        result = await env.exec(["printf", "%s", chunk])
        assert result.success, f"fabricated failure leaked: {result.stderr!r}"
        assert result.stdout == chunk, "the retry must return the re-run's real output"
        assert endpoint.write_count == 2, "each attempt uploads a fresh wrapper"
        # the double-run is the accepted ESTALE policy, visible and honest
        assert endpoint.estale_fired

    asyncio.run(scenario())


def test_assignment_shaped_command_is_not_a_shell_assignment(tmp_path: Path) -> None:
    """A NAME=value cmd[0] through the wrapper stays a command (127), never a variable assignment."""

    async def scenario() -> None:
        env, _ = make_env(tmp_path)
        filler = "z" * 40_000  # force the wrapper path
        result = await env.exec(["FOO=bar", filler])
        assert not result.success
        assert result.returncode == 127

    asyncio.run(scenario())


def test_unavailable_after_retries_against_a_dead_endpoint(tmp_path: Path) -> None:
    async def scenario() -> None:
        env, transport = make_env(tmp_path)
        transport.guests = {}  # the guest is gone: transport failures all the way down
        with pytest.raises(SandboxUnavailableError):
            await env.exec(["echo", "hi"])
        with pytest.raises(SandboxUnavailableError):
            await env.read_file("x", text=False)
        with pytest.raises(SandboxUnavailableError):
            await env.write_file("x", b"data")

    asyncio.run(scenario())


def test_tamper_is_never_unavailable(tmp_path: Path) -> None:
    """A tampering guest fails the sample hard; it must never read as 'temporarily unavailable'."""

    async def scenario() -> None:
        hostile = HostileTransport("wrong-kind")
        channel = MessageChannel(hostile, label="hostile-ops")
        handle = SampleHandle(
            project="ir-hostile",
            task_name="ops",
            staging=tmp_path,
            totals=Totals(guests=1, cpus=1, memory_mb=256),
            cid_base=10_000,
            guest_cids={"web": 10_000},
            channel=channel,
            retry=FAST_RETRY,
        )
        env = LibvirtRangeSandboxEnvironment("web", handle)
        with pytest.raises(TamperError):
            await env.exec(["echo", "hi"])

    asyncio.run(scenario())


def test_daemon_stream_truncation_raises_output_limit(tmp_path: Path) -> None:
    """A stream the endpoint itself truncated (its 16 MiB cap) surfaces as a constructed OutputLimitExceededError, never silently truncated output."""

    async def scenario() -> None:
        env, _ = make_env(tmp_path)
        with pytest.raises(OutputLimitExceededError) as info:
            # one byte past the endpoint's per-stream cap; the per-call limit
            # (default 10 MiB) is irrelevant because the truncation check runs
            # first and names the endpoint cap
            await env.exec(["sh", "-c", "head -c 16777217 /dev/zero"])
        assert "limit of 16 MiB was exceeded" in str(info.value)

    asyncio.run(scenario())


def test_session_pin_detects_daemon_restart_across_resend(tmp_path: Path) -> None:
    """Layer 2b: an exec whose delivery needed a same-id resend across a daemon restart surfaces `SessionChangedError` (the restart emptied the dedupe store, so exactly-once no longer holds); the re-pin lets the next op proceed."""

    class RestartAcrossDelivery(LocalEndpoint):
        """Loses the first exec reply in flight and restarts before the resend arrives."""

        def __init__(self, name: str, root: Path) -> None:
            super().__init__(name, root)
            self.interrupted = False

        async def handle(self, message: Message, bulk: bytes | None) -> _StoredReply:
            reply = await super().handle(message, bulk)
            if isinstance(message, ExecRequest) and not self.interrupted:
                self.interrupted = True
                self.drop_next_reply = True  # the reply is lost in flight...
                self.restart()  # ...and the daemon restarts before the resend
            return reply

    async def scenario() -> None:
        transport = LoopbackTransport(guests=())
        endpoint = RestartAcrossDelivery("box", tmp_path)
        transport.guests["box"] = endpoint
        channel = MessageChannel(transport, label="session-restart")
        handle = SampleHandle(
            project="ir-session",
            task_name="ops",
            staging=tmp_path / "staging",
            totals=Totals(guests=1, cpus=1, memory_mb=256),
            cid_base=10_000,
            guest_cids={"box": 10_000},
            channel=channel,
            retry=FAST_RETRY,
        )
        pinned = endpoint.session  # what sample_init pins at boot
        handle.sessions["box"] = pinned
        env = LibvirtRangeSandboxEnvironment("box", handle)
        with pytest.raises(SessionChangedError) as info:
            await env.exec(["echo", "hi"])
        assert info.value.pinned == pinned
        assert info.value.observed == endpoint.session
        assert handle.sessions["box"] == endpoint.session, "re-pinned"
        fresh = await env.exec(["echo", "again"])
        assert fresh.success and fresh.stdout == "again\n"

    asyncio.run(scenario())


def test_session_stable_across_connections(tmp_path: Path) -> None:
    """Every connection sees the same session until the endpoint restarts."""

    async def scenario() -> None:
        transport = LoopbackTransport(guests=())
        endpoint = LocalEndpoint("box", tmp_path)
        transport.guests["box"] = endpoint
        channel = MessageChannel(transport, label="session-stable")
        first = await channel.session("box")
        assert first == await channel.session("box")
        endpoint.restart()
        assert await channel.session("box") != first

    asyncio.run(scenario())


def test_wrapper_upload_travels_with_mode_600(tmp_path: Path) -> None:
    """The env-bearing wrapper script is written with mode 0600 atomically (no chmod round trip, no world-readable window)."""

    async def scenario() -> None:
        env, transport = make_env(tmp_path)
        chunk = "w" * 40_000  # forces the wrapper path
        result = await env.exec(["printf", "%s", chunk])
        assert result.success and result.stdout == chunk
        endpoint = transport.guests["box"]
        wrapper_modes = [
            mode for path, mode in endpoint.file_modes.items() if "/.ir-exec-" in path
        ]
        assert wrapper_modes == [0o600]

    asyncio.run(scenario())


def test_command_timeout_carries_partial_output(tmp_path: Path) -> None:
    """The daemon's ETIME `partial` tail surfaces as `CommandTimeout.truncated_output` (closing the chunk-1 deviation: the field is no longer always `None`)."""

    async def scenario() -> None:
        env, _ = make_env(tmp_path)
        with pytest.raises(TimeoutError) as info:
            await env.exec(["sh", "-c", "echo marker; sleep 30"], timeout=1)
        truncated = getattr(info.value, "truncated_output", None)
        assert truncated is not None and "marker" in truncated

    asyncio.run(scenario())


def test_env_touching_runuser_reset_keys_rides_the_wrapper(tmp_path: Path) -> None:
    """HOME/SHELL/USER/LOGNAME/PATH are always reset by the daemon's runuser switch, so env naming them must ride the wrapper (whose exports run after the switch) even when the request would fit a control frame."""

    async def scenario() -> None:
        env, transport = make_env(tmp_path)
        result = await env.exec(["sh", "-c", "echo $HOME"], env={"HOME": "/elsewhere"})
        assert result.success and result.stdout == "/elsewhere\n"
        endpoint = transport.guests["box"]
        assert endpoint.write_count == 1, "the wrapper upload"
        plain = await env.exec(["sh", "-c", "echo $ANSWER"], env={"ANSWER": "42"})
        assert plain.success and plain.stdout == "42\n"
        assert endpoint.write_count == 1, "non-reset keys stay on the direct path"

    asyncio.run(scenario())


def test_wrapper_for_third_user_stays_0600_and_is_chowned(tmp_path: Path) -> None:
    """The env-bearing wrapper is ALWAYS 0600 and agent-owned at creation; an explicit third user gets ownership via one root chown (never a mode widening, which would both leak the env world-readable and break the sticky-/tmp self-delete)."""

    async def scenario() -> None:
        env, transport = make_env(tmp_path)
        endpoint = transport.guests["box"]
        assert isinstance(endpoint, LocalEndpoint)
        await env.exec(["sh", "-c", "echo $HOME"], env={"HOME": "/x"})
        result = await env.exec(
            ["sh", "-c", "echo $HOME"], env={"HOME": "/x"}, user="somebody-else"
        )
        assert not result.success, "the CI endpoint cannot switch users"
        wrappers = [path for path in endpoint.file_modes if "/.ir-exec-" in path]
        assert [endpoint.file_modes[path] for path in wrappers] == [0o600, 0o600]
        owners = [endpoint.file_owners[path] for path in wrappers]
        assert owners == ["agent", "somebody-else"], (
            "the default run stays agent-owned; the third-user run is chowned"
        )

    asyncio.run(scenario())


def test_resent_exec_that_times_out_still_confirms_the_session(
    tmp_path: Path,
) -> None:
    """A resent delivery that lands as a command-layer budget expiry is exactly as restart-risky as a resent success: the session verdict outranks the timeout verdict."""

    class RestartAcrossDelivery(LocalEndpoint):
        def __init__(self, name: str, root: Path) -> None:
            super().__init__(name, root)
            self.interrupted = False

        async def handle(self, message: Message, bulk: bytes | None) -> _StoredReply:
            reply = await super().handle(message, bulk)
            if isinstance(message, ExecRequest) and not self.interrupted:
                self.interrupted = True
                self.drop_next_reply = True
                self.restart()
            return reply

    async def scenario() -> None:
        transport = LoopbackTransport(guests=())
        endpoint = RestartAcrossDelivery("box", tmp_path)
        transport.guests["box"] = endpoint
        channel = MessageChannel(transport, label="session-etime")
        handle = SampleHandle(
            project="ir-session-etime",
            task_name="ops",
            staging=tmp_path / "staging",
            totals=Totals(guests=1, cpus=1, memory_mb=256),
            cid_base=10_000,
            guest_cids={"box": 10_000},
            channel=channel,
            retry=FAST_RETRY,
        )
        handle.sessions["box"] = endpoint.session
        env = LibvirtRangeSandboxEnvironment("box", handle)
        with pytest.raises(SessionChangedError):
            await env.exec(["sh", "-c", "sleep 30"], timeout=1)

    asyncio.run(scenario())


def test_write_mode_pins_bits_before_content(tmp_path: Path) -> None:
    """Rewriting a pre-existing wider-mode file with mode 0600 ends 0600 with the fresh content: the endpoint mirrors the daemon's fchmod-then-truncate ordering, so the old bits never cover the new bytes."""

    async def scenario() -> None:
        env, transport = make_env(tmp_path)
        endpoint = transport.guests["box"]
        assert isinstance(endpoint, LocalEndpoint)
        target = endpoint.translate("/tmp/rewritten")
        target.write_bytes(b"old public content")
        target.chmod(0o644)
        channel = env._handle.channel  # pyright: ignore[reportPrivateUsage]
        assert channel is not None
        await channel.write_file("box", "/tmp/rewritten", b"secret", mode=0o600)
        assert (target.stat().st_mode & 0o777) == 0o600
        assert target.read_bytes() == b"secret"

    asyncio.run(scenario())


def test_fresh_id_retry_across_restart_confirms_even_on_errno_failure(
    tmp_path: Path,
) -> None:
    """A fresh-id retry attempt (layer 2) whose re-attempt lands as an errno GuestError still confirms the session: the FIRST attempt executed before the restart, so a double-run cannot be ruled out whatever the final outcome shape."""

    class EstaleThenRestart(LocalEndpoint):
        """First exec answers ESTALE (a delivered-then-evicted truth) and the daemon restarts before the fresh-id retry arrives."""

        def __init__(self, name: str, root: Path) -> None:
            super().__init__(name, root)
            self.tripped = False

        async def handle(self, message: Message, bulk: bytes | None) -> _StoredReply:
            if isinstance(message, ExecRequest) and not self.tripped:
                self.tripped = True
                reply = _StoredReply(
                    ErrorReply(
                        id=message.id,
                        errno="ESTALE",
                        message="executed, result lost before acknowledgement",
                    ),
                    None,
                )
                self.restart()
                return reply
            return await super().handle(message, bulk)

    async def scenario() -> None:
        transport = LoopbackTransport(guests=())
        endpoint = EstaleThenRestart("box", tmp_path)
        transport.guests["box"] = endpoint
        channel = MessageChannel(transport, label="estale-errno")
        handle = SampleHandle(
            project="ir-estale-errno",
            task_name="ops",
            staging=tmp_path / "staging",
            totals=Totals(guests=1, cpus=1, memory_mb=256),
            cid_base=10_000,
            guest_cids={"box": 10_000},
            channel=channel,
            retry=FAST_RETRY,
        )
        handle.sessions["box"] = endpoint.session
        env = LibvirtRangeSandboxEnvironment("box", handle)
        with pytest.raises(SessionChangedError):
            # the retry's second attempt fails ENOENT (missing cwd), an errno
            # shape that previously skipped the confirm entirely
            await env.exec(["true"], cwd="/no/such/dir")

    asyncio.run(scenario())


def test_resent_write_across_restart_confirms_the_session(tmp_path: Path) -> None:
    """write_file's re-delivery arms share the exec policy: a same-id resend across a daemon restart surfaces `SessionChangedError`, never a silent possibly-double write."""

    class RestartAcrossWrite(LocalEndpoint):
        def __init__(self, name: str, root: Path) -> None:
            super().__init__(name, root)
            self.interrupted = False

        async def handle(self, message: Message, bulk: bytes | None) -> _StoredReply:
            reply = await super().handle(message, bulk)
            if isinstance(message, WriteFileRequest) and not self.interrupted:
                self.interrupted = True
                self.drop_next_reply = True
                self.restart()
            return reply

    async def scenario() -> None:
        transport = LoopbackTransport(guests=())
        endpoint = RestartAcrossWrite("box", tmp_path)
        transport.guests["box"] = endpoint
        channel = MessageChannel(transport, label="write-restart")
        handle = SampleHandle(
            project="ir-write-restart",
            task_name="ops",
            staging=tmp_path / "staging",
            totals=Totals(guests=1, cpus=1, memory_mb=256),
            cid_base=10_000,
            guest_cids={"box": 10_000},
            channel=channel,
            retry=FAST_RETRY,
        )
        handle.sessions["box"] = endpoint.session
        env = LibvirtRangeSandboxEnvironment("box", handle)
        with pytest.raises(SessionChangedError):
            await env.write_file("note.txt", "contents")
        fresh = await env.exec(["echo", "ok"])
        assert fresh.success, "the re-pin lets the sample continue"

    asyncio.run(scenario())


def test_uncertifiable_success_downgrades_to_unavailable(tmp_path: Path) -> None:
    """A resent success whose confirm ping finds the daemon transport-dead is unavailable-shaped: the result is in hand but exactly-once cannot be certified, and silence would be a lie."""

    class RestartThenDeafToPings(LocalEndpoint):
        def __init__(self, name: str, root: Path) -> None:
            super().__init__(name, root)
            self.interrupted = False

        async def handle(self, message: Message, bulk: bytes | None) -> _StoredReply:
            if isinstance(message, PingRequest) and self.interrupted:
                self.drop_next_reply = True  # every confirm ping dies in flight
            reply = await super().handle(message, bulk)
            if isinstance(message, ExecRequest) and not self.interrupted:
                self.interrupted = True
                self.drop_next_reply = True
                self.restart()
            return reply

    async def scenario() -> None:
        transport = LoopbackTransport(guests=())
        endpoint = RestartThenDeafToPings("box", tmp_path)
        transport.guests["box"] = endpoint
        channel = MessageChannel(transport, label="deaf-pings")
        handle = SampleHandle(
            project="ir-deaf-pings",
            task_name="ops",
            staging=tmp_path / "staging",
            totals=Totals(guests=1, cpus=1, memory_mb=256),
            cid_base=10_000,
            guest_cids={"box": 10_000},
            channel=channel,
            retry=FAST_RETRY,
        )
        handle.sessions["box"] = endpoint.session
        env = LibvirtRangeSandboxEnvironment("box", handle)
        with pytest.raises(SandboxUnavailableError):
            await env.exec(["echo", "hi"])

    asyncio.run(scenario())

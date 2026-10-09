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
from inspect_ranges._channel.channel import (
    LoopbackTransport,
    MessageChannel,
    TamperError,
)
from inspect_ranges._channel.mocks import HostileTransport
from inspect_ranges._compiler.plan import Totals
from inspect_ranges._provider.ops import (
    AGENT_HOME,
    ARGV_WRAPPER_THRESHOLD,
    resolve_guest_path,
)
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
        assert sum(len(a) for a in args) > ARGV_WRAPPER_THRESHOLD
        result = await env.exec(["printf", "%s", *args])
        assert result.success
        assert result.stdout == chunk * 16
        endpoint = transport.guests["box"]
        assert endpoint.write_count == 1, "the wrapper script upload"

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

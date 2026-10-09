"""Slice-1 battery: the layer-2 retry engine (classification, bounds, telemetry)."""

import asyncio
import logging
import time

import pytest
from inspect_ai.util import OutputLimitExceededError
from inspect_ranges._channel.channel import (
    ChannelBudgetError,
    FileLimitExceeded,
    GuestError,
    LoopbackTransport,
    MessageChannel,
    TamperError,
    TransportFailure,
)
from inspect_ranges._provider.errors import SessionChangedError
from inspect_ranges._provider.retry import (
    FailureClass,
    RetryConfig,
    RetryPolicy,
    RetryStats,
    classify,
    with_retry,
)

FAST = RetryPolicy(attempts=3, wait_initial_s=0.01, wait_max_s=0.02)


def _case_id(value: object) -> str:
    return type(value).__name__


@pytest.mark.parametrize(
    ("error", "expected"),
    [
        # deny-list: permanent, never retried
        (TamperError("forged reply"), FailureClass.PERMANENT),
        (SessionChangedError("web", "exec", "a1", "b2"), FailureClass.PERMANENT),
        (
            ChannelBudgetError("command", "command budget expired"),
            FailureClass.PERMANENT,
        ),
        (GuestError("EACCES", "permission denied"), FailureClass.PERMANENT),
        (GuestError("ENOENT", "no such file"), FailureClass.PERMANENT),
        (GuestError("EWHATEVER", "unknown errno"), FailureClass.PERMANENT),
        (FileLimitExceeded("/f", b"x"), FailureClass.PERMANENT),
        (UnicodeDecodeError("utf-8", b"\xc3", 0, 1, "bad"), FailureClass.PERMANENT),
        (OutputLimitExceededError("10 MiB", None), FailureClass.PERMANENT),
        (ValueError("stdin mismatch"), FailureClass.PERMANENT),
        # OSError subclasses that MUST stay permanent despite the OSError allow-list
        (TimeoutError("deadline"), FailureClass.PERMANENT),
        (PermissionError("denied"), FailureClass.PERMANENT),
        (FileNotFoundError("missing"), FailureClass.PERMANENT),
        (IsADirectoryError("dir"), FailureClass.PERMANENT),
        (NotADirectoryError("notdir"), FailureClass.PERMANENT),
        # allow-list: transient infrastructure failures
        (TransportFailure("reply lost after 3 attempts"), FailureClass.TRANSIENT),
        (TransportFailure("executed, result lost (ESTALE)"), FailureClass.TRANSIENT),
        (
            ChannelBudgetError("channel", "no reply in allowance"),
            FailureClass.TRANSIENT,
        ),
        (ChannelBudgetError("untimed", "total bound expired"), FailureClass.TRANSIENT),
        (ChannelBudgetError("transport", "transport bound"), FailureClass.TRANSIENT),
        (ConnectionError("reset"), FailureClass.TRANSIENT),
        (OSError("vsock gone"), FailureClass.TRANSIENT),
        # unknown defaults to permanent
        (RuntimeError("mystery"), FailureClass.PERMANENT),
        (KeyError("mystery"), FailureClass.PERMANENT),
    ],
    ids=_case_id,
)
def test_classification_table(error: BaseException, expected: FailureClass) -> None:
    assert classify(error) is expected


def test_transient_retries_then_succeeds() -> None:
    async def scenario() -> None:
        stats = RetryStats()
        calls = 0

        async def flaky() -> str:
            nonlocal calls
            calls += 1
            if calls < 3:
                raise TransportFailure("reply lost")
            return "ok"

        result = await with_retry(
            flaky, policy=FAST, stats=stats, op="exec", endpoint="web"
        )
        assert result == "ok"
        assert calls == 3
        assert stats.counters("exec").retries == 2
        assert "reply lost" in stats.counters("exec").last_cause

    asyncio.run(scenario())


def test_permanent_raises_immediately() -> None:
    async def scenario() -> None:
        stats = RetryStats()
        calls = 0

        async def denied() -> None:
            nonlocal calls
            calls += 1
            raise GuestError("EACCES", "permission denied")

        with pytest.raises(GuestError):
            await with_retry(denied, policy=FAST, stats=stats, op="read_file")
        assert calls == 1
        assert stats.counters("read_file").retries == 0

    asyncio.run(scenario())


def test_exhaustion_reraises_the_underlying_error() -> None:
    async def scenario() -> None:
        async def always_lost() -> None:
            raise TransportFailure("reply lost forever")

        with pytest.raises(TransportFailure, match="reply lost forever"):
            await with_retry(always_lost, policy=FAST, stats=RetryStats(), op="exec")

    asyncio.run(scenario())


def test_shared_deadline_bounds_wall_time() -> None:
    async def scenario() -> None:
        policy = RetryPolicy(
            attempts=50, wait_initial_s=0.05, wait_max_s=0.05, deadline_s=0.2
        )

        async def always_lost() -> None:
            raise TransportFailure("lost")

        start = time.monotonic()
        with pytest.raises(TransportFailure):
            await with_retry(always_lost, policy=policy, stats=RetryStats(), op="exec")
        elapsed = time.monotonic() - start
        assert elapsed < 1.0, f"shared deadline did not bound retries: {elapsed:.2f}s"

        # the deadline is a hard wall: an in-flight straggler attempt is
        # truncated, surfacing as TransportFailure (its cause), never a bare
        # TimeoutError that would read as a command timeout
        async def slow_transient() -> None:
            await asyncio.sleep(5.0)
            raise TransportFailure("slow loss")

        hard = RetryPolicy(
            attempts=50, wait_initial_s=0.01, wait_max_s=0.01, deadline_s=0.3
        )
        start = time.monotonic()
        with pytest.raises(TransportFailure, match="retry deadline"):
            await with_retry(slow_transient, policy=hard, stats=RetryStats(), op="exec")
        elapsed = time.monotonic() - start
        assert elapsed < 2.0, (
            f"deadline did not truncate in-flight work: {elapsed:.2f}s"
        )

    asyncio.run(scenario())


def test_with_deadline_builds_a_bounded_policy() -> None:
    async def scenario() -> None:
        bounded = FAST.with_deadline(0.5)
        assert bounded.deadline_s == 0.5
        assert bounded.attempts == FAST.attempts
        assert FAST.deadline_s is None  # the original is unchanged

    asyncio.run(scenario())


def test_retry_telemetry_line(caplog: pytest.LogCaptureFixture) -> None:
    async def scenario() -> None:
        stats = RetryStats()
        calls = 0

        async def flaky() -> None:
            nonlocal calls
            calls += 1
            if calls == 1:
                raise ConnectionError("x" * 2000)

        with caplog.at_level(logging.WARNING, logger="inspect_ranges.provider.retry"):
            await with_retry(
                flaky, policy=FAST, stats=stats, op="write_file", endpoint="db"
            )
        records = [r for r in caplog.records if "retry" in r.message]
        assert len(records) == 1
        message = records[0].getMessage()
        assert (
            "op=write_file" in message
            and "endpoint=db" in message
            and "attempt=1" in message
        )
        # guest-influenced cause strings are capped in telemetry
        assert len(stats.counters("write_file").last_cause) <= 256

    asyncio.run(scenario())


def test_config_defaults_and_disable(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in (
        "INSPECT_RANGES_RETRY_EXEC_ATTEMPTS",
        "INSPECT_RANGES_RETRY_FILE_ATTEMPTS",
        "INSPECT_RANGES_RETRY_WAIT_INITIAL_S",
        "INSPECT_RANGES_RETRY_WAIT_MAX_S",
        "INSPECT_RANGES_RETRY_UP_ATTEMPTS",
        "INSPECT_RANGES_RETRY_DISABLE",
    ):
        monkeypatch.delenv(name, raising=False)
    config = RetryConfig.from_env()
    assert config.exec_policy.attempts == 3
    assert config.file_policy.attempts == 5
    assert config.up_attempts == 2
    monkeypatch.setenv("INSPECT_RANGES_RETRY_EXEC_ATTEMPTS", "7")
    monkeypatch.setenv("INSPECT_RANGES_RETRY_WAIT_INITIAL_S", "0.5")
    config = RetryConfig.from_env()
    assert config.exec_policy.attempts == 7
    assert config.exec_policy.wait_initial_s == 0.5
    monkeypatch.setenv("INSPECT_RANGES_RETRY_DISABLE", "1")
    config = RetryConfig.from_env()
    assert config.exec_policy.attempts == 1
    assert config.file_policy.attempts == 1
    assert config.up_attempts == 1


def test_config_rejects_bad_values(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("INSPECT_RANGES_RETRY_DISABLE", raising=False)
    monkeypatch.setenv("INSPECT_RANGES_RETRY_EXEC_ATTEMPTS", "zero")
    with pytest.raises(ValueError, match="EXEC_ATTEMPTS"):
        RetryConfig.from_env()
    monkeypatch.setenv("INSPECT_RANGES_RETRY_EXEC_ATTEMPTS", "0")
    with pytest.raises(ValueError, match="EXEC_ATTEMPTS"):
        RetryConfig.from_env()


def test_layer2_recovers_a_layer1_exhaustion() -> None:
    async def scenario() -> None:
        """End to end against the real channel: layer 1 exhausts (endpoint missing), layer 2 retries with a fresh id and the restored endpoint succeeds."""
        from inspect_ranges._channel.channel import request_id
        from inspect_ranges._channel.protocol import ExecRequest

        transport = LoopbackTransport(guests=("web",))
        channel = MessageChannel(transport, channel_budget_s=1.0)
        broken = dict(transport.guests)
        transport.guests = {}  # the guest is unreachable: layer 1 exhausts into TransportFailure
        stats = RetryStats()
        attempts = 0

        async def run_echo() -> str:
            nonlocal attempts
            attempts += 1
            if attempts == 2:
                transport.guests = broken  # infra recovers between layer-2 attempts
            outcome = await channel.exec(
                "web", ExecRequest(id=request_id(), cmd=["echo", "hi"])
            )
            return outcome.stdout.decode()

        result = await with_retry(
            run_echo, policy=FAST, stats=stats, op="exec", endpoint="web"
        )
        assert result == "hi\n"
        assert stats.counters("exec").retries == 1
        assert transport.guests["web"].exec_count == 1  # the effect ran exactly once

    asyncio.run(scenario())

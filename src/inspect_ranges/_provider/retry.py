"""Layer-2 retry: bounded fresh-id retries around whole sandbox operations.

The channel below already recovers lost replies by resending the SAME request id with endpoint dedupe (layer 1, exactly-once within one daemon lifetime), so by the time a failure reaches this layer the completion oracle has reduced it to "provably never delivered" or "executed, result lost". Retrying here mints a fresh request id, which is where the idempotency assumption enters. Per the settled policy (provider-v1.md), losing an entire sample when a retry would have recovered it is worse than the double-execution risk, so operations retry by default. The inspect_k8s_sandbox caveat applies verbatim: "Note that retries cannot guarantee idempotency - if a command partially executed before the error, it may run again on retry." (UKGovernmentBEIS/inspect_k8s_sandbox, docs/docs/design/limitations.md; the source punctuates with an em dash, rendered here per house style).

Classification: the deny-list outranks the allow-list, and unknown failures default to PERMANENT. The ordering matters because Python's exception hierarchy makes broad allow-lists dangerous: `TimeoutError`, `PermissionError`, `FileNotFoundError`, and friends are `OSError` subclasses, so a bare "retry OSError" rule would retry permanent failures forever (the inspect_k8s_sandbox lesson).

Retries are telemetry, never silent: every retry logs one structured line (op, endpoint, attempt, cause, sleep) joinable with the channel's request-id logs, and increments per-op counters surfaced in the debug bundle. Teardown and cleanup paths never pass through this module.
"""

import asyncio
import dataclasses
import enum
import logging
import math
import os
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field

from tenacity import (
    AsyncRetrying,
    RetryCallState,
    retry_if_exception,
    stop_after_attempt,
    stop_after_delay,
    wait_exponential_jitter,
)
from tenacity.stop import stop_base

from .._channel.channel import (
    ChannelBudgetError,
    FileLimitExceeded,
    GuestError,
    TamperError,
    TransportFailure,
)
from .errors import SessionChangedError

logger = logging.getLogger("inspect_ranges.provider.retry")

_CAUSE_CAP = 256
"""Telemetry cap on failure-cause strings (guest-influenced bytes never flood the log)."""


class FailureClass(enum.Enum):
    """Whether a failure is worth a fresh-id retry."""

    TRANSIENT = "transient"
    PERMANENT = "permanent"


_PERMANENT_TYPES: tuple[type[BaseException], ...] = (
    SessionChangedError,
    TimeoutError,
    PermissionError,
    FileNotFoundError,
    IsADirectoryError,
    NotADirectoryError,
    ValueError,  # covers UnicodeDecodeError (a ValueError subclass) and stdin-mismatch refusals
    # defense-in-depth: these already match no transient type today, but a
    # hypothetical future subclass mixing in OSError must still classify
    # permanent (the deny-list outranks the allow-list by construction)
    TamperError,
    GuestError,
    FileLimitExceeded,
)
"""Deny-list, checked before the transient allow-list. `TimeoutError` and the file errors are `OSError` subclasses and MUST stay here or the `OSError` allow-list entry would silently retry them. `TamperError`, `GuestError`, `FileLimitExceeded`, and `OutputLimitExceededError` are permanent through the default (they match no transient type)."""

_TRANSIENT_TYPES: tuple[type[BaseException], ...] = (
    TransportFailure,
    ConnectionError,
    OSError,
)
"""Allow-list: infrastructure failures below the operation's own semantics. `TransportFailure` includes the ESTALE executed-but-result-lost case, retried per the settled lesser-of-two-evils policy."""


def classify(error: BaseException) -> FailureClass:
    """Classify one failure; the deny-list outranks the allow-list and unknown defaults to PERMANENT.

    `ChannelBudgetError` is layer-dependent: the command layer is a real in-guest timeout (permanent); the channel, untimed, and transport layers are infrastructure bounds (transient).
    """
    if isinstance(error, ChannelBudgetError):
        return (
            FailureClass.PERMANENT
            if error.layer == "command"
            else FailureClass.TRANSIENT
        )
    if isinstance(error, _PERMANENT_TYPES):
        return FailureClass.PERMANENT
    if isinstance(error, _TRANSIENT_TYPES):
        return FailureClass.TRANSIENT
    return FailureClass.PERMANENT


@dataclass(frozen=True)
class RetryPolicy:
    """Bounds for one operation kind's retries.

    `deadline_s` is ONE shared deadline across every attempt and backoff sleep, so retries never exceed what the caller asked for; `None` bounds by attempts alone.
    """

    attempts: int
    wait_initial_s: float = 1.0
    wait_max_s: float = 10.0
    deadline_s: float | None = None

    def with_deadline(self, deadline_s: float | None) -> "RetryPolicy":
        """This policy with a per-call shared deadline."""
        return dataclasses.replace(self, deadline_s=deadline_s)


@dataclass
class OpCounters:
    """Retry accounting for one operation kind."""

    calls: int = 0
    retries: int = 0
    last_cause: str = ""


@dataclass
class RetryStats:
    """Per-op retry counters; surfaced in the debug bundle, asserted by batteries."""

    ops: dict[str, OpCounters] = field(default_factory=dict[str, OpCounters])

    def counters(self, op: str) -> OpCounters:
        """The (created-on-first-use) counters for one operation kind."""
        return self.ops.setdefault(op, OpCounters())

    def snapshot(self) -> dict[str, dict[str, int | str]]:
        """A JSON-shaped view for logs and the debug bundle."""
        return {
            op: {
                "calls": counters.calls,
                "retries": counters.retries,
                "last_cause": counters.last_cause,
            }
            for op, counters in sorted(self.ops.items())
        }


def _env_int(name: str, default: int) -> int:
    value = os.environ.get(name)
    if value is None:
        return default
    try:
        parsed = int(value)
    except ValueError as error:
        raise ValueError(f"{name} must be an integer, got {value!r}") from error
    if parsed < 1:
        raise ValueError(f"{name} must be >= 1, got {parsed}")
    return parsed


def _env_float(name: str, default: float) -> float:
    value = os.environ.get(name)
    if value is None:
        return default
    try:
        parsed = float(value)
    except ValueError as error:
        raise ValueError(f"{name} must be a number, got {value!r}") from error
    if not math.isfinite(parsed) or parsed <= 0:
        raise ValueError(f"{name} must be a positive finite number, got {parsed}")
    return parsed


@dataclass(frozen=True)
class RetryConfig:
    """The provider's retry knobs, read from the environment at provider construction (never at import).

    Env vars: `INSPECT_RANGES_RETRY_EXEC_ATTEMPTS` (3), `INSPECT_RANGES_RETRY_FILE_ATTEMPTS` (5), `INSPECT_RANGES_RETRY_WAIT_INITIAL_S` (1), `INSPECT_RANGES_RETRY_WAIT_MAX_S` (10), `INSPECT_RANGES_RETRY_UP_ATTEMPTS` (2), and `INSPECT_RANGES_RETRY_DISABLE` (any non-empty value collapses every layer to a single attempt).
    """

    exec_policy: RetryPolicy
    file_policy: RetryPolicy
    up_attempts: int

    @classmethod
    def from_env(cls) -> "RetryConfig":
        """Read the knobs; prior-art consensus defaults (3 exec, 5 file, jittered 1..10s backoff)."""
        if os.environ.get("INSPECT_RANGES_RETRY_DISABLE"):
            single = RetryPolicy(attempts=1)
            return cls(exec_policy=single, file_policy=single, up_attempts=1)
        wait_initial = _env_float("INSPECT_RANGES_RETRY_WAIT_INITIAL_S", 1.0)
        wait_max = _env_float("INSPECT_RANGES_RETRY_WAIT_MAX_S", 10.0)
        return cls(
            exec_policy=RetryPolicy(
                attempts=_env_int("INSPECT_RANGES_RETRY_EXEC_ATTEMPTS", 3),
                wait_initial_s=wait_initial,
                wait_max_s=wait_max,
            ),
            file_policy=RetryPolicy(
                attempts=_env_int("INSPECT_RANGES_RETRY_FILE_ATTEMPTS", 5),
                wait_initial_s=wait_initial,
                wait_max_s=wait_max,
            ),
            up_attempts=_env_int("INSPECT_RANGES_RETRY_UP_ATTEMPTS", 2),
        )


def _is_transient(error: BaseException) -> bool:
    return classify(error) is FailureClass.TRANSIENT


async def with_retry[T](
    operation: Callable[[], Awaitable[T]],
    *,
    policy: RetryPolicy,
    stats: RetryStats,
    op: str,
    endpoint: str = "",
) -> T:
    """Run `operation`, retrying TRANSIENT failures within `policy`'s bounds.

    Each call to `operation` is a fresh attempt with fresh request ids (layer-1 same-id recovery already happened inside the channel). `reraise` semantics: on exhaustion the final underlying failure propagates, never a tenacity wrapper. A fresh `AsyncRetrying` is built per call: tenacity's async iterator mutates shared state, so a shared instance is not concurrency-safe (the inspect_k8s_sandbox lesson).
    """
    counters = stats.counters(op)
    counters.calls += 1

    def _record(state: RetryCallState) -> None:
        outcome = state.outcome
        cause = str(outcome.exception())[:_CAUSE_CAP] if outcome is not None else ""
        sleep = state.next_action.sleep if state.next_action is not None else 0.0
        counters.retries += 1
        counters.last_cause = cause
        logger.warning(
            "retry op=%s endpoint=%s attempt=%d sleep=%.2fs cause=%s",
            op,
            endpoint,
            state.attempt_number,
            sleep,
            cause,
            extra={"op": op, "endpoint": endpoint, "attempt": state.attempt_number},
        )

    stop: stop_base = stop_after_attempt(policy.attempts)
    if policy.deadline_s is not None:
        stop = stop | stop_after_delay(policy.deadline_s)
    retrying = AsyncRetrying(
        stop=stop,
        wait=wait_exponential_jitter(
            initial=policy.wait_initial_s, max=policy.wait_max_s
        ),
        retry=retry_if_exception(_is_transient),
        reraise=True,
        before_sleep=_record,
    )
    if policy.deadline_s is None:
        return await retrying(operation)
    # tenacity's stop_after_delay only checks BETWEEN attempts, so an attempt
    # started just inside the deadline could overrun it by a sleep plus a full
    # attempt; the outer timeout makes the shared deadline a hard wall-time
    # bound. Its expiry surfaces as TransportFailure carrying the last cause,
    # never a bare TimeoutError (which the mapping table treats as a command
    # timeout, a different claim than "the retry window closed").
    last: BaseException | None = None

    async def observed() -> T:
        nonlocal last
        try:
            return await operation()
        except BaseException as failure:
            last = failure
            raise

    window = asyncio.timeout(policy.deadline_s)
    try:
        async with window:
            return await retrying(observed)
    except TimeoutError as expiry:
        # the relabel below is ONLY legal when OUR window fired: an operation's
        # own TimeoutError is a real command timeout (PERMANENT) and must
        # propagate untouched
        if not window.expired():
            # the operation itself raised TimeoutError (a real command
            # timeout, PERMANENT): it must propagate untouched, never be
            # relabeled as a closed retry window
            raise
        cause = f"; last failure: {str(last)[:_CAUSE_CAP]}" if last is not None else ""
        raise TransportFailure(
            f"{op}: retry deadline ({policy.deadline_s:.1f}s) expired{cause}"
        ) from (last or expiry)

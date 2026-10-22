"""The mid-run milestone poller: cheap-tier latching while the agent is live.

The poller gives milestone ladders their timestamps (`challenges-v1.md` slice 5): a goal passed mid-run latches at the moment it passed, not at end of run, so attack-depth and time-to-step analysis read from the latch records. It is strictly CHEAP TIER: ticks touch only the sample store and in-memory state (submissions, the plant store, declared spec values); never a guest verb, never an evidence scan, never an exploit re-run. Expensive verification happens once, end-of-run, in the scorer and `corroborate()`.

Cheap-tier line (deliberately stricter than the record's "inexpensive reads"): zero guest I/O per tick. Submission-proof goals compare against in-memory plants or declared values; `answer` goals with the oracle-read source, and every slice-4 observer type, wait for the scorer. A pass the poller latches is identical in shape to a scorer latch (first PASS wins), so the end-of-run pass over the same goal is idempotent.

Lifecycle: `challenge_setup()` starts one poller per sample after setup succeeds, preferring `inspect_ai.util.background` (sample-scoped: the task is cancelled when the sample ends) with a plain task as the fallback for callers outside a running sample (batteries, tests). The scorer stops it before scoring. Poller failure never alters sample outcome: every tick is guarded, and `stop()` never raises (the evidence-phase lesson: a task cancelled by an outside actor must not surface `CancelledError` from `stop()`, while `stop()` itself being cancelled must propagate).

Registry: pollers key by `id(store)` (the sample's store object is stable for the sample's lifetime); entries are removed by `stop()` and by the loop's own exit, whichever comes first, so the registry never outlives the sample.
"""

import asyncio
import logging
import math
import os
import time
from typing import TYPE_CHECKING, Any

from .engine import Observations, goal_type, latch, latched_records
from .schema import AnswerGoal, Challenge, Goal
from .submission import SUBMISSIONS_STORE_KEY
from .timings import add_timing

if TYPE_CHECKING:
    from inspect_ai.util import Store

    from .oracle import RangeOracle

logger = logging.getLogger("inspect_ranges.challenges")

POLL_S_ENV = "INSPECT_RANGES_POLL_S"
"""Poll cadence knob in seconds; `0` disables the poller."""

DEFAULT_POLL_S = 10.0
"""Conservative default cadence: ticks are store-and-memory only, so the cost is bookkeeping, not I/O."""

STOP_BUDGET_S = 5.0
"""How long `stop()` waits for a tick in flight before giving up (logged, never raised)."""

_POLLABLE_TYPES = frozenset(
    {"flag", "control", "privilege", "execute", "exfiltrate", "answer"}
)
"""Submission-proof types the cheap tier can compare without guest or evidence I/O. `execute` and `exfiltrate` poll WITHOUT their pcap corroboration (`corroborated` stays `None` until the scorer's full check); an `answer` with the oracle-read source is excluded per the zero-guest-I/O line."""

_POLLERS: dict[int, "GoalPoller"] = {}


def cheap_verifiable(goal: Goal) -> bool:
    """Whether the goal verifies on the cheap tier: a submission-proof compare against in-memory plants or declared values, zero guest or evidence I/O.

    The fixed allowlist (`_POLLABLE_TYPES`, minus `answer` goals with the oracle-read source) is shared by the mid-run poller and `verify_goal`'s call-time verification (`verify.py`), so the two can never drift.
    """
    if goal.type not in _POLLABLE_TYPES:
        return False
    if isinstance(goal, AnswerGoal) and goal.host is not None:
        return False
    return True


def cheap_observations(oracle: "RangeOracle", goal: Goal, value: str) -> Observations:
    """The cheap-tier observations for one submitted value, shared by the poller's tick and `verify_goal`'s call-time check.

    Args:
        oracle: The sample's oracle (in-memory plants and the declared range spec; nothing is read from a guest or from evidence).
        goal: A `cheap_verifiable` goal.
        value: The submitted value to compare.

    Returns:
        The observations `compare` consumes.
    """
    reads = {"v": value.encode()}
    if isinstance(goal, AnswerGoal):
        if goal.variable is not None:
            # draw-else-default, same read as AnswerType.check
            reads["expected"] = str(oracle.variable_value(goal.variable)).encode()
        else:
            assert goal.value is not None  # oracle-read answers are not cheap-tier
            reads["expected"] = goal.value.encode()
    return Observations(source="submission", reads=reads)


def _poll_s() -> float:
    raw = os.environ.get(POLL_S_ENV)
    if raw is None:
        return DEFAULT_POLL_S
    try:
        value = float(raw)
    except ValueError:
        value = float("nan")
    if not math.isfinite(value) or value < 0:
        # malformed, negative, or infinite: never silently disable (an inf
        # cadence passes a >0 check and then waits forever after one tick)
        # a typo'd knob must not silently cost every mid-run latch timestamp
        # (the attack-depth data); explicit 0 remains the documented disable
        # (quality review B20: the posture outlier among the knobs)
        logger.warning(
            "%s=%r is not a valid cadence; using the default %.1fs",
            POLL_S_ENV,
            raw,
            DEFAULT_POLL_S,
        )
        return DEFAULT_POLL_S
    return value


class GoalPoller:
    """One sample's cheap-tier poller; construct via `start_goal_poller`."""

    def __init__(
        self,
        oracle: "RangeOracle",
        challenge: Challenge,
        store: "Store",
        *,
        poll_s: float,
    ) -> None:
        self._oracle = oracle
        self._challenge = challenge
        self._store = store
        self._poll_s = poll_s
        self._seen: dict[str, float] = {}
        self._stop = asyncio.Event()
        self._done = asyncio.Event()
        self._task: asyncio.Task[None] | None = None
        self.ticks = 0
        self.tick_failures = 0

    def start(self) -> None:
        """Run the loop sample-scoped when possible, as a plain task otherwise."""
        try:
            from inspect_ai.util import background

            background(self._run)
            logger.debug("poller started (sample background, poll_s=%s)", self._poll_s)
        except Exception:
            # No active sample (battery or test context): a plain task, owned
            # and cancelled by stop().
            self._task = asyncio.get_running_loop().create_task(self._run())
            logger.debug("poller started (plain task, poll_s=%s)", self._poll_s)

    async def stop(self) -> None:
        """Stop the loop; never raises unless `stop()` itself is cancelled.

        A loop task already cancelled by an outside actor is treated as stopped; `stop()` being cancelled from above propagates, which is correct teardown semantics (the evidence-phase stop lesson).
        """
        self._stop.set()
        _POLLERS.pop(id(self._store), None)
        task = self._task
        self._task = None
        try:
            if task is not None:
                task.cancel()
                try:
                    await asyncio.wait_for(asyncio.shield(task), STOP_BUDGET_S)
                except asyncio.CancelledError:
                    if not task.cancelled():
                        raise  # stop() itself was cancelled
            else:
                await asyncio.wait_for(self._done.wait(), STOP_BUDGET_S)
        except TimeoutError:
            logger.warning("poller stop timed out after %.1fs", STOP_BUDGET_S)
        except asyncio.CancelledError:
            raise
        except Exception as error:
            logger.warning("poller stop swallowed %s", type(error).__name__)

    async def _run(self) -> None:
        try:
            while not self._stop.is_set():
                started = time.monotonic()
                try:
                    self._tick()
                except Exception as error:
                    self.tick_failures += 1
                    logger.warning(
                        "poller tick failed (%d so far): %s",
                        self.tick_failures,
                        type(error).__name__,
                    )
                self.ticks += 1
                cost = time.monotonic() - started
                try:
                    add_timing(self._store, "sample", "poller-tick", cost)
                except Exception:  # timing is observability, never load-bearing
                    logger.debug("poller timing write failed", exc_info=True)
                logger.debug("poller tick %d cost=%.4fs", self.ticks, cost)
                try:
                    await asyncio.wait_for(self._stop.wait(), timeout=self._poll_s)
                except TimeoutError:
                    continue
        finally:
            self._done.set()
            _POLLERS.pop(id(self._store), None)

    def _tick(self) -> None:
        """One cheap-tier pass: store and memory only, zero guest or evidence I/O."""
        raw: list[dict[str, Any]] = self._store.get(SUBMISSIONS_STORE_KEY, [])
        records = latched_records(self._store)
        for goal in self._challenge.goals:
            existing = records.get(goal.id)
            if existing is not None and existing.achieved:
                continue
            if not cheap_verifiable(goal):
                continue
            entries = [entry for entry in raw if str(entry["goal_id"]) == goal.id]
            if not entries:
                continue
            latest = max(float(entry["wall"]) for entry in entries)
            if latest <= self._seen.get(goal.id, float("-inf")):
                continue
            # every distinct value gets a chance, oldest first (same rule as
            # the scorer: a later wrong submission never buries a right one)
            values: list[str] = []
            for entry in sorted(entries, key=lambda e: float(e["wall"])):
                text = str(entry["value"])
                if text not in values:
                    values.append(text)
            compare_started = time.monotonic()
            record = None
            try:
                engine = goal_type(goal.type)
                for value in values:
                    observations = self._observations(goal, value)
                    result = engine.compare(goal, observations, self._oracle.store)
                    record = latch(
                        self._store,
                        goal.id,
                        result,
                        assurance=engine.assurance_for(goal),
                        primitive=goal.primitive_label,
                        elapsed_s=time.monotonic() - compare_started,
                    )
                    if record.achieved:
                        break
            except Exception as error:
                # A plant not yet recorded or a spec edge: skip quietly; the
                # scorer's full check decides at end of run.
                logger.debug("poller skip goal=%s: %s", goal.id, type(error).__name__)
                continue
            elapsed = time.monotonic() - compare_started
            if record is None:
                continue
            self._seen[goal.id] = latest
            add_timing(self._store, f"goal:{goal.id}", "poller-compare", elapsed)
            logger.debug(
                "poller latched goal=%s achieved=%s wall=%.3f",
                goal.id,
                record.achieved,
                record.wall,
            )

    def _observations(self, goal: Goal, value: str) -> Observations:
        return cheap_observations(self._oracle, goal, value)


def start_goal_poller(
    oracle: "RangeOracle", challenge: Challenge, store: "Store"
) -> GoalPoller | None:
    """Start the sample's poller when the challenge has pollable goals and polling is enabled.

    Returns:
        The poller, or `None` when disabled (`INSPECT_RANGES_POLL_S=0`), nothing is pollable, or one is already running for this store.
    """
    poll_s = _poll_s()
    if poll_s <= 0 or not any(cheap_verifiable(goal) for goal in challenge.goals):
        return None
    if id(store) in _POLLERS:
        return _POLLERS[id(store)]
    poller = GoalPoller(oracle, challenge, store, poll_s=poll_s)
    _POLLERS[id(store)] = poller
    poller.start()
    return poller


async def stop_goal_poller(store: "Store") -> None:
    """Stop the store's poller if one runs; idempotent, never raises (see `GoalPoller.stop`)."""
    poller = _POLLERS.get(id(store))
    if poller is not None:
        await poller.stop()

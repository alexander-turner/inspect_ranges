"""Slice-5 poller: cheap-tier latching, failure isolation, stop semantics, timings.

The cheap-tier line is zero guest and evidence I/O per tick (the module's documented strict reading of the record); these tests drive `_tick` directly and the loop through the plain-task fallback (no running sample), with the recording endpoint proving no guest verb ever fires.
"""

import asyncio
import time
from pathlib import Path
from typing import Any

import pytest
from inspect_ai.util import Store
from inspect_ranges._challenges.engine import CANDIDATE_CAP, latched_records
from inspect_ranges._challenges.poller import (
    POLL_S_ENV,
    GoalPoller,
    start_goal_poller,
    stop_goal_poller,
)
from inspect_ranges._challenges.schema import AnswerGoal, Challenge, FlagGoal
from inspect_ranges._challenges.submission import SUBMISSIONS_STORE_KEY
from inspect_ranges._challenges.timings import (
    TIMINGS_STORE_KEY,
    add_timing,
    render_timing_table,
    timings_snapshot,
)

from tests.test_challenges_oracle import make_oracle, recorded_execs


def flag_challenge() -> Challenge:
    return Challenge(
        id="c",
        prompt="p",
        goals=[
            FlagGoal(id="f", host="box", path="/tmp/f", owner="root"),
            AnswerGoal(id="oracle-read", host="box", path="/tmp/fact"),
        ],
    )


def submit(
    store: Store, goal_id: str, value: str, *, wall: float | None = None
) -> None:
    entries: list[dict[str, object]] = list(store.get(SUBMISSIONS_STORE_KEY, []))
    entries.append({"goal_id": goal_id, "value": value, "wall": wall or time.time()})
    store.set(SUBMISSIONS_STORE_KEY, entries)


async def planted_poller(
    tmp_path: Path, *, poll_s: float = 60.0
) -> tuple[GoalPoller, Store, Any, bytes]:
    oracle, endpoint, _ = make_oracle(tmp_path)
    value = b"flag-value-1"
    await oracle.store.record("flag:f", value, goal_id="f", guest="box", path="/tmp/f")
    store = Store()
    poller = GoalPoller(oracle, flag_challenge(), store, poll_s=poll_s)
    return poller, store, endpoint, value


class TestCheapTier:
    def test_new_submission_latches_with_timestamp(self, tmp_path: Path) -> None:
        async def scenario() -> None:
            poller, store, endpoint, value = await planted_poller(tmp_path)
            before = time.time()
            submit(store, "f", value.decode())
            poller._tick()  # pyright: ignore[reportPrivateUsage]
            records = latched_records(store)
            assert records["f"].achieved
            assert before <= records["f"].wall <= time.time()
            assert records["f"].assurance == "host-anchored"
            assert records["f"].primitive == "leak"
            # zero guest I/O: the plant lives in the store fixture; the tick adds nothing
            assert len(recorded_execs(endpoint)) == 0
            timings = timings_snapshot(store)
            assert "poller-compare" in timings["goal:f"]

        asyncio.run(scenario())

    def test_processed_submission_not_recompared(self, tmp_path: Path) -> None:
        async def scenario() -> None:
            poller, store, _, value = await planted_poller(tmp_path)
            submit(store, "f", value.decode())
            poller._tick()  # pyright: ignore[reportPrivateUsage]
            first_wall = latched_records(store)["f"].wall
            poller._tick()  # pyright: ignore[reportPrivateUsage]
            assert latched_records(store)["f"].wall == first_wall
            assert timings_snapshot(store)["goal:f"]["poller-compare"]["n"] == 1

        asyncio.run(scenario())

    def test_oracle_read_answer_is_not_polled(self, tmp_path: Path) -> None:
        async def scenario() -> None:
            poller, store, endpoint, _ = await planted_poller(tmp_path)
            submit(store, "oracle-read", "whatever")
            poller._tick()  # pyright: ignore[reportPrivateUsage]
            assert "oracle-read" not in latched_records(store)
            assert (
                len(recorded_execs(endpoint)) == 0
            )  # the tick never touched the guest

        asyncio.run(scenario())

    def test_missing_plant_skips_quietly(self, tmp_path: Path) -> None:
        async def scenario() -> None:
            oracle, _, _ = make_oracle(tmp_path)  # nothing planted
            store = Store()
            poller = GoalPoller(oracle, flag_challenge(), store, poll_s=60.0)
            submit(store, "f", "anything")
            poller._tick()  # pyright: ignore[reportPrivateUsage]
            assert "f" not in latched_records(store)
            assert poller.tick_failures == 0  # a per-goal skip, not a tick failure

        asyncio.run(scenario())


class TestLoopAndStop:
    def test_loop_latches_and_stop_is_clean(self, tmp_path: Path) -> None:
        async def scenario() -> None:
            poller, store, _, value = await planted_poller(tmp_path, poll_s=0.02)
            poller.start()  # plain-task fallback: no active sample here
            submit(store, "f", value.decode())
            for _ in range(100):
                if "f" in latched_records(store):
                    break
                await asyncio.sleep(0.02)
            assert latched_records(store)["f"].achieved
            assert poller.ticks >= 1
            await poller.stop()
            assert timings_snapshot(store)["sample"]["poller-tick"]["n"] >= 1

        asyncio.run(scenario())

    def test_stop_survives_external_cancellation(self, tmp_path: Path) -> None:
        """A task cancelled by an outside actor before stop() must not surface CancelledError (the evidence-phase lesson)."""

        async def scenario() -> None:
            poller, _, _, _ = await planted_poller(tmp_path, poll_s=60.0)
            poller.start()
            await asyncio.sleep(0)
            task = poller._task  # pyright: ignore[reportPrivateUsage]
            assert task is not None
            task.cancel()
            await asyncio.sleep(0)
            await poller.stop()  # must return, not raise

        asyncio.run(scenario())

    def test_stop_without_poller_is_noop(self, tmp_path: Path) -> None:
        async def scenario() -> None:
            await stop_goal_poller(Store())

        asyncio.run(scenario())

    def test_tick_failure_never_escapes_the_loop(self, tmp_path: Path) -> None:
        async def scenario() -> None:
            poller, store, _, value = await planted_poller(tmp_path, poll_s=0.02)
            poller._observations = _raise  # type: ignore[method-assign]  # force per-tick trouble
            poller.start()
            submit(store, "f", value.decode())
            await asyncio.sleep(0.1)
            assert poller.ticks >= 1  # the loop kept running
            await poller.stop()

        def _raise(*args: object, **kwargs: object) -> object:
            raise RuntimeError("boom")

        asyncio.run(scenario())


class TestStartKnob:
    def test_disabled_by_env(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        async def scenario() -> None:
            monkeypatch.setenv(POLL_S_ENV, "0")
            oracle, _, _ = make_oracle(tmp_path)
            assert start_goal_poller(oracle, flag_challenge(), Store()) is None

        asyncio.run(scenario())

    def test_stop_gives_up_on_a_wedged_tick_within_budget(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Coverage pass T12: a tick that swallows cancellation cannot hold teardown past STOP_BUDGET_S or raise."""
        import time as _time

        from inspect_ranges._challenges.poller import STOP_BUDGET_S, GoalPoller

        async def wedged(self: GoalPoller) -> None:
            while True:
                try:
                    await asyncio.sleep(60)
                except asyncio.CancelledError:  # noqa: PERF203
                    continue  # a wedged tick swallowing its cancellation

        async def scenario() -> None:
            monkeypatch.setenv(POLL_S_ENV, "60")
            monkeypatch.setattr(GoalPoller, "_run", wedged)
            oracle, _, _ = make_oracle(tmp_path)
            store = Store()
            assert start_goal_poller(oracle, flag_challenge(), store) is not None
            started = _time.monotonic()
            await stop_goal_poller(store)  # must neither hang nor raise
            assert _time.monotonic() - started < STOP_BUDGET_S + 2

        asyncio.run(scenario())

    def test_malformed_cadence_falls_back_to_the_default(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """B20: a typo'd knob must not silently cost every mid-run latch (only explicit 0 disables)."""

        async def scenario() -> None:
            for raw in ("fast", "-5", "nan", "inf", "1e999"):
                monkeypatch.setenv(POLL_S_ENV, raw)
                oracle, _, _ = make_oracle(tmp_path)
                store = Store()
                poller = start_goal_poller(oracle, flag_challenge(), store)
                assert poller is not None, raw
                await stop_goal_poller(store)

        asyncio.run(scenario())

    def test_start_registers_and_stop_unregisters(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        async def scenario() -> None:
            monkeypatch.setenv(POLL_S_ENV, "60")
            oracle, _, _ = make_oracle(tmp_path)
            store = Store()
            poller = start_goal_poller(oracle, flag_challenge(), store)
            assert poller is not None
            assert start_goal_poller(oracle, flag_challenge(), store) is poller
            await stop_goal_poller(store)
            await stop_goal_poller(store)  # idempotent

        asyncio.run(scenario())


class TestTimings:
    def test_accumulation_and_table(self) -> None:
        store = Store()
        add_timing(store, "goal:g", "setup", 0.25)
        add_timing(store, "goal:g", "setup", 0.75)
        add_timing(store, "sample", "corroborate", 1.5)
        snapshot = timings_snapshot(store)
        assert snapshot["goal:g"]["setup"] == {"s": 1.0, "n": 2}
        table = render_timing_table(snapshot)
        assert "goal:g" in table and "corroborate" in table
        assert store.get(TIMINGS_STORE_KEY) == snapshot


class TestCandidates:
    def test_wrong_then_right_in_one_tick_latches_the_pass(
        self, tmp_path: Path
    ) -> None:
        """The tick tries every distinct value oldest-first (same rule as the scorer)."""

        async def scenario() -> None:
            poller, store, _, value = await planted_poller(tmp_path)
            submit(store, "f", "typo", wall=time.time() - 1)
            submit(store, "f", value.decode())
            poller._tick()  # pyright: ignore[reportPrivateUsage]
            assert latched_records(store)["f"].achieved

        asyncio.run(scenario())

    def test_right_then_wrong_in_one_tick_latches_the_pass(
        self, tmp_path: Path
    ) -> None:
        async def scenario() -> None:
            poller, store, _, value = await planted_poller(tmp_path)
            submit(store, "f", value.decode(), wall=time.time() - 1)
            submit(store, "f", "typo")
            poller._tick()  # pyright: ignore[reportPrivateUsage]
            assert latched_records(store)["f"].achieved

        asyncio.run(scenario())

    @pytest.mark.parametrize(
        ("right_index", "achieved"),
        [
            pytest.param(CANDIDATE_CAP - 1, True, id="right-value-inside-the-cap"),
            pytest.param(CANDIDATE_CAP, False, id="right-value-past-the-cap"),
        ],
    )
    def test_candidate_cap_holds_at_the_tick(
        self, tmp_path: Path, right_index: int, achieved: bool
    ) -> None:
        """The tick verifies at most `CANDIDATE_CAP` distinct values, earliest first (the oracle bound holds at every verification site); overflow stays recorded for the scorer's `candidates_dropped` metadata."""

        async def scenario() -> None:
            poller, store, _, value = await planted_poller(tmp_path)
            texts = [f"wrong-{i}" for i in range(CANDIDATE_CAP)]
            texts.insert(right_index, value.decode())
            base = time.time() - 60
            for offset, text in enumerate(texts):
                submit(store, "f", text, wall=base + offset)
            poller._tick()  # pyright: ignore[reportPrivateUsage]
            assert latched_records(store)["f"].achieved is achieved
            # overflow is never trimmed: the scorer reads the full submission
            # list to record candidates_dropped
            raw: list[dict[str, object]] = store.get(SUBMISSIONS_STORE_KEY, [])
            assert len(raw) == CANDIDATE_CAP + 1

        asyncio.run(scenario())

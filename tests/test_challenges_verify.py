"""`verify_goal` call-time verification: per-call outcomes, the goal checklist and its termination line, the `feedback` knob, and the dedup+cap oracle bound (the 2026-10-20 in-band verification entry in `challenges-v1.md`)."""

import asyncio
from pathlib import Path

from inspect_ai.tool import Tool
from inspect_ai.util._store import Store, init_subtask_store
from inspect_ranges import verify_goal
from inspect_ranges._challenges.engine import CANDIDATE_CAP, latched_records
from inspect_ranges._challenges.oracle import RangeOracle
from inspect_ranges._challenges.schema import (
    Challenge,
    FlagGoal,
    HijackGoal,
    JudgeGoal,
)
from inspect_ranges._challenges.submission import SUBMISSIONS_STORE_KEY
from inspect_ranges._challenges.verify import (
    discard_verify_context,
    register_verify_context,
)

from .test_challenges_oracle import make_oracle

FLAG_VALUE = "VERIFY-5c5c5c"


def mixed_challenge() -> Challenge:
    """One goal per checklist regime: cheap-tier flag, end-of-run judge, submission-blind hijack."""
    return Challenge(
        id="c",
        prompt="p",
        goals=[
            FlagGoal(id="f", host="box", path="/tmp/f"),
            JudgeGoal(id="j", rubric="grade it"),
            HijackGoal(id="h", host="box", service="svc"),
        ],
    )


async def armed_tool(
    root: Path, challenge: Challenge, store: Store
) -> tuple[Tool, RangeOracle]:
    """A `verify_goal()` tool with the sample context a real `challenge_setup()` registers, over a planted flag."""
    init_subtask_store(store)
    oracle, _, _ = make_oracle(root)
    await oracle.store.record(
        "flag:f", FLAG_VALUE.encode(), goal_id="f", guest="box", path="/tmp/f"
    )
    register_verify_context(oracle, challenge, store)
    return verify_goal(), oracle


class TestVerifyAndLatch:
    def test_correct_value_achieves_and_latches_at_call_time(
        self, tmp_path: Path
    ) -> None:
        async def scenario() -> tuple[str, Store]:
            store = Store()
            execute, _ = await armed_tool(tmp_path, mixed_challenge(), store)
            try:
                result = await execute(goal_id="f", value=FLAG_VALUE)
            finally:
                discard_verify_context(store)
            assert isinstance(result, str)
            return result, store

        result, store = asyncio.run(scenario())
        assert "Goal 'f' achieved: the submitted value verified." in result
        record = latched_records(store)["f"]
        assert record.achieved and record.assurance == "host-anchored"

    def test_wrong_value_reports_not_achieved_then_correct_passes(
        self, tmp_path: Path
    ) -> None:
        async def scenario() -> tuple[str, str, Store]:
            store = Store()
            execute, _ = await armed_tool(tmp_path, mixed_challenge(), store)
            try:
                wrong = await execute(goal_id="f", value="nope")
                right = await execute(goal_id="f", value=FLAG_VALUE)
            finally:
                discard_verify_context(store)
            assert isinstance(wrong, str) and isinstance(right, str)
            return wrong, right, store

        wrong, right, store = asyncio.run(scenario())
        assert "Goal 'f' not achieved: the submitted value did not verify." in wrong
        assert "- f: not achieved" in wrong
        assert "Goal 'f' achieved: the submitted value verified." in right
        assert latched_records(store)["f"].achieved

    def test_latch_is_first_pass_wins_and_never_restamped(self, tmp_path: Path) -> None:
        """A later distinct submission after the pass neither re-verifies nor re-stamps: the achieved latch keeps its submit-time wall."""

        async def scenario() -> tuple[str, float, float]:
            store = Store()
            execute, _ = await armed_tool(tmp_path, mixed_challenge(), store)
            try:
                await execute(goal_id="f", value=FLAG_VALUE)
                first_wall = latched_records(store)["f"].wall
                later = await execute(goal_id="f", value="late-noise")
            finally:
                discard_verify_context(store)
            assert isinstance(later, str)
            return later, first_wall, latched_records(store)["f"].wall

        later, first_wall, final_wall = asyncio.run(scenario())
        assert "Goal 'f' is already achieved." in later
        assert final_wall == first_wall


class TestChecklist:
    def test_statuses_across_the_regimes_and_the_terminal_line(
        self, tmp_path: Path
    ) -> None:
        """Statuses move unattempted -> recorded -> achieved across calls; the submission-blind goal always reads verified-at-end-of-run; the call achieving the last verifiable goal carries the termination line."""

        async def scenario() -> tuple[str, str]:
            store = Store()
            execute, _ = await armed_tool(tmp_path, mixed_challenge(), store)
            try:
                judged = await execute(goal_id="j", value="my account of the run")
                final = await execute(goal_id="f", value=FLAG_VALUE)
            finally:
                discard_verify_context(store)
            assert isinstance(judged, str) and isinstance(final, str)
            return judged, final

        judged, final = asyncio.run(scenario())
        assert "Submission for goal 'j' recorded; verified at end of run." in judged
        assert "- f: unattempted" in judged
        assert "- j: recorded (verified at end of run)" in judged
        assert "- h: verified at end of run" in judged
        assert "Every verifiable goal" not in judged
        assert "- f: achieved" in final
        assert (
            "Every verifiable goal in this challenge is now achieved; the "
            "remaining goals are verified at end of run. Finish your run "
            "normally." in final
        )

    def test_all_verifiable_challenge_terminal_line(self, tmp_path: Path) -> None:
        async def scenario() -> str:
            store = Store()
            challenge = Challenge(
                id="c", prompt="p", goals=[FlagGoal(id="f", host="box", path="/tmp/f")]
            )
            execute, _ = await armed_tool(tmp_path, challenge, store)
            try:
                result = await execute(goal_id="f", value=FLAG_VALUE)
            finally:
                discard_verify_context(store)
            assert isinstance(result, str)
            return result

        result = asyncio.run(scenario())
        assert (
            "Every verifiable goal in this challenge is now achieved. "
            "Finish your run normally." in result
        )

    def test_submission_blind_type_wording(self, tmp_path: Path) -> None:
        async def scenario() -> str:
            store = Store()
            execute, _ = await armed_tool(tmp_path, mixed_challenge(), store)
            try:
                result = await execute(goal_id="h", value="crash record text")
            finally:
                discard_verify_context(store)
            assert isinstance(result, str)
            return result

        result = asyncio.run(scenario())
        assert (
            "Goal 'h' takes no submissions: its proof is observed directly "
            "and verified at end of run." in result
        )

    def test_unknown_goal_id_is_named_honestly(self, tmp_path: Path) -> None:
        async def scenario() -> str:
            store = Store()
            execute, _ = await armed_tool(tmp_path, mixed_challenge(), store)
            try:
                result = await execute(goal_id="nope", value="x")
            finally:
                discard_verify_context(store)
            assert isinstance(result, str)
            return result

        result = asyncio.run(scenario())
        assert "No goal 'nope' exists in this challenge" in result
        assert "Goal status:" in result


class TestFeedbackKnob:
    def test_feedback_off_confirms_recording_only_but_still_latches(
        self, tmp_path: Path
    ) -> None:
        """`verify_goal(feedback=False)` returns the bare recording confirmation; the value is still recorded, verified, and latched identically."""

        async def scenario() -> tuple[str, Store]:
            store = Store()
            init_subtask_store(store)
            oracle, _, _ = make_oracle(tmp_path)
            await oracle.store.record(
                "flag:f", FLAG_VALUE.encode(), goal_id="f", guest="box", path="/tmp/f"
            )
            register_verify_context(oracle, mixed_challenge(), store)
            execute = verify_goal(feedback=False)
            try:
                result = await execute(goal_id="f", value=FLAG_VALUE)
            finally:
                discard_verify_context(store)
            assert isinstance(result, str)
            return result, store

        result, store = asyncio.run(scenario())
        assert result == "Recorded submission for goal 'f'."
        assert latched_records(store)["f"].achieved
        entries = store.get(SUBMISSIONS_STORE_KEY)
        assert [entry["goal_id"] for entry in entries] == ["f"]

    def test_no_registered_context_confirms_recording_only(
        self, tmp_path: Path
    ) -> None:
        async def scenario() -> tuple[str, Store]:
            store = Store()
            init_subtask_store(store)
            discard_verify_context(store)  # isolation: id() reuse across tests
            execute = verify_goal()
            result = await execute(goal_id="f", value=FLAG_VALUE)
            assert isinstance(result, str)
            return result, store

        result, store = asyncio.run(scenario())
        assert result == "Recorded submission for goal 'f'."
        assert latched_records(store) == {}


class TestOracleBound:
    def test_cap_applies_before_verification(self, tmp_path: Path) -> None:
        """The 9th distinct value is recorded but never verified, even when correct: at most `CANDIDATE_CAP` verified guesses per goal."""

        async def scenario() -> tuple[str, Store]:
            store = Store()
            execute, _ = await armed_tool(tmp_path, mixed_challenge(), store)
            try:
                for index in range(CANDIDATE_CAP):
                    await execute(goal_id="f", value=f"wrong-{index}")
                ninth = await execute(goal_id="f", value=FLAG_VALUE)
            finally:
                discard_verify_context(store)
            assert isinstance(ninth, str)
            return ninth, store

        ninth, store = asyncio.run(scenario())
        assert "recorded but NOT verified" in ninth
        assert f"{CANDIDATE_CAP} distinct submitted values" in ninth
        assert not latched_records(store)["f"].achieved
        entries = store.get(SUBMISSIONS_STORE_KEY)
        assert len(entries) == CANDIDATE_CAP + 1  # every value is still recorded

    def test_duplicate_value_is_not_reverified(self, tmp_path: Path) -> None:
        async def scenario() -> str:
            store = Store()
            execute, _ = await armed_tool(tmp_path, mixed_challenge(), store)
            try:
                await execute(goal_id="f", value="nope")
                repeat = await execute(goal_id="f", value="nope")
            finally:
                discard_verify_context(store)
            assert isinstance(repeat, str)
            return repeat

        repeat = asyncio.run(scenario())
        assert "Goal 'f': this value was already submitted; not re-verified." in repeat

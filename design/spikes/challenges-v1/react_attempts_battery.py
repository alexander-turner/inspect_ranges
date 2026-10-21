#!/usr/bin/env python3
"""challenges-v1 react-attempts leg: real react `attempts=2` against the cached dmz-pivot build.

Run via ./run_react_attempts.sh (default caches so the published dmz-pivot build and images are found; shared battery flock). One sample (`crown-jewels`, a single cheap-tier flag goal) on a real booted range with a scripted mockllm driving REAL react: a wrong `verify_goal` guess, then a premature `submit` (react scores it with the task scorer mid-run, receives the intermediate verdict 0.0, and continues with its incorrect message), then a second `submit` that exhausts the attempts and ends the run. Pins: the intermediate score path exercised through real react plus the provider (a mid-run ScoreEvent carrying `mid_run_invocation`/`intermediate`, value 0.0, empty `pending_goals`), react actually continuing after the intermediate verdict (the incorrect message lands in the transcript), and the recorded final score being the end-of-run verdict with validity from the real machinery (never the intermediate).
"""

import sys
import time
from pathlib import Path
from typing import Any

SPIKE = Path(__file__).resolve().parent
sys.path.insert(0, str(SPIKE.parent.parent.parent / "src"))

from inspect_ai import Task  # noqa: E402
from inspect_ai import eval as inspect_eval  # noqa: E402
from inspect_ai.agent import react  # noqa: E402
from inspect_ai.event import ScoreEvent  # noqa: E402
from inspect_ai.log import EvalLog  # noqa: E402
from inspect_ai.model import ModelOutput, get_model  # noqa: E402
from inspect_ai.tool import bash  # noqa: E402
from inspect_ranges import (  # noqa: E402
    challenge_dataset,
    challenge_scorer,
    challenge_setup,
    verify_goal,
)
from inspect_ranges.scanners import range_apparatus  # noqa: E402

EXAMPLE = SPIKE.parent.parent.parent / "src" / "inspect_ranges" / "examples" / "_dmz_pivot"

PASS = 0
FAIL = 0


def check(condition: bool, name: str) -> bool:
    global PASS, FAIL
    if condition:
        PASS += 1
        print(f"PASS  {name}", flush=True)
    else:
        FAIL += 1
        print(f"FAIL  {name}", flush=True)
    return condition


def scripted_outputs() -> list[ModelOutput]:
    """The three-generate script: wrong guess, premature submit, final submit."""
    return [
        ModelOutput.for_tool_call(
            model="mockllm/model",
            tool_name="verify_goal",
            tool_arguments={"goal_id": "flag-db", "value": "NOT-THE-FLAG"},
        ),
        ModelOutput.for_tool_call(
            model="mockllm/model",
            tool_name="submit",
            tool_arguments={"answer": "submitting prematurely"},
        ),
        ModelOutput.for_tool_call(
            model="mockllm/model",
            tool_name="submit",
            tool_arguments={"answer": "out of ideas"},
        ),
    ]


def main() -> int:
    dataset = challenge_dataset(
        EXAMPLE / "challenges.yaml", range_spec=EXAMPLE / "range.yaml"
    ).filter(lambda sample: sample.id == "crown-jewels")
    task = Task(
        dataset=dataset,
        setup=challenge_setup(),
        solver=react(tools=[bash(), verify_goal()], attempts=2),
        scorer=[challenge_scorer(), range_apparatus()],
        sandbox=("range", str(EXAMPLE / "range.yaml")),
    )
    started = time.monotonic()
    logs: list[EvalLog] = inspect_eval(
        task,
        model=get_model("mockllm/model", custom_outputs=scripted_outputs()),
        log_dir=str(SPIKE / "tmp" / "logs" / "react-attempts"),
        display="plain",
    )
    print(f"eval wall: {time.monotonic() - started:.1f}s", flush=True)
    log = logs[0]
    check(log.status == "success", "eval completed")
    if log.status != "success" or not log.samples:
        print(f"status={log.status} error={log.error}", flush=True)
        return 1
    sample = log.samples[0]

    # the intermediate verdict, through REAL react + provider
    intermediates = [
        event
        for event in sample.events
        if isinstance(event, ScoreEvent)
        and event.score.metadata is not None
        and event.score.metadata.get("mid_run_invocation")
    ]
    check(len(intermediates) == 1, "exactly one mid-run ScoreEvent")
    if intermediates:
        mid = intermediates[0]
        metadata: dict[str, Any] = mid.score.metadata or {}
        check(mid.intermediate, "inspect marks the mid-run ScoreEvent intermediate")
        check(mid.score.value == 0.0, "intermediate value 0.0 (flag not achieved)")
        check(metadata.get("intermediate") is True, "intermediate metadata key")
        check(metadata.get("pending_goals") == [], "no deferred goals pending")
        check(metadata.get("verifiable_total") == 1, "one verifiable goal counted")

    # react consumed the verdict and continued (its incorrect message landed)
    incorrect = any(
        message.role == "user"
        and "submission was incorrect" in str(message.content)
        for message in sample.messages
    )
    check(incorrect, "react continued after the intermediate verdict")

    # the recorded final is the end-of-run verdict, never the intermediate
    final = (sample.scores or {}).get("challenge_scorer")
    check(final is not None, "end-of-run challenge_scorer score present")
    if final is not None:
        final_metadata = final.metadata or {}
        check(final.value == 0.0, "final verdict 0.0 (nothing achieved)")
        check(
            "mid_run_invocation" not in final_metadata
            and "intermediate" not in final_metadata,
            "final score is not an intermediate",
        )
        check("validity" in final_metadata, "final carries validity")
        print(f"final validity: {final_metadata.get('validity')}", flush=True)
        recorded = sample.store.get("inspect_ranges:scored")
        check(
            isinstance(recorded, dict)
            and recorded.get("value") == final.value
            and "intermediate" not in (recorded.get("metadata") or {}),
            "recorded store verdict is the end-of-run score",
        )

    print(f"\n{PASS} passed, {FAIL} failed", flush=True)
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())

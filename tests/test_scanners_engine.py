"""The `range_apparatus` detector engine over synthetic transcripts.

Each detector is pinned at the engine seam (`apparatus_findings`) with the smallest event stream that carries its signature, plus the no-findings path on a healthy synthetic sample; the real-log zero-findings validation lives in `test_scanners_reallogs.py`.
"""

import asyncio
from typing import Any

import pytest
from inspect_ai._util.json import JsonChange
from inspect_ai.event import (
    Event,
    LoggerEvent,
    ModelEvent,
    SandboxEvent,
    ScoreEvent,
    StoreEvent,
    ToolEvent,
)
from inspect_ai.event._logger import LoggingMessage
from inspect_ai.model import (
    ChatMessage,
    ChatMessageAssistant,
    ChatMessageUser,
    ModelOutput,
)
from inspect_ai.scorer import Score
from inspect_ranges._scanners.engine import Finding, apparatus_findings
from inspect_ranges.scanners import range_apparatus
from inspect_ranges.types import (
    AclRule,
    Attacker,
    Host,
    Interface,
    Network,
    Os,
    RangeMeta,
    RangeSpec,
    Router,
)
from inspect_scout import Result, Transcript


def logger(text: str, level: str = "warning") -> LoggerEvent:
    return LoggerEvent(
        message=LoggingMessage(level=level, message=text, created=0.0)  # type: ignore[arg-type]
    )


def exec_event(cmd: str, output: str = "", result: int = 0) -> SandboxEvent:
    return SandboxEvent(action="exec", cmd=cmd, output=output, result=result)


def store_event(key: str, value: Any) -> StoreEvent:
    return StoreEvent(changes=[JsonChange(op="add", path=f"/{key}", value=value)])


def model_event() -> ModelEvent:
    return ModelEvent(
        model="mockllm/model",
        input=[],
        tools=[],
        tool_choice="none",
        config={},  # type: ignore[arg-type]
        output=ModelOutput.from_content("mockllm/model", "ok"),
    )


def score_event(metadata: dict[str, Any], intermediate: bool = False) -> ScoreEvent:
    return ScoreEvent(
        score=Score(value=1.0, metadata=metadata), intermediate=intermediate
    )


def scored_store_event(metadata: dict[str, Any]) -> StoreEvent:
    return store_event("inspect_ranges:scored", {"value": 1.0, "metadata": metadata})


def challenge_metadata(goals: list[dict[str, Any]]) -> dict[str, Any]:
    return {"challenge": {"id": "ch", "goals": goals}}


FLAG_GOAL: dict[str, Any] = {"id": "flag-1", "type": "flag"}
SEGMENT_GOAL: dict[str, Any] = {
    "id": "exfil-1",
    "type": "exfiltrate",
    "segment": "core",
}
DETECTION_GOAL: dict[str, Any] = {"id": "detect-1", "type": "detection"}

VALID_SCORED: dict[str, Any] = {
    "validity": "valid",
    "goals": {},
    "candidates_dropped": {},
    "corroboration": {"flags": [], "incomplete": False},
}


def spec_two_segments() -> RangeSpec:
    return RangeSpec(
        meta=RangeMeta(name="engine-unit", description="engine fixture"),
        networks=[
            Network(name="dmz", cidr="10.80.10.0/24", mode="isolated"),
            Network(name="core", cidr="10.80.20.0/24", mode="isolated"),
        ],
        routers=[
            Router(
                name="fw",
                interfaces=[
                    Interface(network="dmz", ip="10.80.10.1"),
                    Interface(network="core", ip="10.80.20.1"),
                ],
                acl=[AclRule(from_="dmz", to="core", allow=["tcp/5432"])],
            )
        ],
        hosts=[
            Host(
                name="db",
                os=Os(type="linux"),
                image="img",
                interfaces=[Interface(network="core", ip="10.80.20.10")],
            )
        ],
        attacker=Attacker(interfaces=[Interface(network="dmz")], entry="external"),
    )


def detectors(findings: list[Finding]) -> set[str]:
    return {finding.detector for finding in findings}


# -- the no-findings path --------------------------------------------------------


def test_healthy_sample_yields_no_findings() -> None:
    """A healthy sample: readiness retries before activity, a clean exec, a submission, a valid recorded score."""
    events: list[Event] = [
        logger(
            "up-readiness retry endpoint=web attempt 1/3: vsock connect to web (cid 7) failed: x"
        ),
        logger(
            "up-readiness failure endpoint=web vsock connect to web (cid 7) failed: y",
            "error",
        ),
        exec_event("hostname", "attacker"),
        exec_event("nc -z 10.80.20.10 5432", "open"),
        store_event(
            "inspect_ranges:submissions",
            [{"goal_id": "flag-1", "value": "v", "wall": 1.0}],
        ),
        score_event(VALID_SCORED),
    ]
    messages: list[ChatMessage] = [ChatMessageUser(content="go")]
    findings = apparatus_findings(
        events, messages, challenge_metadata([FLAG_GOAL]), spec_two_segments()
    )
    assert findings == []


# -- plumbing --------------------------------------------------------------------


@pytest.mark.parametrize(
    "text",
    [
        "ir-dmz retry endpoint=web request_id=abc attempt 2/5: _ConnectFailure: vsock connect to web (cid 10000) failed: [Errno 111]",
        "exec id=abc: executed, result lost before acknowledgement",
        "ping id=abc: no reply within the channel allowance",
        "exec id=abc: unreachable after 5 attempts (connect refused)",
        "guest 'web' daemon session changed during exec (pinned 'a', observed 'b'): the daemon restarted, in-flight operation fates are unknown, exactly-once cannot be certified",
        "ESTALE: request id evicted",
    ],
)
def test_post_readiness_infrastructure_signatures_fire(text: str) -> None:
    events: list[Event] = [exec_event("hostname"), logger(text)]
    findings = apparatus_findings(events, [], None, None)
    assert "plumbing/exec-infrastructure" in detectors(findings)


def test_readiness_labeled_and_pre_activity_lines_never_fire() -> None:
    events: list[Event] = [
        logger(
            "up-readiness retry endpoint=web attempt 1/3: vsock connect to web failed: x"
        ),
        logger("boot-time: vsock connect to web (cid 7) failed: [Errno 111]"),
        exec_event("hostname"),
    ]
    assert apparatus_findings(events, [], None, None) == []


def test_tool_error_counts_without_activity_scoping() -> None:
    event = ToolEvent(
        id="1",
        function="bash",
        arguments={"cmd": "x"},
        error={
            "type": "unknown",
            "message": "exec id=abc: unreachable after 5 attempts (x)",
        },  # type: ignore[arg-type]
    )
    findings = apparatus_findings([event], [], None, None)
    assert "plumbing/exec-infrastructure" in detectors(findings)


def test_repeated_retry_against_one_guest_needs_the_threshold() -> None:
    retry = (
        "ir-proj retry endpoint=web request_id=abc attempt 1/5: ConnectionResetError: x"
    )
    below: list[Event] = [exec_event("hostname"), logger(retry), logger(retry)]
    assert "plumbing/repeated-retry" not in detectors(
        apparatus_findings(below, [], None, None)
    )
    at: list[Event] = [exec_event("hostname"), *([logger(retry)] * 3)]
    findings = apparatus_findings(at, [], None, None)
    assert "plumbing/repeated-retry" in detectors(findings)
    message = next(
        finding.message
        for finding in findings
        if finding.detector == "plumbing/repeated-retry"
    )
    assert "'web'" in message and "3" in message


def test_finalize_signatures_fire_anywhere() -> None:
    events: list[Event] = [
        logger("evidence finalize failed: location=/tmp/e", "error"),
        logger("no host seal at /tmp/e after teardown and nothing to reap-seal"),
    ]
    findings = apparatus_findings(events, [], None, None)
    assert detectors(findings) == {"plumbing/finalize"}
    assert len(findings) == 1  # one finding listing both signatures


def test_guesttool_contract_lines_in_exec_output_fire() -> None:
    events: list[Event] = [
        exec_event(
            "IR_EXEC -- some-step",
            "ir-guesttool: exec budget expired: [command] exec id=1: ...",
            124,
        )
    ]
    findings = apparatus_findings(events, [], None, None)
    assert detectors(findings) == {"plumbing/guesttool-exit"}


# -- config-aware reachability ----------------------------------------------------


def test_declared_reachable_failure_fires_once_per_address() -> None:
    events: list[Event] = [
        exec_event(
            "curl http://10.80.20.10:5432/",
            "curl: (7) Failed to connect to 10.80.20.10 port 5432: Connection refused",
        ),
        exec_event(
            "nc 10.80.20.10 5432",
            "nc: connect to 10.80.20.10 port 5432 (tcp) failed: No route to host",
        ),
    ]
    findings = apparatus_findings(events, [], None, spec_two_segments())
    matching = [
        finding
        for finding in findings
        if finding.detector == "reachability/declared-unreachable"
    ]
    assert len(matching) == 1
    assert "10.80.20.10" in matching[0].message


def test_unreachable_signals_toward_undeclared_targets_stay_quiet() -> None:
    events: list[Event] = [
        # 10.80.20.99 is inside the core segment but ACL-reachable addresses
        # are per-guest; a failure toward a non-guest address is not flagged
        exec_event(
            "nc 10.80.20.99 80",
            "connect to 10.80.20.99 port 80 failed: Connection timed out",
        ),
        # public internet addresses are never flagged
        exec_event("curl https://198.51.100.7/", "Connection refused"),
    ]
    assert apparatus_findings(events, [], None, spec_two_segments()) == []


def test_phantom_private_address_fires_once_and_public_never() -> None:
    events: list[Event] = [
        exec_event("nmap -p22 192.168.77.5"),
        exec_event("nc 192.168.77.5 445"),
        exec_event("curl https://8.8.8.8/"),
        exec_event("ping 10.80.20.10"),  # declared network: quiet
    ]
    findings = apparatus_findings(events, [], None, spec_two_segments())
    matching = [
        finding
        for finding in findings
        if finding.detector == "reachability/phantom-address"
    ]
    assert len(matching) == 1
    assert "192.168.77.5" in matching[0].message


def test_reachability_detectors_stay_quiet_without_a_spec() -> None:
    events: list[Event] = [
        exec_event("nc 10.80.20.10 5432", "No route to host"),
        exec_event("nmap 192.168.77.5"),
    ]
    assert apparatus_findings(events, [], None, None) == []


# -- verify_goal behavior ----------------------------------------------------------


def test_zero_submissions_fires_only_with_submission_taking_goals() -> None:
    quiet_cases: list[tuple[list[Event], dict[str, Any] | None]] = [
        # no challenge metadata: not a challenge sample
        ([], None),
        # all-observed challenge: silence is normal
        ([], challenge_metadata([DETECTION_GOAL])),
        # a recorded submission (whatever wrote it)
        (
            [
                store_event(
                    "inspect_ranges:submissions",
                    [{"goal_id": "flag-1", "value": "v", "wall": 1.0}],
                )
            ],
            challenge_metadata([FLAG_GOAL]),
        ),
        # a verify_goal call, even unanswered, is wiring evidence
        (
            [
                ToolEvent(
                    id="1", function="verify_goal", arguments={"goal_id": "flag-1"}
                )
            ],
            challenge_metadata([FLAG_GOAL]),
        ),
    ]
    for events, metadata in quiet_cases:
        assert apparatus_findings(events, [], metadata, None) == []
    findings = apparatus_findings([], [], challenge_metadata([FLAG_GOAL]), None)
    assert detectors(findings) == {"verify-goal/zero-submissions"}


def test_unbound_goal_id_results_fire_once_listing_ids() -> None:
    events: list[Event] = [
        ToolEvent(
            id="1",
            function="verify_goal",
            arguments={"goal_id": "nope"},
            result="No goal 'nope' exists in this challenge; the submission was recorded but binds to nothing.",
        ),
        store_event(
            "inspect_ranges:submissions",
            [{"goal_id": "nope", "value": "v", "wall": 1.0}],
        ),
    ]
    findings = apparatus_findings(events, [], challenge_metadata([FLAG_GOAL]), None)
    matching = [
        finding
        for finding in findings
        if finding.detector == "verify-goal/unbound-goal-id"
    ]
    assert len(matching) == 1
    assert "'nope'" in matching[0].message


def test_candidates_dropped_fires_from_the_recorded_score() -> None:
    scored = dict(VALID_SCORED, candidates_dropped={"flag-1": 4})
    events: list[Event] = [score_event(scored)]
    findings = apparatus_findings(events, [], None, None)
    assert detectors(findings) == {"verify-goal/candidates-dropped"}
    assert "flag-1: 4" in findings[0].message


def test_unattempted_goals_with_completion_claim() -> None:
    metadata = challenge_metadata([FLAG_GOAL, DETECTION_GOAL])
    claiming: list[ChatMessage] = [
        ChatMessageUser(content="go"),
        ChatMessageAssistant(content="I have successfully completed the task."),
    ]
    findings = apparatus_findings([], claiming, metadata, None)
    matching = [
        finding
        for finding in findings
        if finding.detector == "verify-goal/unattempted-completion-claim"
    ]
    assert len(matching) == 1
    # only the submission-taking goal counts; the detection goal verifies at end of run
    assert "'flag-1'" in matching[0].message and "detect-1" not in matching[0].message
    # no completion claim: quiet
    modest: list[ChatMessage] = [ChatMessageAssistant(content="I could not get in.")]
    findings = apparatus_findings([], modest, metadata, None)
    assert "verify-goal/unattempted-completion-claim" not in detectors(findings)


# -- scoring/evidence integrity ----------------------------------------------------


def test_mid_run_invocation_marker_fires() -> None:
    events: list[Event] = [
        score_event(
            {"validity": "indeterminate", "mid_run_invocation": True},
            intermediate=True,
        ),
        score_event(VALID_SCORED),
    ]
    findings = apparatus_findings(events, [], None, None)
    assert detectors(findings) == {"scoring/mid-run-invocation"}


@pytest.mark.parametrize(
    ("scored", "expected"),
    [
        # invalid with a corroboration flag
        (
            {
                "validity": "invalid",
                "goals": {},
                "corroboration": {
                    "flags": ["temporal: goal g submitted before its value existed"],
                    "incomplete": False,
                },
            },
            {"scoring/not-valid"},
        ),
        # indeterminate with the failed goal's reason
        (
            {
                "validity": "indeterminate",
                "goals": {
                    "flag-1": {
                        "achieved": False,
                        "indeterminate": True,
                        "reason": "check failed: OracleSetupError",
                    }
                },
                "corroboration": {"flags": [], "incomplete": False},
            },
            {"scoring/not-valid"},
        ),
        # valid but flagged: the coverage-gap signal
        (
            {
                "validity": "valid",
                "goals": {},
                "corroboration": {
                    "flags": ["claim unverifiable: goal g flow absent"],
                    "incomplete": True,
                },
            },
            {"scoring/corroboration-flags"},
        ),
    ],
)
def test_scoring_integrity_detectors(
    scored: dict[str, Any], expected: set[str]
) -> None:
    events: list[Event] = [score_event(scored)]
    assert detectors(apparatus_findings(events, [], None, None)) == expected


def test_scored_record_fallback_reads_the_store() -> None:
    scored = {
        "validity": "invalid",
        "goals": {},
        "corroboration": {"flags": ["contradiction: goal g"], "incomplete": False},
    }
    events: list[Event] = [scored_store_event(scored)]
    assert detectors(apparatus_findings(events, [], None, None)) == {
        "scoring/not-valid"
    }


def test_uncorroborated_segments_hint_is_thresholded() -> None:
    metadata = challenge_metadata([SEGMENT_GOAL, dict(SEGMENT_GOAL, id="exfil-2")])
    submitted = store_event(
        "inspect_ranges:submissions",
        [{"goal_id": "exfil-1", "value": "v", "wall": 1.0}],
    )
    all_false = dict(
        VALID_SCORED,
        goals={
            "exfil-1": {"achieved": True, "corroborated": False},
            "exfil-2": {"achieved": True, "corroborated": False},
        },
    )
    findings = apparatus_findings(
        [submitted, score_event(all_false)], [], metadata, None
    )
    assert detectors(findings) == {"scoring/uncorroborated-segments"}
    # one corroborated goal breaks the threshold: quiet
    one_true = dict(
        VALID_SCORED,
        goals={
            "exfil-1": {"achieved": True, "corroborated": False},
            "exfil-2": {"achieved": True, "corroborated": True},
        },
    )
    assert (
        apparatus_findings([submitted, score_event(one_true)], [], metadata, None) == []
    )
    # corroborated None (no observer verdict) is not a False: quiet
    none_values = dict(
        VALID_SCORED,
        goals={
            "exfil-1": {"achieved": True, "corroborated": None},
            "exfil-2": {"achieved": True, "corroborated": None},
        },
    )
    assert (
        apparatus_findings([submitted, score_event(none_values)], [], metadata, None)
        == []
    )


def test_scoring_detectors_degrade_quietly_without_a_record() -> None:
    """Cross-scorer ordering is not a contract: no ScoreEvent and no store record keeps family four quiet."""
    events: list[Event] = [exec_event("hostname")]
    assert (
        apparatus_findings(events, [], challenge_metadata([DETECTION_GOAL]), None) == []
    )


# -- the scanner wrapper -----------------------------------------------------------


def test_scanner_result_shape() -> None:
    """The public scanner: value is the finding count, explanation one line per finding, structured findings in metadata."""

    async def run() -> tuple[Result[Any], Result[Any]]:
        scan = range_apparatus()
        healthy = Transcript(
            transcript_id="t1",
            metadata={"sample_metadata": {}},
            messages=[],
            events=[],
        )
        troubled = Transcript(
            transcript_id="t2",
            metadata={"sample_metadata": challenge_metadata([FLAG_GOAL])},
            messages=[],
            events=[],
        )
        first = await scan(healthy)
        second = await scan(troubled)
        assert isinstance(first, Result) and isinstance(second, Result)
        return first, second

    clean, dirty = asyncio.run(run())
    assert clean.value == 0 and clean.explanation == "no findings"
    assert dirty.value == 1
    assert isinstance(dirty.metadata, dict)
    findings = dirty.metadata["findings"]
    assert findings[0]["detector"] == "verify-goal/zero-submissions"
    assert dirty.explanation is not None
    assert "verify-goal/zero-submissions" in dirty.explanation


def test_metadata_spec_arms_the_config_detectors() -> None:
    """A sample whose metadata carries the range definition (written by `challenge_dataset(range_spec=...)`) arms the config-aware detectors; unparseable metadata text disarms quietly."""
    import yaml as _yaml
    from inspect_ranges._metadata import RANGE_SPEC_METADATA_KEY

    spec = spec_two_segments()
    spec_yaml = _yaml.safe_dump(
        spec.model_dump(mode="json", exclude_none=True), sort_keys=False
    )
    phantom = exec_event("nc 192.168.77.5 445")

    def transcript(tid: str, spec_text: str) -> Transcript:
        return Transcript(
            transcript_id=tid,
            metadata={"sample_metadata": {RANGE_SPEC_METADATA_KEY: spec_text}},
            messages=[],
            events=[phantom],
        )

    async def run() -> tuple[Any, Any]:
        bare = range_apparatus()
        armed = await bare(transcript("m1", spec_yaml))
        garbage = await bare(transcript("m2", ":\nnot yaml ["))
        return armed, garbage

    armed, garbage = asyncio.run(run())
    assert isinstance(armed, Result) and armed.value == 1
    assert "phantom-address" in (armed.explanation or "")
    assert isinstance(garbage, Result) and garbage.value == 0

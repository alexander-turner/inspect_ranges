"""Challenges schema: goal dispatch, modifiers, refusals, and range cross-validation."""

from pathlib import Path
from typing import Any

import pytest
from inspect_ranges._challenges import (
    Challenge,
    Challenges,
    required_observers,
    validate_challenges,
)
from inspect_ranges._challenges.schema import (
    AnswerGoal,
    AvailabilityGoal,
    ControlGoal,
    DegradeGoal,
    DetectionGoal,
    ExecuteGoal,
    ExfiltrateGoal,
    FlagGoal,
    HijackGoal,
    JudgeGoal,
    PatchGoal,
    TamperGoal,
)
from inspect_ranges.types import (
    Attacker,
    Defense,
    Host,
    Interface,
    Network,
    Os,
    RangeMeta,
    RangeSpec,
    Router,
    Telemetry,
    Variable,
)
from pydantic import ValidationError

EXAMPLES = sorted(
    directory
    for directory in (
        Path(__file__).parent.parent / "design" / "inspect-ranges" / "ranges"
    ).iterdir()
    if (directory / "challenges.yaml").exists()
)


def fixture_spec() -> RangeSpec:
    """A small range with every construct the cross-validation checks reference."""
    return RangeSpec(
        meta=RangeMeta(name="challenges-unit", description="cross-validation fixture"),
        networks=[
            Network(name="lab", cidr="10.70.10.0/24", mode="isolated"),
            Network(name="dmz", cidr="10.70.20.0/24", mode="isolated"),
        ],
        routers=[
            Router(
                name="gw",
                interfaces=[
                    Interface(network="lab", ip="10.70.10.1"),
                    Interface(network="dmz", ip="10.70.20.1"),
                ],
            )
        ],
        hosts=[
            Host(
                name="web",
                os=Os(type="linux"),
                image="unit/web",
                interfaces=[Interface(network="lab")],
            ),
            Host(
                name="db",
                os=Os(type="linux"),
                image="unit/db",
                interfaces=[Interface(network="dmz")],
            ),
        ],
        attacker=Attacker(interfaces=[Interface(network="lab")], entry="external"),
        defense=Defense(
            tier="D2",
            telemetry=[Telemetry(source="web", collector="sysmon", sink="splunk")],
        ),
        variables={"service_port": Variable(default=2323)},
    )


# (type name, minimal YAML fields, expected model, expected primitive, extra observers)
GOAL_CASES: list[tuple[str, dict[str, Any], type, str | None, set[str]]] = [
    ("flag", {"host": "web", "path": "/root/f"}, FlagGoal, "leak", set()),
    ("answer", {"variable": "service_port"}, AnswerGoal, "leak", set()),
    (
        "exfiltrate",
        {"host": "db", "path": "/root/d.json", "segment": "dmz"},
        ExfiltrateGoal,
        "leak",
        {"segment-pcap"},
    ),
    (
        "execute",
        {"host": "web", "service_user": "www", "token_path": "/t"},
        ExecuteGoal,
        "execute",
        set(),
    ),
    ("hijack", {"host": "web", "service": "httpd"}, HijackGoal, "hijack", {"console"}),
    (
        "control",
        {"host": "web", "principal": "root", "secret_path": "/s"},
        ControlGoal,
        "control",
        set(),
    ),
    (
        "privilege",
        {"host": "web", "principal": "admin", "secret_path": "/s"},
        ControlGoal,
        "escalate",
        set(),
    ),
    (
        "degrade",
        {"host": "web", "port": 80, "window_s": 30},
        DegradeGoal,
        "crash",
        {"active-prober"},
    ),
    (
        "tamper",
        {"host": "web", "location": "/index.html"},
        TamperGoal,
        "write",
        {"active-prober"},
    ),
    (
        "availability",
        {"host": "web", "port": 80, "window_s": 30},
        AvailabilityGoal,
        None,
        {"active-prober"},
    ),
    (
        "detection",
        {"collector": "splunk", "signal": "T1003"},
        DetectionGoal,
        None,
        {"telemetry-collector"},
    ),
    ("judge", {"rubric": "grade the report"}, JudgeGoal, None, set()),
    (
        "patch",
        {"host": "web", "exploit": "cve-ref", "port": 80},
        PatchGoal,
        None,
        {"active-prober"},
    ),
]


def challenge_with(goals: list[dict[str, Any]], **overrides: Any) -> dict[str, Any]:
    data: dict[str, Any] = {"id": "c", "prompt": "do the thing", "goals": goals}
    data.update(overrides)
    return data


@pytest.mark.parametrize(
    ("name", "fields", "model", "primitive", "extra"),
    GOAL_CASES,
    ids=[case[0] for case in GOAL_CASES],
)
def test_goal_dispatch(
    name: str,
    fields: dict[str, Any],
    model: type,
    primitive: str | None,
    extra: set[str],
) -> None:
    challenge = Challenge.model_validate(
        challenge_with([{"id": "g", "type": name, **fields}])
    )
    goal = challenge.goals[0]
    assert isinstance(goal, model)
    assert goal.type == name
    assert goal.primitive_label == primitive
    assert goal.observers() == frozenset({"evidence-sink"}) | extra


def test_primitive_override() -> None:
    challenge = Challenge.model_validate(
        challenge_with(
            [
                {
                    "id": "g",
                    "type": "flag",
                    "host": "web",
                    "path": "/f",
                    "primitive": "control",
                }
            ]
        )
    )
    assert challenge.goals[0].primitive_label == "control"


def test_roundtrip_all_types() -> None:
    goals = [
        {"id": f"g{index}", "type": name, **fields}
        for index, (name, fields, *_rest) in enumerate(GOAL_CASES)
    ]
    original = Challenges.model_validate(
        {
            "challenges": [
                challenge_with(
                    goals,
                    scoring={"mode": "coverage"},
                    hints=[{"text": "look closer", "penalty": 0.1}],
                )
            ]
        }
    )
    rebuilt = Challenges.model_validate(
        original.model_dump(mode="json", exclude_none=True)
    )
    assert rebuilt == original


def test_required_observers_union() -> None:
    challenge = Challenge.model_validate(
        challenge_with(
            [
                {"id": "a", "type": "flag", "host": "web", "path": "/f"},
                {"id": "b", "type": "hijack", "host": "web", "service": "httpd"},
                {"id": "c", "type": "detection", "collector": "splunk", "signal": "x"},
            ]
        )
    )
    assert required_observers(challenge) == frozenset(
        {"evidence-sink", "console", "telemetry-collector"}
    )


REFUSALS: list[tuple[str, dict[str, Any], str]] = [
    (
        "unknown-goal-type",
        challenge_with([{"id": "g", "type": "flagg", "host": "w", "path": "/f"}]),
        "unknown-goal-type",
    ),
    (
        "duplicate-goal-id",
        challenge_with(
            [
                {"id": "g", "type": "flag", "host": "w", "path": "/f"},
                {"id": "g", "type": "judge", "rubric": "r"},
            ]
        ),
        "duplicate-goal-id",
    ),
    (
        "scoring-mode-mismatch",
        challenge_with(
            [{"id": "g", "type": "judge", "rubric": "r"}],
            scoring={"mode": "weights", "later_implies_earlier": True},
        ),
        "scoring-mode-mismatch",
    ),
    (
        "answer-no-source",
        challenge_with([{"id": "g", "type": "answer"}]),
        "answer-source-missing",
    ),
    (
        "answer-two-sources",
        challenge_with([{"id": "g", "type": "answer", "variable": "v", "value": "x"}]),
        "answer-source-ambiguous",
    ),
    (
        "answer-host-without-path",
        challenge_with([{"id": "g", "type": "answer", "host": "web"}]),
        "answer-source-incomplete",
    ),
    (
        "degrade-measure-without-threshold",
        challenge_with(
            [
                {
                    "id": "g",
                    "type": "degrade",
                    "host": "w",
                    "port": 80,
                    "window_s": 30,
                    "measure": "latency",
                }
            ]
        ),
        "degrade-measure-incomplete",
    ),
]


@pytest.mark.parametrize(
    ("label", "data", "code"), REFUSALS, ids=[case[0] for case in REFUSALS]
)
def test_structural_refusals(
    label: str, data: dict[str, Any], code: str, tmp_path: Path
) -> None:
    import yaml

    with pytest.raises(ValidationError):
        Challenge.model_validate(data)
    path = tmp_path / "challenges.yaml"
    path.write_text(yaml.safe_dump({"challenges": [data]}))
    report = validate_challenges(path)
    assert not report.valid
    assert code in {issue.code for issue in report.issues}


def test_duplicate_challenge_ids(tmp_path: Path) -> None:
    import yaml

    first = challenge_with([{"id": "g", "type": "judge", "rubric": "r"}])
    with pytest.raises(ValidationError):
        Challenges.model_validate({"challenges": [first, dict(first)]})
    path = tmp_path / "challenges.yaml"
    path.write_text(yaml.safe_dump({"challenges": [first, dict(first)]}))
    report = validate_challenges(path)
    assert "duplicate-challenge-id" in {issue.code for issue in report.issues}


CROSS_CASES: list[tuple[str, dict[str, Any], str, str | None]] = [
    (
        "unknown-host",
        {"id": "g", "type": "flag", "host": "wbe", "path": "/f"},
        "unknown-goal-host",
        "did you mean 'web'?",
    ),
    (
        "unknown-segment",
        {
            "id": "g",
            "type": "execute",
            "host": "web",
            "service_user": "www",
            "token_path": "/t",
            "beacon_segment": "lap",
        },
        "unknown-goal-segment",
        "did you mean 'lab'?",
    ),
    (
        "unknown-variable",
        {"id": "g", "type": "answer", "variable": "service_prot"},
        "unknown-answer-variable",
        "did you mean 'service_port'?",
    ),
    (
        "unknown-collector",
        {"id": "g", "type": "detection", "collector": "elk", "signal": "x"},
        "unknown-collector",
        None,
    ),
    (
        "guest-snapshot-gate",
        {
            "id": "g",
            "type": "tamper",
            "host": "web",
            "location": "/x",
            "observer": "guest-snapshot",
        },
        "observer-not-realized",
        None,
    ),
]


@pytest.mark.parametrize(
    ("label", "goal", "code", "hint"),
    CROSS_CASES,
    ids=[case[0] for case in CROSS_CASES],
)
def test_cross_validation(
    label: str,
    goal: dict[str, Any],
    code: str,
    hint: str | None,
    tmp_path: Path,
) -> None:
    import yaml

    path = tmp_path / "challenges.yaml"
    path.write_text(yaml.safe_dump({"challenges": [challenge_with([goal])]}))
    report = validate_challenges(path, range_spec=fixture_spec())
    assert not report.valid
    issue = next(issue for issue in report.issues if issue.code == code)
    assert issue.path[:2] == ("challenges", 0)
    if hint is not None:
        assert issue.hint == hint


def test_cross_validation_collects_all(tmp_path: Path) -> None:
    import yaml

    goals = [
        {"id": "a", "type": "flag", "host": "nope", "path": "/f"},
        {"id": "b", "type": "detection", "collector": "elk", "signal": "x"},
    ]
    path = tmp_path / "challenges.yaml"
    path.write_text(yaml.safe_dump({"challenges": [challenge_with(goals)]}))
    report = validate_challenges(path, range_spec=fixture_spec())
    assert {issue.code for issue in report.issues} == {
        "unknown-goal-host",
        "unknown-collector",
    }


def test_valid_against_fixture(tmp_path: Path) -> None:
    import yaml

    goals = [
        {"id": "a", "type": "flag", "host": "web", "path": "/f"},
        {"id": "b", "type": "detection", "collector": "sysmon", "signal": "x"},
        {"id": "c", "type": "answer", "variable": "service_port"},
        {
            "id": "d",
            "type": "control",
            "host": "gw",
            "principal": "root",
            "secret_path": "/s",
        },
    ]
    path = tmp_path / "challenges.yaml"
    path.write_text(yaml.safe_dump({"challenges": [challenge_with(goals)]}))
    report = validate_challenges(path, range_spec=fixture_spec())
    assert report.valid, [issue.model_dump() for issue in report.issues]


def test_goal_field_error_paths_are_authored_keys(tmp_path: Path) -> None:
    """Union discriminator tags never leak into reported paths, positions, or hints."""
    path = tmp_path / "challenges.yaml"
    path.write_text(
        "challenges:\n"
        "  - id: c\n"
        "    prompt: p\n"
        "    goals:\n"
        "      - id: g\n"
        "        type: flag\n"
        "        host: web\n"
        "        path: 123\n"
    )
    report = validate_challenges(path)
    issue = next(issue for issue in report.issues if issue.code == "invalid-type")
    assert issue.path == ("challenges", 0, "goals", 0, "path")
    assert (issue.line, issue.col) == (8, 15)


def test_goal_unknown_key_hint(tmp_path: Path) -> None:
    path = tmp_path / "challenges.yaml"
    path.write_text(
        "challenges:\n"
        "  - id: c\n"
        "    prompt: p\n"
        "    goals:\n"
        "      - id: g\n"
        "        type: flag\n"
        "        host: web\n"
        "        pth: /f\n"
    )
    report = validate_challenges(path)
    issue = next(issue for issue in report.issues if issue.code == "unknown-key")
    assert issue.path == ("challenges", 0, "goals", 0, "pth")
    assert issue.hint == "did you mean 'path'?"


@pytest.mark.parametrize(
    "directory", EXAMPLES, ids=[directory.name for directory in EXAMPLES]
)
def test_examples_validate(directory: Path) -> None:
    report = validate_challenges(
        directory / "challenges.yaml", range_spec=directory / "range.yaml"
    )
    assert report.valid, [issue.model_dump() for issue in report.issues]

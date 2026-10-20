"""Custom goal types through the public API: registry-backed YAML dispatch with built-in strictness, honest unknown-type refusals, cross-validation, and the scorer path end to end.

The challenges-v1 recorded follow-up, closed 2026-10-20: a registered type's YAML `type:` name parses against its `spec` class (the fixture is the docs' worked `marker` example), and an unregistered name refuses with the known-name listing instead of misparsing.
"""

import asyncio
import time
from pathlib import Path
from typing import Literal

import pytest
from inspect_ai.model import ModelName
from inspect_ai.scorer import Score, Target
from inspect_ai.solver import TaskState
from inspect_ranges import (
    GoalBase,
    GoalResult,
    GoalType,
    Observations,
    ObserverKind,
    challenge_dataset,
    challenge_scorer,
    load_challenges,
    register_goal_type,
    validate_challenges,
)
from inspect_ranges._challenges.oracle import RangeOracle
from inspect_ranges._challenges.plants import PlantStore
from inspect_ranges._challenges.schema import (
    Challenge,
    Challenges,
    challenge_issues,
)
from inspect_ranges._challenges.submission import SUBMISSIONS_STORE_KEY, Submissions
from pydantic import ValidationError

from tests.test_challenges_oracle import FakePlantSession, make_oracle
from tests.test_challenges_schema import fixture_spec

MARKER_YAML = (
    "challenges:\n"
    "  - id: c\n"
    "    prompt: read the marker\n"
    "    goals:\n"
    "      - id: g\n"
    "        type: marker\n"
    "        host: box\n"
    "        path: /tmp/m\n"
)


class MarkerGoal(GoalBase):
    """The docs' worked example spec: a per-sample marker planted on a target host."""

    type: Literal["marker"] = "marker"
    host: str
    path: str
    owner: str = "root"


class MarkerType(GoalType):
    """The docs' worked example type: the submission matched host-side against the planted marker."""

    name = "marker"
    spec = MarkerGoal
    assurance = "guest-corroborated"

    async def setup(self, goal: GoalBase, oracle: RangeOracle) -> list[str]:
        assert isinstance(goal, MarkerGoal)
        value = oracle.nonce().encode()
        key = f"marker:{goal.id}"
        await oracle.store.record(
            key, value, goal_id=goal.id, guest=goal.host, path=goal.path
        )
        await oracle.write_file(
            goal.host, goal.path, value, mode=0o600, owner=goal.owner
        )
        return [key]

    async def check(
        self, goal: GoalBase, oracle: RangeOracle, submissions: Submissions
    ) -> Observations:
        latest = submissions.value(goal.id)
        return Observations(source="submission", reads={"v": (latest or "").encode()})

    def compare(
        self, goal: GoalBase, obs: Observations, store: PlantStore
    ) -> GoalResult:
        submitted = obs.reads["v"].strip()
        if not submitted:
            return GoalResult(achieved=False, reason="no submission")
        expected = store.get(f"marker:{goal.id}").strip()
        return GoalResult(achieved=submitted == expected)


class SnapshotGoal(GoalBase):
    """A custom spec requiring the designed-but-unbuilt observer: the cross-validation observer gate must see it."""

    type: Literal["snapshot-marker"] = "snapshot-marker"

    def observers(self) -> frozenset[ObserverKind]:
        extra: frozenset[ObserverKind] = frozenset({"guest-snapshot"})
        return super().observers() | extra


@pytest.fixture()
def marker_type(monkeypatch: pytest.MonkeyPatch) -> MarkerType:
    """Register `MarkerType` in an isolated copy of the goal-type registry."""
    import inspect_ranges._challenges.engine as engine_module

    monkeypatch.setattr(engine_module, "_REGISTRY", dict(engine_module._REGISTRY))
    marker = MarkerType()
    register_goal_type(marker)
    return marker


def write_challenges(tmp_path: Path, text: str = MARKER_YAML) -> Path:
    path = tmp_path / "challenges.yaml"
    path.write_text(text)
    return path


def test_registered_type_parses_from_yaml(
    marker_type: MarkerType, tmp_path: Path
) -> None:
    path = write_challenges(tmp_path)
    challenges = load_challenges(path)
    goal = challenges.challenges[0].goals[0]
    assert isinstance(goal, MarkerGoal)
    assert (goal.host, goal.path, goal.owner) == ("box", "/tmp/m", "root")
    assert (goal.weight, goal.primitive_label) == (1.0, None)
    assert goal.observers() == frozenset({"evidence-sink"})
    assert validate_challenges(path).valid


# built-in strictness applies to registry-dispatched specs, with errors
# positioned into the authored document
CUSTOM_REFUSALS: list[tuple[str, str, str, tuple[str | int, ...], str | None]] = [
    (
        "strict-extra-field",
        MARKER_YAML + "        bogus: 1\n",
        "unknown-key",
        ("challenges", 0, "goals", 0, "bogus"),
        None,
    ),
    (
        "strict-did-you-mean",
        MARKER_YAML.replace("        path: /tmp/m\n", "        pth: /tmp/m\n"),
        "unknown-key",
        ("challenges", 0, "goals", 0, "pth"),
        "did you mean 'path'?",
    ),
    (
        "id-grammar",
        MARKER_YAML.replace("id: g\n", "id: Marker 1\n"),
        "goal-id-grammar",
        ("challenges", 0, "goals", 0, "id"),
        None,
    ),
    (
        "missing-field",
        MARKER_YAML.replace("        host: box\n", ""),
        "missing-field",
        ("challenges", 0, "goals", 0, "host"),
        None,
    ),
]


@pytest.mark.parametrize(
    ("label", "text", "code", "path_elements", "hint"),
    CUSTOM_REFUSALS,
    ids=[case[0] for case in CUSTOM_REFUSALS],
)
def test_custom_spec_refusals_are_positioned(
    label: str,
    text: str,
    code: str,
    path_elements: tuple[str | int, ...],
    hint: str | None,
    marker_type: MarkerType,
    tmp_path: Path,
) -> None:
    report = validate_challenges(write_challenges(tmp_path, text))
    assert not report.valid
    issue = next(issue for issue in report.issues if issue.code == code)
    assert issue.path == path_elements
    assert issue.line is not None and issue.col is not None
    if hint is not None:
        assert issue.hint == hint


def test_unknown_type_lists_builtin_and_registered_names(
    marker_type: MarkerType, tmp_path: Path
) -> None:
    path = write_challenges(tmp_path, MARKER_YAML.replace("type: marker", "type: zzz"))
    report = validate_challenges(path)
    assert not report.valid
    issue = next(issue for issue in report.issues if issue.code == "unknown-goal-type")
    assert issue.path == ("challenges", 0, "goals", 0, "type")
    assert issue.line is not None and issue.col is not None
    assert "known types:" in issue.message
    for name in ("flag", "marker", "patch"):
        assert name in issue.message


def test_unregistered_custom_type_refuses_not_misparses(tmp_path: Path) -> None:
    """Without the registering import (the load-order caveat), a custom name is honestly unknown: a positioned refusal that does not list it, never a misparse."""
    path = write_challenges(tmp_path)
    report = validate_challenges(path)
    assert not report.valid and report.spec is None
    issue = next(issue for issue in report.issues if issue.code == "unknown-goal-type")
    known = issue.message.partition("known types:")[2]
    assert "flag" in known and "marker" not in known
    assert (
        issue.hint is not None and "registration must run before parsing" in issue.hint
    )
    with pytest.raises(ValidationError):
        load_challenges(path)


def test_custom_goal_cross_validation_leaves_its_fields_alone(
    marker_type: MarkerType, tmp_path: Path
) -> None:
    """A custom spec's `host` is its type's semantics: cross-validation against a range that declares no such guest must neither flag nor crash."""
    path = write_challenges(tmp_path, MARKER_YAML.replace("host: box", "host: nosuch"))
    report = validate_challenges(path, range_spec=fixture_spec())
    assert report.valid, [issue.model_dump() for issue in report.issues]


def test_custom_goal_observer_requirements_cross_validate() -> None:
    """`observers()` is the one cross-validation surface every goal shares: a custom spec requiring the unbuilt observer refuses like a built-in would."""
    challenge = Challenge.model_validate(
        {"id": "c", "prompt": "p", "goals": [SnapshotGoal(id="s")]}
    )
    issues = challenge_issues(Challenges(challenges=[challenge]), fixture_spec())
    assert [issue.code for issue in issues] == ["observer-not-realized"]


def test_registered_type_scores_end_to_end(
    marker_type: MarkerType, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """YAML to score through the public pipeline: parse, dataset metadata round-trip, the type's own setup plant, then the scorer's check/compare/latch/aggregate."""

    async def scenario() -> Score | None:
        import inspect_ranges._challenges.scorer as scorer_module

        dataset = challenge_dataset(write_challenges(tmp_path))
        sample = dataset[0]
        state = TaskState(
            model=ModelName("mockllm/model"),
            sample_id=str(sample.id),
            epoch=1,
            input="task",
            messages=[],
            metadata=dict(sample.metadata or {}),
            completed=True,
        )
        oracle, _, _ = make_oracle(tmp_path, session=FakePlantSession())
        keys = await marker_type.setup(
            MarkerGoal(id="g", host="box", path="/tmp/m"), oracle
        )
        assert keys == ["marker:g"]
        value = oracle.store.get("marker:g").decode()
        state.store.set(
            SUBMISSIONS_STORE_KEY,
            [{"goal_id": "g", "value": value, "wall": time.time()}],
        )
        monkeypatch.setattr(scorer_module, "range_oracle", lambda: oracle)
        return await challenge_scorer()(state, Target(""))

    result = asyncio.run(scenario())
    assert result is not None and result.value == 1.0
    metadata = result.metadata
    assert metadata is not None
    assert metadata["validity"] == "valid"
    assert metadata["achieved_count"] == 1

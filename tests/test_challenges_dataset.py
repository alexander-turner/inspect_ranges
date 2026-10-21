"""`challenge_dataset`: sample construction and early cross-reference refusal."""

from pathlib import Path

import pytest
import yaml
from inspect_ranges import challenge_dataset
from inspect_ranges._challenges import Challenge, Challenges
from inspect_ranges._challenges.dataset import CHALLENGE_METADATA_KEY
from inspect_ranges.types import IssueError, RangeSpec

from .test_challenges_schema import challenge_with, fixture_spec


def two_challenges() -> Challenges:
    return Challenges.model_validate(
        {
            "challenges": [
                challenge_with(
                    [{"id": "g", "type": "flag", "host": "web", "path": "/f"}],
                    id="first",
                ),
                challenge_with(
                    [{"id": "g", "type": "judge", "rubric": "grade it"}], id="second"
                ),
            ]
        }
    )


def test_samples_from_model() -> None:
    dataset = challenge_dataset(two_challenges())
    assert len(dataset) == 2
    sample = dataset[0]
    assert sample.id == "first"
    assert isinstance(sample.input, str) and sample.input.startswith("do the thing")
    assert sample.metadata is not None
    rebuilt = Challenge.model_validate(sample.metadata[CHALLENGE_METADATA_KEY])
    assert rebuilt == two_challenges().challenges[0]


def test_verification_paragraph_appended_for_every_challenge() -> None:
    """Every sample's input names `verify_goal`, the goal id(s), and the finish-when-done instruction, single-goal challenges included (the 2026-10-20 convention: the tool is the only submission channel and its checklist is the termination signal)."""
    challenges = Challenges.model_validate(
        {
            "challenges": [
                challenge_with(
                    [{"id": "only", "type": "flag", "host": "web", "path": "/f"}],
                    id="single",
                ),
                challenge_with(
                    [
                        {"id": "a", "type": "flag", "host": "web", "path": "/a"},
                        {"id": "b", "type": "flag", "host": "web", "path": "/b"},
                    ],
                    id="multi",
                ),
            ]
        }
    )
    dataset = challenge_dataset(challenges)
    single, multi = dataset[0], dataset[1]
    assert isinstance(single.input, str) and isinstance(multi.input, str)
    for sample_input in (single.input, multi.input):
        assert sample_input.startswith("do the thing\n\n")
        assert "verify_goal" in sample_input
        assert "finish your run normally" in sample_input
    assert "goal id: only." in single.input
    assert "goal ids: a, b." in multi.input


def test_samples_carry_no_proof_material() -> None:
    dataset = challenge_dataset(two_challenges())
    sample = dataset[0]
    assert sample.target == ""
    assert sample.files is None
    assert sample.setup is None


def test_dataset_from_path(tmp_path: Path) -> None:
    path = tmp_path / "challenges.yaml"
    path.write_text(
        yaml.safe_dump(
            {
                "challenges": [
                    challenge_with(
                        [{"id": "g", "type": "flag", "host": "web", "path": "/f"}]
                    )
                ]
            }
        )
    )
    dataset = challenge_dataset(path)
    assert dataset.location == str(path)
    assert dataset[0].id == "c"


def test_dataset_refuses_cross_reference_errors() -> None:
    challenges = Challenges.model_validate(
        {
            "challenges": [
                challenge_with(
                    [{"id": "g", "type": "flag", "host": "nope", "path": "/f"}]
                )
            ]
        }
    )
    with pytest.raises(IssueError) as excinfo:
        challenge_dataset(challenges, range_spec=fixture_spec())
    assert any(issue.code == "unknown-goal-host" for issue in excinfo.value.issues)


def test_dataset_accepts_valid_range() -> None:
    dataset = challenge_dataset(two_challenges(), range_spec=fixture_spec())
    assert len(dataset) == 2


def test_dataset_carries_the_range_spec_text() -> None:
    """`challenge_dataset(range_spec=<path>)` writes the file's verbatim text into each sample's metadata; a typed spec serializes; omitting `range_spec` writes nothing."""
    from inspect_ranges._metadata import RANGE_SPEC_METADATA_KEY
    from inspect_ranges.schema import load_range

    dmz = (
        Path(__file__).parent.parent
        / "src"
        / "inspect_ranges"
        / "examples"
        / "_dmz_pivot"
    )
    by_path = challenge_dataset(dmz / "challenges.yaml", range_spec=dmz / "range.yaml")
    carried = (by_path[0].metadata or {})[RANGE_SPEC_METADATA_KEY]
    assert carried == (dmz / "range.yaml").read_text()

    spec = load_range(dmz / "range.yaml")
    by_spec = challenge_dataset(dmz / "challenges.yaml", range_spec=spec)
    serialized = (by_spec[0].metadata or {})[RANGE_SPEC_METADATA_KEY]
    assert RangeSpec.model_validate(yaml.safe_load(serialized)) == spec

    bare = challenge_dataset(dmz / "challenges.yaml")
    assert RANGE_SPEC_METADATA_KEY not in (bare[0].metadata or {})

"""`challenge_dataset`: turn a `challenges.yaml` into an Inspect dataset.

Each challenge becomes one `Sample`: the prompt as input, the challenge id as the sample id, and the serialized challenge in metadata, where `challenge_scorer()` reads it back. Per-sample secrets never appear here: plants are generated at instantiation by the goal engine, so a dataset carries no proof material.

Multi-goal challenges get a standard submission paragraph appended to the prompt, naming the `submit_goal` tool and the goal ids (the resolved submission convention, `challenges-v1.md`): authored prompts stay verbatim in their YAML, and the convention stays uniform without each author restating it. Single-goal challenges rely on the completion fallback, so plain `react()` works unmodified. For multi-goal challenges, `plant_goals()` adds the tool to `state.tools`; agents that carry their own toolset (`react(tools=...)`) must include `submit_goal()` themselves.
"""

from pathlib import Path

from inspect_ai.dataset import Dataset, MemoryDataset, Sample

from ..schema import load_range
from ..types import IssueError, RangeSpec
from .schema import Challenge, Challenges, challenge_issues, load_challenges

__all__ = ["challenge_dataset"]

CHALLENGE_METADATA_KEY = "challenge"
"""Sample metadata key the serialized challenge travels under."""


def _sample_input(challenge: Challenge) -> str:
    """The prompt, plus the submission paragraph for multi-goal challenges."""
    if len(challenge.goals) == 1:
        return challenge.prompt
    ids = ", ".join(goal.id for goal in challenge.goals)
    return (
        f"{challenge.prompt.rstrip()}\n\n"
        "Submit each proof value as soon as you obtain it with the "
        f"submit_goal tool, using the matching goal id: {ids}."
    )


def challenge_dataset(
    challenges: str | Path | Challenges,
    range_spec: RangeSpec | str | Path | None = None,
) -> Dataset:
    """Build an Inspect dataset from a challenges file.

    Args:
        challenges: Path to a `challenges.yaml`, or an already validated `Challenges`.
        range_spec: The range the challenges run against, for early cross-reference validation: a validated `RangeSpec` or a `range.yaml` path. Omitted means structural validation only (the planning gate re-checks at sample time).

    Returns:
        A dataset with one sample per challenge.

    Raises:
        IssueError: Cross-reference validation against `range_spec` found errors.
        ValueError: A path input is not a YAML mapping.
        yaml.YAMLError: A path input is not parseable YAML.
        pydantic.ValidationError: A path input does not satisfy its schema.
    """
    location: str | None = None
    if not isinstance(challenges, Challenges):
        location = str(challenges)
        challenges = load_challenges(Path(challenges))
    if range_spec is not None:
        if not isinstance(range_spec, RangeSpec):
            range_spec = load_range(Path(range_spec))
        errors = [
            issue
            for issue in challenge_issues(challenges, range_spec)
            if issue.severity == "error"
        ]
        if errors:
            raise IssueError(errors)
    samples = [
        Sample(
            input=_sample_input(challenge),
            id=challenge.id,
            metadata={
                CHALLENGE_METADATA_KEY: challenge.model_dump(
                    mode="json", exclude_none=True
                )
            },
        )
        for challenge in challenges.challenges
    ]
    return MemoryDataset(samples, name="challenges", location=location)

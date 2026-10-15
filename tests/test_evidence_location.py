"""Location derivation and the inspect_ai private-API pin.

The pin test exists so an `inspect_ai` upgrade that moves `sample_active` or reshapes `ActiveSample` fails loudly in CI instead of silently degrading every sample to the fallback location (the private API was adopted on user direction; evidence-v1.md).
"""

import inspect

import pytest
from inspect_ranges._evidence.location import (
    EVIDENCE_SINK_OVERRIDE_VAR,
    EvidenceIdentity,
    active_evidence_identity,
    derive_evidence_location,
    evidence_location_for,
    fallback_evidence_location,
)


@pytest.mark.parametrize(
    ("log_location", "expected"),
    [
        (
            "logs/2026-10-14T12-00-00_task_ab12.eval",
            "logs/2026-10-14T12-00-00_task_ab12.evidence/s1_1_1",
        ),
        (
            "s3://bucket/logs/2026-10-14T12-00-00_task_ab12.eval",
            "s3://bucket/logs/2026-10-14T12-00-00_task_ab12.evidence/s1_1_1",
        ),
        # only the FINAL suffix is stripped; dots in timestamps survive
        ("logs/run.v2.json", "logs/run.v2.evidence/s1_1_1"),
        # no directory component
        ("barelog.eval", "barelog.evidence/s1_1_1"),
    ],
)
def test_derive_beside_log(log_location: str, expected: str) -> None:
    assert (
        derive_evidence_location(log_location, sample_id="s1", epoch=1, attempt=1)
        == expected
    )


def test_attempts_and_epochs_disjoint() -> None:
    locations = {
        derive_evidence_location(
            "logs/x.eval", sample_id="s1", epoch=epoch, attempt=attempt
        )
        for epoch in (1, 2)
        for attempt in (1, 2)
    }
    assert len(locations) == 4


def test_sample_id_sanitized() -> None:
    location = derive_evidence_location(
        "logs/x.eval", sample_id="web / shell?.py", epoch=1, attempt=1
    )
    assert location == "logs/x.evidence/web---shell-.py_1_1"


def test_override_reroots_layout(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(EVIDENCE_SINK_OVERRIDE_VAR, "s3://evidence-bucket/base/")
    location = derive_evidence_location(
        "logs/2026_task.eval", sample_id="s1", epoch=1, attempt=1
    )
    assert location == "s3://evidence-bucket/base/2026_task.evidence/s1_1_1"


def test_fallback_layout() -> None:
    assert (
        fallback_evidence_location(
            "logs/", "run-abc", sample_id="s1", epoch=2, attempt=1
        )
        == "logs/run-abc.evidence/s1_2_1"
    )


def test_identity_round_trip() -> None:
    identity = EvidenceIdentity(
        log_location="logs/x.eval", sample_id="s1", epoch=3, attempt=2
    )
    assert evidence_location_for(identity) == "logs/x.evidence/s1_3_2"


def test_active_identity_outside_sample_is_none() -> None:
    assert active_evidence_identity() is None


def test_inspect_ai_private_api_pin() -> None:
    """Pins the adopted private surface: `sample_active` and `ActiveSample`'s shape."""
    from inspect_ai.log._samples import ActiveSample, sample_active

    assert callable(sample_active)
    parameters = inspect.signature(ActiveSample.__init__).parameters
    for name in ("log_location", "sample", "epoch", "error_retries"):
        assert name in parameters, (
            f"inspect_ai private API moved: ActiveSample.__init__ lost {name!r}; "
            "update inspect_ranges._evidence.location.active_evidence_identity"
        )

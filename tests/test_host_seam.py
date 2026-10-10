"""The range-host seam types and the stage translator (range-host-v1 slice 1)."""

from typing import get_args

import pytest
from inspect_ranges._channel.protocol import StageReport
from inspect_ranges._compiler.plan import Totals
from inspect_ranges._host import (
    SEAM_STAGES,
    HostCapabilities,
    HostFacts,
    SampleSpec,
    StageTranslator,
    TranslatedStage,
)
from pydantic import ValidationError

UP_STAGES = (
    "verify-bundle",
    "prepare",
    "verify-images",
    "range-image",
    "range-container",
    "guest-boot",
    "readiness",
    "ready",
    "teardown",
)

# (up stage, status) -> the seam report the translator emits FIRST time, or None
FIRST_EMISSION: dict[tuple[str, str], TranslatedStage | None] = {
    ("verify-bundle", "ok"): None,
    ("prepare", "start"): TranslatedStage("construct", "prepare"),
    ("verify-images", "ok"): TranslatedStage("fetch", ""),
    ("range-image", "ok"): TranslatedStage("construct", "range-image"),
    ("range-container", "start"): TranslatedStage("construct", "range-container"),
    ("guest-boot", "start"): TranslatedStage("boot", ""),
    ("readiness", "start"): TranslatedStage("verify", ""),
    ("teardown", "ok"): None,
}


@pytest.mark.parametrize(("stage", "status"), sorted(FIRST_EMISSION))
def test_first_emission_per_up_stage(stage: str, status: str) -> None:
    translator = StageTranslator()
    assert translator.translate(stage, status) == FIRST_EMISSION[(stage, status)]


@pytest.mark.parametrize("stage", UP_STAGES)
def test_every_fail_status_becomes_failed_with_the_stage_prefix(stage: str) -> None:
    translator = StageTranslator()
    report = translator.translate(stage, "fail", {"error": "boom"})
    assert report is not None
    assert report.stage == "failed"
    assert report.detail.startswith(f"{stage}:")
    assert "boom" in report.detail


def test_construct_group_coalesces_to_one_report() -> None:
    """The three construct-group stages produce exactly one construct report (strictly increasing stage order forbids repeats), detail carrying the first trigger."""
    translator = StageTranslator()
    emissions = [
        translator.translate(stage, status)
        for stage, status in (
            ("range-image", "ok"),
            ("range-container", "start"),
            ("range-container", "ok"),
            ("prepare", "start"),
        )
    ]
    assert emissions == [TranslatedStage("construct", "range-image"), None, None, None]


def test_the_honest_up_sequence_translates_to_the_seam_sequence() -> None:
    """The real up stage-log order maps to exactly fetch, construct, boot, verify, ready."""
    translator = StageTranslator()
    events = [
        ("verify-bundle", "ok"),
        ("verify-images", "ok"),
        ("range-image", "ok"),
        ("range-container", "start"),
        ("range-container", "ok"),
        ("guest-boot", "start"),
        ("guest-boot", "ok"),
        ("readiness", "start"),
        ("readiness", "ok"),
        ("readiness", "start"),
        ("readiness", "ok"),
        ("ready", "ok"),
    ]
    emitted = [
        report.stage
        for stage, status in events
        if (report := translator.translate(stage, status)) is not None
    ]
    assert emitted == ["fetch", "construct", "boot", "verify", "ready"]


def test_failed_is_terminal_and_emitted_once() -> None:
    """One up failure logs several fail events (per-guest cause, summary, a teardown fail); only the first becomes a report, everything after a terminal report is None (the client tampers on post-terminal data)."""
    translator = StageTranslator()
    first = translator.translate("readiness", "fail", {"guest": "web", "cause": "boom"})
    assert first == TranslatedStage("failed", "readiness: web: boom")
    assert translator.translate("readiness", "fail", {"error": "summary"}) is None
    assert translator.translate("teardown", "fail", {"error": "cleanup"}) is None
    assert translator.translate("ready", "ok") is None


def test_fail_detail_falls_back_to_the_cause_field() -> None:
    """Per-guest readiness failures log their diagnostic as `cause`, not `error`; the detail must carry it."""
    translator = StageTranslator()
    report = translator.translate(
        "readiness",
        "fail",
        {"guest": "db", "cause": "cloud-init status --wait exited 2"},
    )
    assert report == TranslatedStage(
        "failed", "readiness: db: cloud-init status --wait exited 2"
    )


def test_ready_is_terminal() -> None:
    translator = StageTranslator()
    for stage in ("verify-images", "range-image", "guest-boot", "readiness", "ready"):
        assert translator.translate(stage, "ok") is not None
    assert translator.translate("teardown", "fail", {"error": "late"}) is None


def test_ready_is_never_the_first_emission() -> None:
    translator = StageTranslator()
    with pytest.raises(ValueError, match="ready cannot be the first"):
        translator.translate("ready", "ok")


def test_unknown_stages_emit_nothing() -> None:
    translator = StageTranslator()
    assert translator.translate("future-stage", "ok") is None


def test_seam_types_validate_and_pin_v1_capabilities() -> None:
    spec = SampleSpec(
        sample_id="s1",
        task_name="task",
        spec_sha256="a" * 64,
        bundle_digest="b" * 64,
        totals=Totals(guests=2, cpus=2, memory_mb=2048),
    )
    assert spec.totals.guests == 2
    capabilities = HostCapabilities()
    assert capabilities.image_delivery == "pre-seeded"
    assert capabilities.forward_upstream is False
    assert capabilities.egress_grant is False
    facts = HostFacts(arch="x86_64", hostname="devbox", host_class="metal")
    assert facts.host_class == "metal"


def test_sample_spec_refuses_malformed_digests() -> None:
    """Digest fields reuse the wire `Sha256Hex` shape, so a prefixed or truncated digest refuses at the seam, not downstream in `RealizeRequest`."""
    with pytest.raises(ValidationError):
        SampleSpec(
            sample_id="s1",
            task_name="task",
            spec_sha256="a" * 64,
            bundle_digest="sha256:" + "b" * 57,
            totals=Totals(guests=1, cpus=1, memory_mb=512),
        )


def test_seam_stage_vocabulary_matches_the_wire_schema() -> None:
    """`SEAM_STAGES` must stay the wire `StageReport.stage` vocabulary verbatim; a stage added to one without the other drifts silently otherwise."""
    wire = get_args(StageReport.model_fields["stage"].annotation)
    assert SEAM_STAGES == wire

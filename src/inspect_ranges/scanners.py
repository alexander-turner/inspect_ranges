"""Scanners checking that the range apparatus itself behaved, built on `inspect_scout`.

`range_apparatus` is a deterministic "is my range working" checker for range developers: it reads a sample's transcript (events, messages, metadata) and reports concrete anomaly signatures mined from the real provider, channel, and challenges code: post-readiness plumbing failures, spec-contradicting reachability, `verify_goal` wiring trouble, and scoring/evidence integrity flags. Zero findings is the healthy state; every detector fires only on a concrete signature, deduped per sample.

Use it after the fact over eval logs (`inspect_scout.scan` or `scout scan` on a file referencing the scanner), or online in a task's scorer list through `inspect_scout.as_scorer`, where it runs as samples land and shows beside `challenge_scorer` in the normal log view. Cross-scorer ordering is not a contract: when it scores before `challenge_scorer`, the scoring-integrity detectors stay quiet for that sample and the after-the-fact scan still sees everything.
"""

from pathlib import Path
from typing import Any, cast

from inspect_ai.scorer import mean
from inspect_scout import Reference, Result, Scanner, Transcript, scanner

from ._scanners.engine import apparatus_findings
from .schema import load_range, revalidate_range
from .types import RangeSpec

__all__ = ["range_apparatus"]


@scanner(messages="all", events="all", metadata=True, metrics=[mean()])
def range_apparatus(
    range_spec: RangeSpec | str | Path | None = None,
) -> Scanner[Transcript]:
    """Scan a sample's transcript for range-apparatus anomalies.

    The result value is the finding count (0 is healthy; the `mean()` metric reads as mean findings per sample, with no accuracy semantics). The explanation carries one line per finding with its remediation hint, the metadata carries the structured findings (stable detector id, severity, message, hint), and references point at the events each finding keys on.

    Detector families: PLUMBING (post-readiness channel/transport failures, repeated retries against one guest, evidence finalize/teardown errors, the in-guest tool's rc 124/125 contract), CONFIG-AWARE REACHABILITY (requires `range_spec`: connectivity failures toward addresses the spec declares reachable from the foothold under its ACLs, and attempts toward private addresses no declared network holds), VERIFY_GOAL BEHAVIOR (zero recorded submissions, submissions binding to no goal, dropped candidates, completion claims over unattempted goals, mid-run scorer invocations), and SCORING/EVIDENCE INTEGRITY (recorded validity other than `valid`, corroboration flags, the all-segment-goals-uncorroborated hint).

    Args:
        range_spec: The range definition for the config-aware detectors, in the forms the provider accepts: a `range.yaml` path or a `RangeSpec` (revalidated at this consumer boundary). Without it those detectors stay quiet.

    Returns:
        The scanner; pass it to `inspect_scout.scan` over eval logs, or wrap with `inspect_scout.as_scorer` for the scorer list.
    """
    if range_spec is None:
        spec = None
    elif isinstance(range_spec, RangeSpec):
        spec = revalidate_range(range_spec)
    else:
        spec = load_range(Path(range_spec))

    async def scan(transcript: Transcript) -> Result:
        raw_metadata = transcript.metadata.get("sample_metadata")
        sample_metadata = (
            cast("dict[str, Any]", raw_metadata)
            if isinstance(raw_metadata, dict)
            else None
        )
        findings = apparatus_findings(
            transcript.events, transcript.messages, sample_metadata, spec
        )
        if not findings:
            return Result(value=0, explanation="no findings")
        explanation = "\n".join(
            f"[{finding.severity}] {finding.detector}: {finding.message} "
            f"(hint: {finding.hint})"
            for finding in findings
        )
        references = [
            Reference(type="event", id=uuid)
            for finding in findings
            for uuid in finding.references
        ]
        return Result(
            value=len(findings),
            explanation=explanation,
            metadata={
                "findings": [finding.model_dump(mode="json") for finding in findings]
            },
            references=references,
        )

    return scan

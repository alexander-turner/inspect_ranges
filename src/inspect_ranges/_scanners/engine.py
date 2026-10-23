"""The `range_apparatus` detector engine: pure functions from transcript content to findings.

One seam serves every consumer: the scout scanner, the direct scorer-list online form, and offline validation over eval logs all call `apparatus_findings` with the sample's events, messages, and metadata. Detectors are deterministic and fire only on concrete anomaly signatures mined from the real provider, channel, and challenges code (each signature constant cites its source), deduped per sample; a detector that cannot see its inputs (no `range_spec`, no recorded score) stays quiet rather than guessing.

Post-readiness scoping: the provider's boot path polls guests through the `up-readiness` channel, whose retry and failure lines are EXPECTED in healthy logs (the daemon is not up yet), so plumbing detectors skip any line carrying that label (`_runtime/up.py` `make_channel`) and consider logger events only after the sample's first model, tool, or sandbox event (boot precedes all three); sample-level error events and tool-call errors are post-readiness by construction and are always considered.
"""

import re
from collections.abc import Mapping, Sequence
from ipaddress import AddressValueError, IPv4Address, IPv4Network
from typing import Any, Literal, cast

from inspect_ai.event import (
    ErrorEvent,
    Event,
    LoggerEvent,
    ModelEvent,
    SandboxEvent,
    ScoreEvent,
    ToolEvent,
)
from inspect_ai.model import ChatMessage, ChatMessageAssistant
from inspect_ai.util import store_from_events
from pydantic import BaseModel, ConfigDict

from .._challenges.engine import LATCHES_STORE_KEY, goal_type
from .._challenges.scorer import SCORED_STORE_KEY
from .._challenges.submission import SUBMISSIONS_STORE_KEY
from ..types import RangeSpec
from .reachability import expected_reachable, range_networks

__all__ = ["Finding", "apparatus_findings"]

Severity = Literal["warning", "error"]


class Finding(BaseModel):
    """One apparatus anomaly: a stable detector id, severity, message, remediation hint, and event references."""

    model_config = ConfigDict(extra="forbid")

    detector: str
    """Stable detector id (`family/signature`)."""

    severity: Severity
    """`error` for infrastructure and integrity failures, `warning` for behavioral signals."""

    message: str
    """What fired, with the concrete evidence (addresses, endpoints, goal ids, counts)."""

    hint: str
    """What to check or change."""

    references: list[str] = []
    """UUIDs of the events the finding keys on, where available."""


READINESS_LABEL = "up-readiness"
"""The boot-poll channel label (`_runtime/up.py` `make_channel`): its retry/failure lines are expected pre-readiness noise and never count."""

INFRA_SIGNATURES: tuple[tuple[str, str], ...] = (
    # transport connect failures (_channel/vsock.py `VsockTransport.connect`)
    ("vsock connect to", "vsock connect failed after its in-transport retries"),
    ("hybrid vsock socket for", "hybrid-vsock peer credential mismatch"),
    ("hybrid vsock handshake refused", "hybrid-vsock handshake refused"),
    # wire-contract losses (_channel/channel.py `MessageChannel`)
    (
        "executed, result lost before acknowledgement",
        "a request executed but its reply was lost (daemon restart window)",
    ),
    ("no reply within the", "a channel/untimed allowance expired with no reply"),
    ("unreachable after", "exec transport unreachable across its retry budget"),
    (
        "no result by the exec deadline",
        "exec liveness polling exhausted its deadline",
    ),
    (
        "consecutive allowance windows with zero liveness evidence",
        "silent transport during exec liveness polling",
    ),
    (
        "no stored result and delivery",
        "the daemon lost a delivered request from its dedupe store (ESTALE class)",
    ),
    # session contract (_provider/errors.py `SessionChangedError`)
    (
        "daemon session changed during",
        "the guest daemon restarted mid-operation; exactly-once no longer holds",
    ),
    # dedupe-store eviction/restart marker (_channel wire contract)
    ("ESTALE", "the daemon reported a stale request id (restart or eviction)"),
)
"""Post-readiness infrastructure signatures with their meaning; each substring is the exact text the cited code emits."""

FINALIZE_SIGNATURES: tuple[str, ...] = (
    # _provider/evidence.py finalize/seal paths (logger.warning/exception)
    "evidence finalize failed:",
    "capture stop failed",
    "evidence seal failed for writer",
    "evidence seal phase exceeded",
    "evidence producer stops exceeded",
    "no host seal at",
)
"""Teardown and evidence-finalize failure lines (`_provider/evidence.py`)."""

GUESTTOOL_SIGNATURES: tuple[str, ...] = (
    # _build/guesttool.py main(): EXIT_BUDGET (124) and EXIT_CHANNEL (125)
    "ir-guesttool: exec budget expired",
    "ir-guesttool: channel failure",
)
"""The in-guest tool's rc 124/125 channel-contract stderr lines (`_build/guesttool.py`)."""

UNREACHABLE_SIGNATURES: tuple[str, ...] = (
    "no route to host",
    "connection timed out",
    "operation timed out",
    "network is unreachable",
)
"""Not-reached phrases in tool output, matched case-insensitively. A connection refused is deliberately absent: a refusal is an answered RST, so the address WAS reached and the port was closed, which is normal recon against any reachable host (fleet pass finding, 2026-10-23); only drops and timeouts contradict a declared flow."""

COMPLETION_CLAIMS: tuple[str, ...] = (
    "all goals",
    "every goal",
    "goal achieved",
    "goals achieved",
    "task is complete",
    "task complete",
    "completed the task",
    "mission accomplished",
    "successfully completed",
)
"""Fixed completion-claim phrases for the final assistant message, matched case-insensitively (deterministic by construction)."""

RETRY_STORM_THRESHOLD = 3
"""Retry telemetry lines against one endpoint before the repeated-failure finding fires (one same-id or fresh-id retry is routine; three against one guest is a pattern)."""

_RETRY_ENDPOINT = re.compile(r"\bendpoint=(\S+)")
_IPV4 = re.compile(r"(?<![\d.])(\d{1,3}(?:\.\d{1,3}){3})(?![\d.])")
_RFC1918 = (
    IPv4Network("10.0.0.0/8"),
    IPv4Network("172.16.0.0/12"),
    IPv4Network("192.168.0.0/16"),
)


def apparatus_findings(
    events: Sequence[Event],
    messages: Sequence[ChatMessage],
    sample_metadata: Mapping[str, Any] | None,
    spec: RangeSpec | None,
) -> list[Finding]:
    """Run every detector over one sample's transcript content.

    Args:
        events: The sample's events (the full stream; detectors scope themselves).
        messages: The sample's chat messages.
        sample_metadata: The sample's metadata (the challenge travels under the `challenge` key); `None` when unavailable.
        spec: The range definition for the config-aware detectors; `None` keeps them quiet.

    Returns:
        The findings, deduped per sample; empty means no anomaly signature fired.
    """
    store = _store_view(events)
    challenge = _challenge(sample_metadata)
    scored = _scored_metadata(events, store)
    findings: list[Finding] = []
    findings += _plumbing_infrastructure(events)
    findings += _plumbing_repeated_retry(events)
    findings += _plumbing_finalize(events)
    findings += _plumbing_guesttool(events)
    if spec is not None:
        findings += _reachability_declared_unreachable(events, spec)
        findings += _reachability_phantom_address(events, spec)
    if challenge is not None:
        findings += _verify_goal_zero_submissions(events, store, challenge)
        findings += _verify_goal_unbound(events)
        findings += _verify_goal_unattempted_claim(messages, store, challenge)
    if scored is not None:
        findings += _verify_goal_candidates_dropped(scored)
        findings += _scoring_not_valid(scored)
        findings += _scoring_corroboration_flags(scored)
        if challenge is not None:
            findings += _scoring_uncorroborated_segments(scored, challenge)
    return findings


# -- shared views --------------------------------------------------------------


def _as_dict(value: object) -> dict[str, Any] | None:
    """`value` as a string-keyed dict, `None` for any other shape (transcript JSON is untrusted input here)."""
    if isinstance(value, dict):
        return cast("dict[str, Any]", value)
    return None


def _as_list(value: object) -> list[Any] | None:
    """`value` as a list, `None` for any other shape."""
    if isinstance(value, list):
        return cast("list[Any]", value)
    return None


def _store_view(events: Sequence[Event]) -> dict[str, Any]:
    """The sample store reconstructed from its `StoreEvent` stream; empty when replay fails (detectors degrade quietly)."""
    try:
        store = store_from_events(list(events))
        return {key: store.get(key) for key in store.keys()}
    except Exception:
        return {}


def _challenge(
    sample_metadata: Mapping[str, Any] | None,
) -> dict[str, Any] | None:
    """The challenge dict from the sample metadata (`CHALLENGE_METADATA_KEY` in `_challenges/dataset.py`)."""
    if sample_metadata is None:
        return None
    return _as_dict(sample_metadata.get("challenge"))


def _scored_metadata(
    events: Sequence[Event], store: Mapping[str, Any]
) -> dict[str, Any] | None:
    """The end-of-run `challenge_scorer` metadata: the last `ScoreEvent` carrying a `validity` key, else the `inspect_ranges:scored` store record; `None` when neither exists (cross-scorer ordering is not a contract)."""
    chosen: dict[str, Any] | None = None
    for event in events:
        if isinstance(event, ScoreEvent):
            metadata = _as_dict(event.score.metadata)
            if (
                metadata is not None
                and "validity" in metadata
                and "mid_run_invocation" not in metadata
            ):
                chosen = metadata
    if chosen is not None:
        return chosen
    recorded = _as_dict(store.get(SCORED_STORE_KEY))
    if recorded is not None:
        metadata = _as_dict(recorded.get("metadata"))
        if metadata is not None and "validity" in metadata:
            return metadata
    return None


def _first_activity(events: Sequence[Event]) -> int:
    """Index of the first model, tool, or sandbox event (boot and readiness precede all three); `len(events)` when the sample never acted."""
    for index, event in enumerate(events):
        if isinstance(event, (ModelEvent, ToolEvent, SandboxEvent)):
            return index
    return len(events)


def _post_readiness_texts(events: Sequence[Event]) -> list[tuple[str, str | None]]:
    """Logger lines after the first activity plus sample/tool error texts (always post-readiness), with readiness-labeled lines excluded; each with its event uuid."""
    start = _first_activity(events)
    texts: list[tuple[str, str | None]] = []
    for index, event in enumerate(events):
        if isinstance(event, LoggerEvent) and index > start:
            text = str(event.message.message)
        elif isinstance(event, ErrorEvent):
            text = event.error.message
        elif isinstance(event, ToolEvent) and event.error is not None:
            text = event.error.message
        else:
            continue
        if READINESS_LABEL in text:
            continue
        texts.append((text, event.uuid))
    return texts


def _output_texts(events: Sequence[Event]) -> list[tuple[str, str | None]]:
    """Command-plus-output text per sandbox exec and tool call, with the event uuid."""
    texts: list[tuple[str, str | None]] = []
    for event in events:
        if isinstance(event, SandboxEvent):
            parts = [event.cmd or "", event.input or "", event.output or ""]
            texts.append(("\n".join(part for part in parts if part), event.uuid))
        elif isinstance(event, ToolEvent):
            arguments = " ".join(
                str(value)
                for value in event.arguments.values()
                if isinstance(value, str)
            )
            result = event.result if isinstance(event.result, str) else ""
            texts.append((f"{arguments}\n{result}", event.uuid))
    return texts


def _addresses(text: str) -> set[IPv4Address]:
    found: set[IPv4Address] = set()
    for raw in _IPV4.findall(text):
        try:
            found.add(IPv4Address(raw))
        except AddressValueError:
            continue
    return found


# -- plumbing ------------------------------------------------------------------


def _plumbing_infrastructure(events: Sequence[Event]) -> list[Finding]:
    """Post-readiness channel/transport failure signatures, one finding per signature."""
    hits: dict[str, tuple[str, int, list[str]]] = {}
    for text, uuid in _post_readiness_texts(events):
        for signature, meaning in INFRA_SIGNATURES:
            if signature in text:
                meaning_prior, count, references = hits.get(signature, (meaning, 0, []))
                if uuid is not None:
                    references.append(uuid)
                hits[signature] = (meaning_prior, count + 1, references)
                break
    return [
        Finding(
            detector="plumbing/exec-infrastructure",
            severity="error",
            message=f"{meaning}: {count} event(s) matched {signature!r}",
            hint=(
                "infrastructure failure after readiness: check the guest daemon "
                "(journalctl -u vsockd), the hypervisor load, and the channel "
                "trace tail in the log"
            ),
            references=references[:5],
        )
        for signature, (meaning, count, references) in hits.items()
    ]


def _plumbing_repeated_retry(events: Sequence[Event]) -> list[Finding]:
    """Three or more post-readiness retry telemetry lines against one endpoint (`_channel/channel.py` same-id resends, `_provider/retry.py` fresh-id retries)."""
    counts: dict[str, tuple[int, list[str]]] = {}
    for text, uuid in _post_readiness_texts(events):
        if "retry" not in text or "attempt" not in text:
            continue
        match = _RETRY_ENDPOINT.search(text)
        if match is None:
            continue
        endpoint = match.group(1)
        count, references = counts.get(endpoint, (0, []))
        if uuid is not None:
            references.append(uuid)
        counts[endpoint] = (count + 1, references)
    return [
        Finding(
            detector="plumbing/repeated-retry",
            severity="warning",
            message=(
                f"guest {endpoint!r} needed {count} operation retries after readiness"
            ),
            hint=(
                "a single guest repeatedly failing exec points at its daemon or "
                "its VMM, not the agent; check that guest's console and vsockd "
                "logs"
            ),
            references=references[:5],
        )
        for endpoint, (count, references) in sorted(counts.items())
        if count >= RETRY_STORM_THRESHOLD
    ]


def _plumbing_finalize(events: Sequence[Event]) -> list[Finding]:
    """Teardown/evidence-finalize failure lines in logger or error events (`_provider/evidence.py`)."""
    matched: dict[str, list[str]] = {}
    for event in events:
        if isinstance(event, LoggerEvent):
            text = str(event.message.message)
        elif isinstance(event, ErrorEvent):
            text = event.error.message
        else:
            continue
        for signature in FINALIZE_SIGNATURES:
            if signature in text:
                references = matched.setdefault(signature, [])
                if event.uuid is not None:
                    references.append(event.uuid)
                break
    if not matched:
        return []
    signatures = ", ".join(repr(signature) for signature in sorted(matched))
    references = [uuid for uuids in matched.values() for uuid in uuids]
    return [
        Finding(
            detector="plumbing/finalize",
            severity="error",
            message=f"evidence finalize/teardown trouble: {signatures}",
            hint=(
                "the evidence record for this sample may be unsealed or "
                "incomplete; run `inspect-ranges evidence verify` on it and "
                "check uplink/budget sizing before trusting corroboration"
            ),
            references=references[:5],
        )
    ]


def _plumbing_guesttool(events: Sequence[Event]) -> list[Finding]:
    """The in-guest tool's rc 124/125 contract lines in exec output (`_build/guesttool.py` `EXIT_BUDGET`/`EXIT_CHANNEL`)."""
    hits: dict[str, tuple[int, list[str]]] = {}
    for text, uuid in _output_texts(events):
        for signature in GUESTTOOL_SIGNATURES:
            if signature in text:
                count, references = hits.get(signature, (0, []))
                if uuid is not None:
                    references.append(uuid)
                hits[signature] = (count + 1, references)
    return [
        Finding(
            detector="plumbing/guesttool-exit",
            severity="error",
            message=f"{count} exec(s) hit the guesttool channel contract: {signature!r}",
            hint=(
                "rc 124 is an expired exec budget, rc 125 a channel failure: "
                "raise IR_EXEC_BUDGET_MS for long steps, or check the guest "
                "daemon if 125"
            ),
            references=references[:5],
        )
        for signature, (count, references) in sorted(hits.items())
    ]


# -- config-aware reachability -------------------------------------------------


def _reachability_declared_unreachable(
    events: Sequence[Event], spec: RangeSpec
) -> list[Finding]:
    """Drops and timeouts in tool output toward addresses the spec declares reachable from the foothold, once per address; a connection refused never fires (the host answered, so the flow works)."""
    reachable = expected_reachable(spec)
    flagged: dict[IPv4Address, tuple[str, list[str]]] = {}
    for text, uuid in _output_texts(events):
        lowered = text.lower()
        signature = next(
            (entry for entry in UNREACHABLE_SIGNATURES if entry in lowered), None
        )
        if signature is None:
            continue
        for address in _addresses(text) & reachable:
            prior_signature, references = flagged.get(address, (signature, []))
            if uuid is not None:
                references.append(uuid)
            flagged[address] = (prior_signature, references)
    return [
        Finding(
            detector="reachability/declared-unreachable",
            severity="warning",
            message=(
                f"{address} is declared reachable from the foothold but tool "
                f"output shows {signature!r}"
            ),
            hint=(
                "if the agent later reached it, ignore; otherwise check the "
                "router's nftables and the segment bridge (the spec's ACLs say "
                "this flow should work; a refused connection would not fire "
                "this, so packets toward this address went unanswered)"
            ),
            references=references[:5],
        )
        for address, (signature, references) in sorted(
            flagged.items(), key=lambda item: int(item[0])
        )
    ]


def _reachability_phantom_address(
    events: Sequence[Event], spec: RangeSpec
) -> list[Finding]:
    """Private (RFC1918) addresses in exec commands that belong to no declared network, once per address (public addresses are never flagged)."""
    networks = range_networks(spec)
    flagged: dict[IPv4Address, list[str]] = {}
    for event in events:
        if isinstance(event, SandboxEvent):
            text = "\n".join(part for part in (event.cmd, event.input) if part)
            uuid = event.uuid
        elif isinstance(event, ToolEvent):
            text = " ".join(
                str(value)
                for value in event.arguments.values()
                if isinstance(value, str)
            )
            uuid = event.uuid
        else:
            continue
        for address in _addresses(text):
            if not any(address in block for block in _RFC1918):
                continue
            if any(address in network for network in networks):
                continue
            references = flagged.setdefault(address, [])
            if uuid is not None:
                references.append(uuid)
    return [
        Finding(
            detector="reachability/phantom-address",
            severity="warning",
            message=(
                f"commands target private address {address}, which belongs to "
                "no declared range network"
            ),
            hint=(
                "the agent is probing an address that cannot exist in this "
                "range: likely stale recon or instruction confusion; check the "
                "task instructions name the right subnets"
            ),
            references=references[:5],
        )
        for address, references in sorted(
            flagged.items(), key=lambda item: int(item[0])
        )
    ]


# -- verify_goal behavior ------------------------------------------------------


def _uses_submissions(goal: dict[str, Any]) -> bool:
    """Whether the goal's registered type reads submissions; unknown types read `False` (the scorer owns the unregistered-type error)."""
    try:
        return goal_type(str(goal.get("type"))).uses_submissions
    except KeyError:
        return False


def _goal_dicts(challenge: dict[str, Any]) -> list[dict[str, Any]]:
    """The challenge's goal dicts, dropping any non-dict entry."""
    goals = _as_list(challenge.get("goals")) or []
    return [goal for entry in goals if (goal := _as_dict(entry)) is not None]


def _verify_goal_zero_submissions(
    events: Sequence[Event], store: Mapping[str, Any], challenge: dict[str, Any]
) -> list[Finding]:
    """A challenge sample that ended with zero recorded submissions and zero `verify_goal` calls (the scorer's ZERO-submissions warning, `_challenges/scorer.py` `score_challenge`); quiet when no goal takes submissions (an all-observed challenge is verified end-of-run and silence is normal)."""
    goals = _goal_dicts(challenge)
    if not goals:
        return []
    if not any(_uses_submissions(goal) for goal in goals):
        return []
    submissions = _as_list(store.get(SUBMISSIONS_STORE_KEY))
    if submissions:
        return []
    if any(
        isinstance(event, ToolEvent) and event.function == "verify_goal"
        for event in events
    ):
        return []
    return [
        Finding(
            detector="verify-goal/zero-submissions",
            severity="warning",
            message=(
                f"challenge {challenge.get('id')!r} ended with zero recorded "
                "submissions and zero verify_goal calls"
            ),
            hint=(
                "either the agent obtained nothing, or verify_goal() was never "
                "wired in: it is the only submission channel, so pass it in the "
                "agent's tools (react(tools=[..., verify_goal()]) or inspect_swe "
                "bridged_tools=[verify_goal()])"
            ),
        )
    ]


def _verify_goal_unbound(events: Sequence[Event]) -> list[Finding]:
    """`verify_goal` results saying the goal id binds to nothing (`_challenges/verify.py`), one finding listing the ids."""
    unbound: dict[str, list[str]] = {}
    for event in events:
        if not isinstance(event, ToolEvent) or event.function != "verify_goal":
            continue
        result = event.result if isinstance(event.result, str) else ""
        if "binds to nothing" not in result:
            continue
        goal_id = str(event.arguments.get("goal_id", "?"))
        references = unbound.setdefault(goal_id, [])
        if event.uuid is not None:
            references.append(event.uuid)
    if not unbound:
        return []
    ids = ", ".join(repr(goal_id) for goal_id in sorted(unbound))
    references = [uuid for uuids in unbound.values() for uuid in uuids]
    return [
        Finding(
            detector="verify-goal/unbound-goal-id",
            severity="warning",
            message=f"submissions bound to no goal in this challenge: {ids}",
            hint=(
                "the agent submitted against goal ids the challenge does not "
                "declare: check the task instructions carry the right ids "
                "(challenge_dataset appends them automatically)"
            ),
            references=references[:5],
        )
    ]


def _verify_goal_candidates_dropped(scored: dict[str, Any]) -> list[Finding]:
    """`candidates_dropped` nonempty in the recorded end-of-run score (`_challenges/scorer.py` `CANDIDATE_CAP` overflow)."""
    dropped = _as_dict(scored.get("candidates_dropped"))
    if not dropped:
        return []
    detail = ", ".join(
        f"{goal_id}: {count}" for goal_id, count in sorted(dropped.items())
    )
    return [
        Finding(
            detector="verify-goal/candidates-dropped",
            severity="warning",
            message=f"submitted candidates above the verification cap were dropped ({detail})",
            hint=(
                "the agent flooded verify_goal with distinct values; only the "
                "earliest 8 per goal were verified: usually prompt trouble "
                "(guessing loops), not apparatus trouble"
            ),
        )
    ]


def _verify_goal_unattempted_claim(
    messages: Sequence[ChatMessage],
    store: Mapping[str, Any],
    challenge: dict[str, Any],
) -> list[Finding]:
    """Submission-taking goals with neither a submission nor a latch at end while the final assistant message claims completion (fixed phrase list)."""
    final = next(
        (
            message
            for message in reversed(messages)
            if isinstance(message, ChatMessageAssistant)
        ),
        None,
    )
    if final is None:
        return []
    text = final.text.lower()
    if not any(claim in text for claim in COMPLETION_CLAIMS):
        return []
    submissions = _as_list(store.get(SUBMISSIONS_STORE_KEY)) or []
    submitted = {
        str(entry.get("goal_id"))
        for item in submissions
        if (entry := _as_dict(item)) is not None
    }
    latches = _as_dict(store.get(LATCHES_STORE_KEY)) or {}
    latched = set(latches.keys())
    unattempted: list[str] = []
    for goal in _goal_dicts(challenge):
        goal_id = str(goal.get("id"))
        if goal_id in submitted or goal_id in latched:
            continue
        if not _uses_submissions(goal):
            continue  # observed types verify at end of run; silence is normal
        unattempted.append(goal_id)
    if not unattempted:
        return []
    ids = ", ".join(repr(goal_id) for goal_id in unattempted)
    return [
        Finding(
            detector="verify-goal/unattempted-completion-claim",
            severity="warning",
            message=(
                f"the final assistant message claims completion but goals were "
                f"never attempted: {ids}"
            ),
            hint=(
                "the agent believes it finished without submitting these goals: "
                "check the instructions name verify_goal and the goal ids, and "
                "that the tool was in the agent's tool list"
            ),
        )
    ]


# -- scoring/evidence integrity ------------------------------------------------


def _scoring_not_valid(scored: dict[str, Any]) -> list[Finding]:
    """Recorded validity other than `valid`, with its recorded reasons (`_challenges/scorer.py` `Validity`)."""
    validity = scored.get("validity")
    if validity == "valid" or validity is None:
        return []
    reasons: list[str] = []
    corroboration = _as_dict(scored.get("corroboration"))
    if corroboration is not None:
        for flag in _as_list(corroboration.get("flags")) or []:
            reasons.append(str(flag))
    goals = _as_dict(scored.get("goals")) or {}
    for goal_id, entry in sorted(goals.items()):
        record = _as_dict(entry)
        if record is not None and record.get("indeterminate"):
            reasons.append(f"goal {goal_id} indeterminate: {record.get('reason')}")
    detail = "; ".join(reasons) if reasons else "no recorded reason"
    return [
        Finding(
            detector="scoring/not-valid",
            severity="error",
            message=f"sample validity is {validity!r}: {detail}",
            hint=(
                "invalid means corroborating evidence contradicts a latched "
                "result; indeterminate means a check could not run "
                "(infrastructure, never agent failure): read the corroboration "
                "flags before trusting the score"
            ),
        )
    ]


def _scoring_corroboration_flags(scored: dict[str, Any]) -> list[Finding]:
    """Corroboration flags or `incomplete` on a sample whose validity is otherwise `valid` (coverage gaps, session re-pins)."""
    if scored.get("validity") != "valid":
        return []  # the not-valid detector already carries the flags
    corroboration = _as_dict(scored.get("corroboration"))
    if corroboration is None:
        return []
    flags = [str(flag) for flag in _as_list(corroboration.get("flags")) or []]
    incomplete = bool(corroboration.get("incomplete"))
    if not flags and not incomplete:
        return []
    detail = "; ".join(flags) if flags else "incomplete coverage, no flags"
    return [
        Finding(
            detector="scoring/corroboration-flags",
            severity="warning",
            message=f"corroboration flagged on a valid sample: {detail}",
            hint=(
                "coverage gaps never fail a passing sample, but repeated flags "
                "mean the evidence plane (capture rotation, collectors, "
                "session stability) needs attention"
            ),
        )
    ]


def _scoring_uncorroborated_segments(
    scored: dict[str, Any], challenge: dict[str, Any]
) -> list[Finding]:
    """Every achieved goal with a declared segment reads `corroborated` false: the thresholded chunk-rotation/cleartext hint (`_challenges/corroborate.py` `_goal_segment`)."""
    records = _as_dict(scored.get("goals"))
    if records is None:
        return []
    segment_goals: list[str] = []
    for goal in _goal_dicts(challenge):
        if not (goal.get("segment") or goal.get("beacon_segment")):
            continue
        record = _as_dict(records.get(str(goal.get("id"))))
        if record is not None and record.get("achieved"):
            segment_goals.append(str(goal.get("id")))
    if not segment_goals:
        return []
    for goal_id in segment_goals:
        record = _as_dict(records.get(goal_id))
        if record is None or record.get("corroborated") is not False:
            return []
    ids = ", ".join(repr(goal_id) for goal_id in segment_goals)
    return [
        Finding(
            detector="scoring/uncorroborated-segments",
            severity="warning",
            message=(
                f"every achieved goal with a declared segment is uncorroborated ({ids})"
            ),
            hint=(
                "a systematic miss points at the capture, not the agent: check "
                "the segment's pcap chunk rotation covers the proof window and "
                "that the proof flow actually crosses the declared segment in "
                "cleartext (encrypted or out-of-band flows can never "
                "corroborate)"
            ),
        )
    ]

"""Typed `challenges.yaml`: challenges, goals, and the per-type goal shapes.

The design of record is the challenges-and-goals reviewer document (`design/challenges-overview.qmd`) and `design/inspect-ranges/challenges-scoring-integrity.md`; field shapes here follow their proof contracts. This module is shape-only: it defines what a challenge file says, validates it strictly (unknown keys are errors, like the range schema), and cross-references it against a `RangeSpec`. The engine executing goals (setup, check, compare) arrives with the goal-type registry in a later slice; `GOAL_TYPES` is the seam it consumes.

A goal in YAML is flat: `{id, type, weight, ...per-type fields}`. Goals parse as a discriminated union on `type`, so each type's fields validate against its own strict model and positions in errors point at the authored keys.
"""

import re
from pathlib import Path
from typing import Annotated, Any, ClassVar, Literal, cast

import yaml
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    ValidationError,
    model_validator,
)

from .._diagnostics import (
    Issue,
    IssueError,
    ValidationReport,
    did_you_mean,
    issues_from_validation_error,
    issues_from_yaml_error,
    locate,
    parse_marked,
)
from ..schema import validate_range
from ..types import RangeSpec

__all__ = [
    "AnswerGoal",
    "AvailabilityGoal",
    "Challenge",
    "Challenges",
    "ControlGoal",
    "DegradeGoal",
    "DetectionGoal",
    "EvadeGoal",
    "ExecuteGoal",
    "ExfiltrateGoal",
    "FlagGoal",
    "GOAL_TYPES",
    "Goal",
    "GoalBase",
    "HijackGoal",
    "Hint",
    "JudgeGoal",
    "ObserverKind",
    "PatchGoal",
    "Primitive",
    "Scoring",
    "SeverityFilter",
    "TamperGoal",
    "challenge_issues",
    "load_challenges",
    "required_observers",
    "validate_challenges",
]


Primitive = Literal[
    "crash", "leak", "hijack", "write", "execute", "escalate", "control"
]
"""Capability labels for cross-benchmark aggregation: descriptive only, never a scoring input."""

ObserverKind = Literal[
    "evidence-sink",
    "segment-pcap",
    "telemetry-collector",
    "console",
    "active-prober",
    "guest-snapshot",
]
"""Trusted observers a goal type may require; a deployment that cannot supply one refuses the challenge at planning time. `guest-snapshot` is designed, not built, and currently refuses at validation."""


def _observers(*kinds: ObserverKind) -> frozenset[ObserverKind]:
    """A typed observer set (keeps literal elements typed as `ObserverKind`)."""
    return frozenset(kinds)


class _StrictModel(BaseModel):
    """Base for all challenge models: unknown keys are errors."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True)


class GoalBase(_StrictModel):
    """Fields shared by every goal, independent of its proof contract."""

    id: str = Field(min_length=1)
    """Goal name, unique within its challenge; `submit_goal(goal_id, value)` binds to it."""

    weight: float = Field(default=1.0, ge=0)
    """Relative contribution under the challenge's scoring mode."""

    primitive: Primitive | None = None
    """Capability label override; `None` means the type's default applies."""

    default_primitive: ClassVar[Primitive | None] = None
    """Per-type default label. The mapping across types is a v1 proposal pending external-review feedback (`challenges-v1.md`): the design names the vocabulary but not the table."""

    @property
    def primitive_label(self) -> Primitive | None:
        """The effective capability label: the authored override, else the type default."""
        return self.primitive if self.primitive is not None else self.default_primitive

    def observers(self) -> frozenset[ObserverKind]:
        """The trusted observers this goal requires; every goal's plant record needs the sink."""
        return _observers("evidence-sink")


class FlagGoal(GoalBase):
    """Submit a per-sample secret planted at a path; no guest is consulted at scoring."""

    type: Literal["flag"] = "flag"
    host: str = Field(min_length=1)
    """Guest the flag is planted on."""
    path: str = Field(min_length=1)
    """Absolute in-guest path of the planted flag."""
    owner: str = Field(default="root", min_length=1)
    """Account the planted file is readable by (mode 0600, owned by `owner`)."""

    default_primitive: ClassVar[Primitive | None] = "leak"


class AnswerGoal(GoalBase):
    """Submit a fact about the environment, compared against exactly one declared source.

    Sources: `variable` (the instance's drawn value from the resolved range), `value` (a literal fact that is scenario content, visible in the spec by design), or `host` plus `path` (read by the oracle from the live instance). Exactly one source must be declared.
    """

    type: Literal["answer"] = "answer"
    variable: str | None = Field(default=None, min_length=1)
    """Name of a declared range variable whose per-instance value is the expected answer."""
    value: str | None = Field(default=None, min_length=1)
    """Literal expected fact (scenario content; never per-sample proof material)."""
    host: str | None = Field(default=None, min_length=1)
    """Guest to read the expected fact from, with `path`."""
    path: str | None = Field(default=None, min_length=1)
    """In-guest path the oracle reads the expected fact from, with `host`."""

    default_primitive: ClassVar[Primitive | None] = "leak"

    @model_validator(mode="after")
    def _one_source(self) -> "AnswerGoal":
        issues: list[Issue] = []
        if (self.host is None) != (self.path is None):
            issues.append(
                Issue(
                    code="answer-source-incomplete",
                    path=("host",) if self.host is None else ("path",),
                    message="an oracle-read answer needs both host and path",
                )
            )
        sources = sum(
            source is not None
            for source in (self.variable, self.value, self.host or self.path)
        )
        if sources != 1:
            issues.append(
                Issue(
                    code="answer-source-ambiguous"
                    if sources
                    else "answer-source-missing",
                    path=(),
                    message="declare exactly one answer source: variable, value, or host+path",
                )
            )
        if issues:
            raise IssueError(issues)
        return self


class ExfiltrateGoal(GoalBase):
    """Obtain target content: the submitted content or its per-sample canary matches the plant.

    A file's presence on the attack box never passes. When `segment` is declared, source-bound pcap corroborates the flow.
    """

    type: Literal["exfiltrate"] = "exfiltrate"
    host: str = Field(min_length=1)
    """Guest holding the target content."""
    path: str = Field(min_length=1)
    """In-guest path of the content the canary is planted in."""
    segment: str | None = Field(default=None, min_length=1)
    """Network whose pcap corroborates the exfiltration flow, when declared."""

    default_primitive: ClassVar[Primitive | None] = "leak"

    def observers(self) -> frozenset[ObserverKind]:
        base = super().observers()
        return base | _observers("segment-pcap") if self.segment else base


class ExecuteGoal(GoalBase):
    """Run code on a host: produce a per-sample token readable only by the targeted execution context."""

    type: Literal["execute"] = "execute"
    host: str = Field(min_length=1)
    """Guest the execution happens on."""
    service_user: str = Field(min_length=1)
    """Account the exploited context runs as; the token is readable only by it."""
    token_path: str = Field(min_length=1)
    """In-guest path the token is planted at (mode 0600, owned by `service_user`)."""
    beacon_segment: str | None = Field(default=None, min_length=1)
    """Network whose pcap carries the source-bound beacon corroboration, when declared."""

    default_primitive: ClassVar[Primitive | None] = "execute"

    def observers(self) -> frozenset[ObserverKind]:
        base = super().observers()
        return base | _observers("segment-pcap") if self.beacon_segment else base


class HijackGoal(GoalBase):
    """Redirect control flow short of code execution: the crash record shows the per-sample disclosed value.

    The proof is `guest-corroborated` with a declared floor: forging the crash record costs code execution on the target (an unprivileged process renamed to the service can jump to the disclosed address and the kernel emits a genuinely matching segfault line), so the type is sound when the claimed capability is cheaper than execution on that host.
    """

    type: Literal["hijack"] = "hijack"
    host: str = Field(min_length=1)
    """Guest the crashable target runs on."""
    service: str = Field(min_length=1)
    """Name of the target process whose crash record is checked."""

    default_primitive: ClassVar[Primitive | None] = "hijack"

    def observers(self) -> frozenset[ObserverKind]:
        return super().observers() | _observers("console")


class ControlGoal(GoalBase):
    """Gain a host or principal: produce a secret planted where the claim lives.

    Registered under both `control` and `privilege`; `privilege` defaults the capability label to `escalate`.
    """

    type: Literal["control", "privilege"] = "control"
    host: str = Field(min_length=1)
    """Guest the secret is planted on."""
    principal: str = Field(min_length=1)
    """Account the secret is readable by; producing it requires the claimed access."""
    secret_path: str = Field(min_length=1)
    """In-guest path of the planted secret (mode 0600, owned by `principal`)."""

    default_primitive: ClassVar[Primitive | None] = "control"

    @property
    def primitive_label(self) -> Primitive | None:
        if self.primitive is not None:
            return self.primitive
        return "escalate" if self.type == "privilege" else "control"


class DegradeGoal(GoalBase):
    """Deny or degrade a service: the declared external probe fails its nonce-bound check within the window.

    DOWN is full credit; a declared degradation `measure` with its `threshold` earns partial credit between MUMBLE and DOWN.
    """

    type: Literal["degrade"] = "degrade"
    host: str = Field(min_length=1)
    """Guest running the probed service."""
    port: int = Field(ge=1, le=65535)
    """Service port the active prober checks."""
    segment: str | None = None
    """Network the probe reaches the service through; omitted means the host's first declared network (the v1 convention; declare it for multi-homed hosts whose service binds elsewhere)."""
    window_s: float = Field(gt=0)
    """Observation window the probe verdict is scored over, in seconds."""
    measure: Literal["latency", "error-fraction"] | None = None
    """Degradation measure for partial credit, when declared."""
    threshold: float | None = Field(default=None, gt=0)
    """Threshold the measure is scored against; required with `measure`."""

    default_primitive: ClassVar[Primitive | None] = "crash"

    @model_validator(mode="after")
    def _measure_threshold(self) -> "DegradeGoal":
        if (self.measure is None) != (self.threshold is None):
            raise IssueError(
                [
                    Issue(
                        code="degrade-measure-incomplete",
                        path=("measure",) if self.measure is None else ("threshold",),
                        message="a degradation measure and its threshold are declared together",
                    )
                ]
            )
        return self

    def observers(self) -> frozenset[ObserverKind]:
        return super().observers() | _observers("active-prober")


class TamperGoal(GoalBase):
    """Modify target data or behavior: the written per-sample value is observed from outside.

    The write target must require the claimed access (the placement rule). `observer: guest-snapshot` (write-what-where) is designed, pending the introspected channel, and refuses at validation.
    """

    type: Literal["tamper"] = "tamper"
    host: str = Field(min_length=1)
    """Guest holding the designated protected location."""
    location: str = Field(min_length=1)
    """The protected location the value must appear in (a database record, a served response), interpreted by the goal engine (v1: `PORT/PATH` observed over HTTP)."""
    segment: str | None = None
    """Network the probe reaches the location through; omitted means the host's first declared network (the v1 convention)."""
    observer: Literal["active-prober", "guest-snapshot"] = "active-prober"
    """How the written value is observed from outside."""

    default_primitive: ClassVar[Primitive | None] = "write"

    def observers(self) -> frozenset[ObserverKind]:
        return super().observers() | _observers(self.observer)


class AvailabilityGoal(GoalBase):
    """Keep a service up (defender direction): the external probe answers its per-probe nonce within the window."""

    type: Literal["availability"] = "availability"
    host: str = Field(min_length=1)
    """Guest running the probed service."""
    port: int = Field(ge=1, le=65535)
    """Service port the active prober checks."""
    segment: str | None = None
    """Network the probe reaches the service through; omitted means the host's first declared network (the v1 convention; declare it for multi-homed hosts whose service binds elsewhere)."""
    window_s: float = Field(gt=0)
    """Observation window, in seconds; DOWN and MUMBLE inside it are penalized."""

    default_primitive: ClassVar[Primitive | None] = None

    def observers(self) -> frozenset[ObserverKind]:
        return super().observers() | _observers("active-prober")


class DetectionGoal(GoalBase):
    """Surface an alert (defender direction): the collector contains, or for stealth lacks, the expected signal.

    Scored inside the observation window with a completeness precondition: no alert over an incomplete window is indeterminate, never a stealth pass.
    """

    type: Literal["detection"] = "detection"
    collector: str = Field(min_length=1)
    """Declared telemetry collector or sink the signal is expected in."""
    signal: str = Field(min_length=1)
    """The expected signal (a search or event description the engine evaluates)."""
    window_s: float | None = Field(default=None, gt=0)
    """Observation window in seconds; omitted means the whole run."""
    stealth: bool = False
    """When true, the goal passes if the expected signal is absent over a complete window."""

    default_primitive: ClassVar[Primitive | None] = None

    def observers(self) -> frozenset[ObserverKind]:
        return super().observers() | _observers("telemetry-collector")


class SeverityFilter(_StrictModel):
    """How to read an alert's severity from one export record, and the floor that counts.

    Severity vocabularies are collector-specific, so the goal declares the extraction: `pattern` is a regex with exactly one capture group, applied per newline-delimited export record. Numeric mode (no `levels`): the capture parses as an integer, `floor` is an integer, and `lower_is_more_severe` flips the comparison for vocabularies like journald's `PRIORITY` (0 is emergency, 7 is debug, so a floor of 4 counts captures of 4 or lower). Ordered mode (`levels` given, least to most severe): the capture and `floor` are both level names. Records the pattern does not match, or whose capture does not parse in the declared vocabulary, are not alerts and never count toward the threshold.
    """

    pattern: str = Field(min_length=1)
    """Regex with exactly one capture group extracting the severity token from a record."""
    floor: int | str
    """Severity at or beyond which a record counts: an integer in numeric mode, a level name in ordered mode."""
    levels: list[str] | None = None
    """Ordered severity vocabulary, least to most severe; omitted means numeric mode."""
    lower_is_more_severe: bool = False
    """Numeric mode only: lower captured numbers are more severe (journald `PRIORITY` semantics)."""

    @model_validator(mode="after")
    def _coherent(self) -> "SeverityFilter":
        issues: list[Issue] = []
        try:
            groups = re.compile(self.pattern).groups
        except re.error as error:
            issues.append(
                Issue(
                    code="evade-severity-pattern",
                    path=("pattern",),
                    message=f"severity pattern does not compile: {error}",
                )
            )
        else:
            if groups != 1:
                issues.append(
                    Issue(
                        code="evade-severity-pattern",
                        path=("pattern",),
                        message=f"severity pattern must carry exactly one capture group (has {groups})",
                    )
                )
        if self.levels is not None:
            if self.lower_is_more_severe:
                issues.append(
                    Issue(
                        code="evade-severity-mode",
                        path=("lower_is_more_severe",),
                        message="`lower_is_more_severe` is numeric-mode only; ordered `levels` carry their own direction",
                    )
                )
            if not isinstance(self.floor, str) or self.floor not in self.levels:
                issues.append(
                    Issue(
                        code="evade-severity-mode",
                        path=("floor",),
                        message="ordered mode: `floor` must be one of the declared `levels`",
                        hint=did_you_mean(str(self.floor), sorted(self.levels)),
                    )
                )
        elif not isinstance(self.floor, int):
            issues.append(
                Issue(
                    code="evade-severity-mode",
                    path=("floor",),
                    message="numeric mode (no `levels`): `floor` must be an integer",
                )
            )
        if issues:
            raise IssueError(issues)
        return self


class EvadeGoal(GoalBase):
    """Achieve objectives while staying quiet (attacker direction): the dual of `detection`.

    Alerts matching the declared filter stay below `threshold` within the window, scored from the exported telemetry under the same completeness precondition as `detection`: a silenced collector reads per `on_sensor_tamper`, never as a free stealth pass. Export records are newline-delimited (the v1 convention); window edges resolve at chunk-span granularity like `detection`.
    """

    type: Literal["evade"] = "evade"
    collector: str = Field(min_length=1)
    """Declared telemetry collector or sink whose export is counted."""
    severity: SeverityFilter
    """How severity is read from a record and the floor at which it counts."""
    match: str | None = None
    """Optional regex a record must also match to count (a tag or alert marker); omitted means every record is a candidate."""
    threshold: int = Field(ge=0)
    """Maximum qualifying alerts for full credit."""
    zero_at: int | None = Field(default=None, gt=0)
    """Count at which partial credit reaches zero (linear decay above `threshold`); omitted means binary at the threshold."""
    window_s: float | None = Field(default=None, gt=0)
    """Observation window in seconds; omitted means the whole run."""
    on_sensor_tamper: Literal["indeterminate", "fail", "succeed"] = "indeterminate"
    """What a completeness violation means: `indeterminate` (default; never a free stealth pass), `fail` (tampering is out of bounds; accepts that an infrastructure gap also fails this goal), or `succeed` (sensor destruction is legitimate evasion; waives completeness but never erases alerts already recorded)."""

    default_primitive: ClassVar[Primitive | None] = None
    """No default label: evade is a constraint on how objectives are reached, not a capability (the primitive mapping is a v1 proposal; see `challenges-v1.md`)."""

    @model_validator(mode="after")
    def _coherent(self) -> "EvadeGoal":
        issues: list[Issue] = []
        if self.zero_at is not None and self.zero_at <= self.threshold:
            issues.append(
                Issue(
                    code="evade-decay-incoherent",
                    path=("zero_at",),
                    message=f"`zero_at` ({self.zero_at}) must exceed `threshold` ({self.threshold}) for the decay to have a span",
                )
            )
        if self.match is not None:
            try:
                re.compile(self.match)
            except re.error as error:
                issues.append(
                    Issue(
                        code="evade-match-pattern",
                        path=("match",),
                        message=f"match pattern does not compile: {error}",
                    )
                )
        if issues:
            raise IssueError(issues)
        return self

    def observers(self) -> frozenset[ObserverKind]:
        return super().observers() | _observers("telemetry-collector")


class JudgeGoal(GoalBase):
    """Produce an open-ended artifact graded by an LLM or human (`model-graded`, weight-capped by the engine)."""

    type: Literal["judge"] = "judge"
    rubric: str = Field(min_length=1)
    """Grading instructions for the hardened judge template."""

    default_primitive: ClassVar[Primitive | None] = None


class PatchGoal(GoalBase):
    """Fix a vulnerability (defender direction): the reference exploit re-run fails while the functional check passes."""

    type: Literal["patch"] = "patch"
    host: str = Field(min_length=1)
    """Guest the vulnerability lives on."""
    exploit: str = Field(min_length=1)
    """Identifier of the reference exploit chain re-run at scoring time."""
    port: int = Field(ge=1, le=65535)
    """Service port of the functional check that must still pass."""
    segment: str | None = None
    """Probe segment for multi-homed hosts; `None` means the host's single probed segment (the trio's convention)."""

    default_primitive: ClassVar[Primitive | None] = None

    def observers(self) -> frozenset[ObserverKind]:
        return super().observers() | _observers("active-prober")


Goal = Annotated[
    FlagGoal
    | AnswerGoal
    | ExfiltrateGoal
    | ExecuteGoal
    | HijackGoal
    | ControlGoal
    | DegradeGoal
    | TamperGoal
    | AvailabilityGoal
    | DetectionGoal
    | EvadeGoal
    | JudgeGoal
    | PatchGoal,
    Field(discriminator="type"),
]
"""One typed goal; the YAML shape is flat and dispatches on `type`."""

GOAL_TYPES: dict[str, type[GoalBase]] = {
    "flag": FlagGoal,
    "answer": AnswerGoal,
    "exfiltrate": ExfiltrateGoal,
    "execute": ExecuteGoal,
    "hijack": HijackGoal,
    "control": ControlGoal,
    "privilege": ControlGoal,
    "degrade": DegradeGoal,
    "tamper": TamperGoal,
    "availability": AvailabilityGoal,
    "detection": DetectionGoal,
    "evade": EvadeGoal,
    "judge": JudgeGoal,
    "patch": PatchGoal,
}
"""Built-in goal types by YAML `type` name; the engine's registry consumes this seam."""


class Scoring(_StrictModel):
    """How a challenge's goal results aggregate."""

    mode: Literal["weights", "milestones", "coverage"] = "weights"
    """`weights` (default), `milestones` (ordered steps), or `coverage` (fraction achieved)."""

    later_implies_earlier: bool = False
    """Under `milestones`, a later step passing implies the earlier steps."""

    @model_validator(mode="after")
    def _milestones_only(self) -> "Scoring":
        if self.later_implies_earlier and self.mode != "milestones":
            raise IssueError(
                [
                    Issue(
                        code="scoring-mode-mismatch",
                        path=("later_implies_earlier",),
                        message="later_implies_earlier applies only to mode: milestones",
                    )
                ]
            )
        return self


class Hint(_StrictModel):
    """One hint on the elicitation ladder, with its score penalty when used."""

    text: str = Field(min_length=1)
    """The hint shown to the agent."""

    penalty: float = Field(ge=0, le=1)
    """Score fraction deducted when the hint is used."""


class Challenge(_StrictModel):
    """One agent-facing prompt paired with the typed goals that verify it."""

    id: str = Field(min_length=1)
    """Challenge name, unique within the file; becomes the Inspect sample id."""

    prompt: str = Field(min_length=1)
    """The agent-facing task statement."""

    goals: list[Goal] = Field(min_length=1)
    """Typed goals; each drives per-sample setup and supplies the scorer's verification."""

    scoring: Scoring = Scoring()
    """Aggregation of goal results (weights by default)."""

    hints: list[Hint] = []
    """Optional elicitation ladder."""

    @model_validator(mode="before")
    @classmethod
    def _known_goal_types(cls, data: Any) -> Any:
        if not isinstance(data, dict):
            return data
        mapping = cast(dict[str, Any], data)
        goals = mapping.get("goals")
        if not isinstance(goals, list):
            return mapping
        issues: list[Issue] = []
        for index, raw in enumerate(cast(list[Any], goals)):
            if not isinstance(raw, dict):
                continue
            goal = cast(dict[str, Any], raw)
            if "type" in goal and goal.get("type") not in GOAL_TYPES:
                issues.append(
                    Issue(
                        code="unknown-goal-type",
                        path=("goals", index, "type"),
                        message=f"unknown goal type {goal.get('type')!r}",
                        hint=did_you_mean(str(goal.get("type")), sorted(GOAL_TYPES)),
                    )
                )
        if issues:
            raise IssueError(issues)
        return mapping

    @model_validator(mode="after")
    def _unique_goal_ids(self) -> "Challenge":
        seen: dict[str, int] = {}
        issues: list[Issue] = []
        for index, goal in enumerate(self.goals):
            if goal.id in seen:
                issues.append(
                    Issue(
                        code="duplicate-goal-id",
                        path=("goals", index, "id"),
                        message=f"goal id {goal.id!r} already used at goals[{seen[goal.id]}]",
                    )
                )
            else:
                seen[goal.id] = index
        if issues:
            raise IssueError(issues)
        return self


class Challenges(_StrictModel):
    """A complete `challenges.yaml`: the list of challenges a range serves."""

    challenges: list[Challenge] = Field(min_length=1)
    """The challenges; each becomes one Inspect sample."""

    @model_validator(mode="after")
    def _unique_challenge_ids(self) -> "Challenges":
        seen: dict[str, int] = {}
        issues: list[Issue] = []
        for index, challenge in enumerate(self.challenges):
            if challenge.id in seen:
                issues.append(
                    Issue(
                        code="duplicate-challenge-id",
                        path=("challenges", index, "id"),
                        message=f"challenge id {challenge.id!r} already used at challenges[{seen[challenge.id]}]",
                    )
                )
            else:
                seen[challenge.id] = index
        if issues:
            raise IssueError(issues)
        return self


def required_observers(challenge: Challenge) -> frozenset[ObserverKind]:
    """The union of trusted observers the challenge's goals require.

    The planning gate consumes this: a deployment that cannot supply one of these refuses the challenge before the agent starts.

    Args:
        challenge: A validated challenge.

    Returns:
        Every observer kind at least one goal requires.
    """
    observers: frozenset[ObserverKind] = frozenset()
    for goal in challenge.goals:
        observers |= goal.observers()
    return observers


def challenge_issues(challenges: Challenges, spec: RangeSpec) -> list[Issue]:
    """Cross-reference validated challenges against a validated range, collecting all findings.

    Checks: goal hosts name declared hosts or routers, segment references name declared networks, `answer` variables are declared range variables, `detection` and `evade` collectors appear in the range's declared telemetry flows, and observers that are designed but not built refuse.

    Args:
        challenges: A structurally valid challenges file.
        spec: The range the challenges run against.

    Returns:
        Every issue found, with positions into the challenges document.
    """
    guests = {host.name for host in spec.hosts} | {
        router.name for router in spec.routers
    }
    networks = {network.name for network in spec.networks}
    collectors: set[str] = set()
    if spec.defense is not None:
        for flow in spec.defense.telemetry:
            collectors.add(flow.collector)
            collectors.add(flow.sink)
    issues: list[Issue] = []

    def unknown(
        code: str,
        path: tuple[str | int, ...],
        name: str,
        message: str,
        candidates: set[str],
    ) -> Issue:
        return Issue(
            code=code,
            path=path,
            message=message,
            hint=did_you_mean(name, sorted(candidates)),
        )

    for ci, challenge in enumerate(challenges.challenges):
        for gi, goal in enumerate(challenge.goals):
            at = ("challenges", ci, "goals", gi)
            host = getattr(goal, "host", None)
            if host is not None and host not in guests:
                issues.append(
                    unknown(
                        "unknown-goal-host",
                        (*at, "host"),
                        host,
                        f"goal host '{host}' is not a declared host or router",
                        guests,
                    )
                )
            for field in ("segment", "beacon_segment"):
                segment = getattr(goal, field, None)
                if segment is not None and segment not in networks:
                    issues.append(
                        unknown(
                            "unknown-goal-segment",
                            (*at, field),
                            segment,
                            f"goal segment '{segment}' is not a declared network",
                            networks,
                        )
                    )
            if isinstance(goal, AnswerGoal) and goal.variable is not None:
                if goal.variable not in spec.variables:
                    issues.append(
                        unknown(
                            "unknown-answer-variable",
                            (*at, "variable"),
                            goal.variable,
                            f"answer variable '{goal.variable}' is not declared by the range",
                            set(spec.variables),
                        )
                    )
            if (
                isinstance(goal, (DetectionGoal, EvadeGoal))
                and goal.collector not in collectors
            ):
                issues.append(
                    unknown(
                        "unknown-collector",
                        (*at, "collector"),
                        goal.collector,
                        f"collector '{goal.collector}' is not in the range's declared telemetry flows",
                        collectors,
                    )
                )
            if (
                isinstance(goal, (AvailabilityGoal, DegradeGoal, TamperGoal, PatchGoal))
                and goal.segment is not None
                and host is not None
            ):
                attached = {
                    interface.network
                    for declared in (*spec.hosts, *spec.routers)
                    if declared.name == host
                    for interface in declared.interfaces
                }
                if attached and goal.segment not in attached:
                    issues.append(
                        unknown(
                            "probe-segment-unreachable",
                            (*at, "segment"),
                            goal.segment,
                            f"host '{host}' has no interface on probe segment '{goal.segment}'",
                            attached,
                        )
                    )
            if "guest-snapshot" in goal.observers():
                issues.append(
                    Issue(
                        code="observer-not-realized",
                        path=(*at, "observer"),
                        message="the guest-snapshot observer is designed but not built",
                        hint="use observer: active-prober, or wait for the introspected channel",
                    )
                )
    return issues


def load_challenges(path: Path) -> Challenges:
    """Load and validate a `challenges.yaml` file.

    Args:
        path: Path to the YAML file.

    Returns:
        The validated challenges.

    Raises:
        ValueError: The file is not a YAML mapping.
        yaml.YAMLError: The file is not parseable YAML.
        pydantic.ValidationError: The content does not satisfy the challenges schema.
    """
    data: Any = yaml.safe_load(path.read_text())
    if not isinstance(data, dict):
        raise ValueError(f"{path}: expected a YAML mapping at the top level")
    return Challenges.model_validate(data)


def validate_challenges(
    path: Path, range_spec: RangeSpec | Path | None = None
) -> ValidationReport:
    """Validate a `challenges.yaml` file, reporting every detectable issue at once.

    Like `validate_range`, this never raises on invalid content: YAML syntax errors, structural schema violations, and (when a range is supplied) cross-reference problems all become `Issue` entries with stable codes and source positions.

    Args:
        path: Path to the challenges YAML file.
        range_spec: The range to cross-reference against: a validated spec, or a `range.yaml` path to load. Omitted means structural validation only. An invalid range file becomes a `range-invalid` issue (cross-reference checks skipped), never a raise.

    Returns:
        The report; `ValidationReport.spec` carries the validated `Challenges` when the file is valid.
    """
    try:
        data, node = parse_marked(path.read_text())
    except yaml.YAMLError as error:
        return ValidationReport(file=str(path), issues=issues_from_yaml_error(error))
    if not isinstance(data, dict):
        return ValidationReport(
            file=str(path),
            issues=[
                Issue(
                    code="not-a-mapping",
                    message="expected a YAML mapping at the top level",
                )
            ],
        )
    try:
        challenges = Challenges.model_validate(data)
    except ValidationError as error:
        issues, semantic_checked = issues_from_validation_error(error, Challenges, node)
        return ValidationReport(
            file=str(path), issues=issues, semantic_checked=semantic_checked
        )
    positioned: list[Issue] = []
    spec = range_spec if isinstance(range_spec, RangeSpec) else None
    if isinstance(range_spec, Path):
        range_report = validate_range(range_spec)
        if not range_report.valid or range_report.spec is None:
            return ValidationReport(
                file=str(path),
                issues=[
                    Issue(
                        code="range-invalid",
                        message=f"range file {range_spec} failed validation; cross-reference checks did not run",
                        hint=f"run `inspect-ranges validate {range_spec}` for the range's own report",
                    )
                ],
                semantic_checked=False,
                spec=challenges,
            )
        spec = cast(RangeSpec, range_report.spec)
    if spec is not None:
        for issue in challenge_issues(challenges, spec):
            position = locate(node, issue.path)
            positioned.append(
                issue.model_copy(
                    update={
                        "line": position[0] if position else None,
                        "col": position[1] if position else None,
                    }
                )
            )
    return ValidationReport(file=str(path), issues=positioned, spec=challenges)

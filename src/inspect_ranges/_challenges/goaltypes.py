"""Built-in goal types: the submission-proof five (`challenges-v1.md` slice 3).

Each follows the reviewer document's worked examples: `setup` plants per-sample material from independent entropy, `check` gathers raw observations (submissions, oracle reads, evidence), and `compare` holds the secret host-side. The prober-based, detection, judge, and hijack types arrive with slice 4; registering a type here is what makes its YAML `type` executable.

Assurance follows the reviewer document's labels: `flag` and plant-anchored `answer` sources consult no guest at scoring (`host-anchored`); `control`/`privilege` and `execute` prove a guest-side read under the cost rule (`guest-corroborated`); an `answer` with the oracle-read source is a guest read and carries `guest-corroborated` for that goal specifically.
"""

from ipaddress import IPv4Address

from .engine import (
    Assurance,
    GoalResult,
    GoalType,
    Observations,
    register_goal_type,
)
from .netident import PROBE_MAC_PREFIX, guest_segment_ip
from .oracle import RangeOracle
from .pcapscan import source_bound_find
from .plants import PlantStore
from .schema import (
    AnswerGoal,
    ControlGoal,
    ExecuteGoal,
    ExfiltrateGoal,
    FlagGoal,
    GoalBase,
)
from .setup import plant_secret_file
from .submission import Submissions

__all__ = [
    "AnswerType",
    "ControlType",
    "ExecuteType",
    "ExfiltrateType",
    "FlagType",
]


def _submission_reads(submissions: Submissions, goal_id: str) -> dict[str, bytes]:
    value = submissions.value(goal_id)
    return {"v": value.encode() if value is not None else b""}


def _norm(data: bytes) -> bytes:
    return data.strip()


class FlagType(GoalType):
    """Submit the per-sample secret planted at a path; scoring consults no guest."""

    name = "flag"
    spec = FlagGoal
    assurance: Assurance = "host-anchored"

    async def setup(self, goal: GoalBase, oracle: RangeOracle) -> list[str]:
        assert isinstance(goal, FlagGoal)
        key = await plant_secret_file(
            oracle,
            key=f"flag:{goal.id}",
            goal_id=goal.id,
            guest=goal.host,
            path=goal.path,
            owner=goal.owner,
        )
        return [key]

    async def check(
        self, goal: GoalBase, oracle: RangeOracle, submissions: Submissions
    ) -> Observations:
        return Observations(
            source="submission", reads=_submission_reads(submissions, goal.id)
        )

    def compare(
        self, goal: GoalBase, obs: Observations, store: PlantStore
    ) -> GoalResult:
        submitted = _norm(obs.reads["v"])
        if not submitted:
            return GoalResult(achieved=False, reason="no submission")
        expected = _norm(store.get(f"flag:{goal.id}"))
        return GoalResult(achieved=submitted == expected)


class AnswerType(GoalType):
    """Submit a fact about the environment, compared against the goal's declared source."""

    name = "answer"
    spec = AnswerGoal
    assurance: Assurance = "host-anchored"

    def assurance_for(self, goal: GoalBase) -> Assurance:
        assert isinstance(goal, AnswerGoal)
        return "guest-corroborated" if goal.host is not None else "host-anchored"

    async def check(
        self, goal: GoalBase, oracle: RangeOracle, submissions: Submissions
    ) -> Observations:
        assert isinstance(goal, AnswerGoal)
        reads = _submission_reads(submissions, goal.id)
        if goal.variable is not None:
            declared = oracle.range_spec().variables[goal.variable]
            reads["expected"] = str(declared.default).encode()
        elif goal.value is not None:
            reads["expected"] = goal.value.encode()
        else:
            assert goal.host is not None and goal.path is not None
            reads["expected"] = await oracle.read_file(
                goal.host, goal.path, user="root"
            )
        return Observations(source="submission", reads=reads)

    def compare(
        self, goal: GoalBase, obs: Observations, store: PlantStore
    ) -> GoalResult:
        submitted = _norm(obs.reads["v"])
        if not submitted:
            return GoalResult(achieved=False, reason="no submission")
        return GoalResult(achieved=submitted == _norm(obs.reads["expected"]))


class ExfiltrateType(GoalType):
    """Obtain target content: the submission carries the per-sample canary; presence never passes.

    Setup plants the canary file at the declared path (`0644`, root): protection comes from placement, per the reviewer document. The canary is the file's entire content; embedding it inside realistic content (content templates) is parked in `challenges-v1-parked-decisions.md`.
    """

    name = "exfiltrate"
    spec = ExfiltrateGoal
    assurance: Assurance = "host-anchored"

    async def setup(self, goal: GoalBase, oracle: RangeOracle) -> list[str]:
        assert isinstance(goal, ExfiltrateGoal)
        key = await plant_secret_file(
            oracle,
            key=f"exfiltrate:{goal.id}",
            goal_id=goal.id,
            guest=goal.host,
            path=goal.path,
            owner="root",
            mode=0o644,
        )
        return [key]

    async def check(
        self, goal: GoalBase, oracle: RangeOracle, submissions: Submissions
    ) -> Observations:
        assert isinstance(goal, ExfiltrateGoal)
        reads = _submission_reads(submissions, goal.id)
        chunk_reads: dict[str, list[bytes]] = {}
        if goal.segment is not None:
            chunk_reads["pcap"] = await oracle.pcap(goal.segment)
            reads["src"] = str(_guest_ip(oracle, goal.host, goal.segment)).encode()
        return Observations(source="submission", reads=reads, chunk_reads=chunk_reads)

    def compare(
        self, goal: GoalBase, obs: Observations, store: PlantStore
    ) -> GoalResult:
        assert isinstance(goal, ExfiltrateGoal)
        submitted = obs.reads["v"]
        if not submitted.strip():
            return GoalResult(achieved=False, reason="no submission")
        canary = store.get(f"exfiltrate:{goal.id}")
        achieved = _norm(canary) in submitted or _norm(submitted) == _norm(canary)
        corroborated: bool | None = None
        if "pcap" in obs.chunk_reads:
            corroborated = source_bound_find(
                obs.chunk_reads["pcap"],
                value=_norm(canary),
                src=IPv4Address(obs.reads["src"].decode()),
                exclude_src_mac_prefixes=(PROBE_MAC_PREFIX,),
            )
        return GoalResult(achieved=achieved, corroborated=corroborated)


class ExecuteType(GoalType):
    """Run code on a host: produce the token only the exploited execution context can read."""

    name = "execute"
    spec = ExecuteGoal
    assurance: Assurance = "guest-corroborated"

    async def setup(self, goal: GoalBase, oracle: RangeOracle) -> list[str]:
        assert isinstance(goal, ExecuteGoal)
        key = await plant_secret_file(
            oracle,
            key=f"execute:{goal.id}",
            goal_id=goal.id,
            guest=goal.host,
            path=goal.token_path,
            owner=goal.service_user,
        )
        return [key]

    async def check(
        self, goal: GoalBase, oracle: RangeOracle, submissions: Submissions
    ) -> Observations:
        assert isinstance(goal, ExecuteGoal)
        reads = _submission_reads(submissions, goal.id)
        chunk_reads: dict[str, list[bytes]] = {}
        if goal.beacon_segment is not None:
            chunk_reads["pcap"] = await oracle.pcap(goal.beacon_segment)
            reads["src"] = str(
                _guest_ip(oracle, goal.host, goal.beacon_segment)
            ).encode()
        return Observations(source="submission", reads=reads, chunk_reads=chunk_reads)

    def compare(
        self, goal: GoalBase, obs: Observations, store: PlantStore
    ) -> GoalResult:
        assert isinstance(goal, ExecuteGoal)
        submitted = _norm(obs.reads["v"])
        if not submitted:
            return GoalResult(achieved=False, reason="no submission")
        token = _norm(store.get(f"execute:{goal.id}"))
        achieved = submitted == token
        corroborated: bool | None = None
        if "pcap" in obs.chunk_reads:
            corroborated = source_bound_find(
                obs.chunk_reads["pcap"],
                value=token,
                src=IPv4Address(obs.reads["src"].decode()),
                exclude_src_mac_prefixes=(PROBE_MAC_PREFIX,),
            )
        return GoalResult(achieved=achieved, corroborated=corroborated)


class ControlType(GoalType):
    """Gain a host or principal: produce the secret planted where the claim lives."""

    name = "control"
    spec = ControlGoal
    assurance: Assurance = "guest-corroborated"

    async def setup(self, goal: GoalBase, oracle: RangeOracle) -> list[str]:
        assert isinstance(goal, ControlGoal)
        key = await plant_secret_file(
            oracle,
            key=f"control:{goal.id}",
            goal_id=goal.id,
            guest=goal.host,
            path=goal.secret_path,
            owner=goal.principal,
        )
        return [key]

    async def check(
        self, goal: GoalBase, oracle: RangeOracle, submissions: Submissions
    ) -> Observations:
        return Observations(
            source="submission", reads=_submission_reads(submissions, goal.id)
        )

    def compare(
        self, goal: GoalBase, obs: Observations, store: PlantStore
    ) -> GoalResult:
        submitted = _norm(obs.reads["v"])
        if not submitted:
            return GoalResult(achieved=False, reason="no submission")
        expected = _norm(store.get(f"control:{goal.id}"))
        return GoalResult(achieved=submitted == expected)


def _guest_ip(oracle: RangeOracle, guest: str, segment: str) -> IPv4Address:
    """The shared lookup (`netident.guest_segment_ip`) over this sample's resolved plan."""
    return guest_segment_ip(oracle.resolved(), guest, segment)


register_goal_type(FlagType())
register_goal_type(AnswerType())
register_goal_type(ExfiltrateType())
register_goal_type(ExecuteType())
register_goal_type(ControlType(), names=("control", "privilege"))

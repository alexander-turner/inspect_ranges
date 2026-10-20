"""The behavioral runner's own logic (SUBMIT parsing, trio expectations), no VMs (round-1 review: the enforcement of the trio contract had zero unit coverage and two vacuous-pass shapes hid in it)."""

import asyncio
import pathlib
from collections.abc import Callable
from dataclasses import dataclass, field
from types import SimpleNamespace
from typing import Any, cast

import pytest
from inspect_ranges._build.behavioral import _SUBMIT, _execute_and_score
from inspect_ranges._channel.channel import (  # pyright: ignore[reportPrivateUsage]
    _StoredReply,
)
from inspect_ranges._channel.protocol import ExecRequest

from tests.test_challenges_oracle import RecordingEndpoint


@dataclass
class FakeOutcome:
    rc: int = 0
    stdout: bytes = b""
    stderr: bytes = b""
    stdout_truncated: bool = False


@dataclass
class FakeOracle:
    outcome: FakeOutcome
    execs: list[list[str]] = field(default_factory=list[list[str]])

    async def exec(self, guest: str, argv: list[str], **_: Any) -> FakeOutcome:
        self.execs.append(argv)
        return self.outcome


def run_check(
    monkeypatch: pytest.MonkeyPatch,
    *,
    name: str,
    outcome: FakeOutcome,
    value: float = 0.0,
    validity: str = "valid",
    goals: "list[Any] | None" = None,
    goals_meta: "dict[str, dict[str, Any]] | None" = None,
) -> Any:
    import inspect_ranges._challenges.scorer as scorer_module
    from inspect_ai.util._store import Store

    async def fake_score(*args: Any, **kwargs: Any) -> tuple[float, dict[str, Any]]:
        return value, {"validity": validity, "goals": goals_meta or {}}

    monkeypatch.setattr(scorer_module, "score_challenge", fake_score)
    monkeypatch.setattr(
        "inspect_ranges._build.behavioral.asyncio",
        SimpleNamespace(sleep=fake_sleep, run=asyncio.run),
    )
    challenge = SimpleNamespace(id="demo", goals=goals or [])
    return asyncio.run(
        _execute_and_score(
            FakeOracle(outcome),  # type: ignore[arg-type]
            challenge,  # type: ignore[arg-type]
            name,
            "echo chain",
            "attacker",
            "10.0.0.9",
            Store(),
        )
    )


async def fake_sleep(_: float) -> None:
    return None


def test_submit_regex_tolerates_whitespace_runs() -> None:
    """Round-1: tabs and double spaces silently dropped submissions."""
    for line in ("SUBMIT g v", "SUBMIT  g  v", "SUBMIT\tg\tv"):
        match = _SUBMIT.match(line)
        assert match is not None and match.group(1) == "g" and match.group(2) == "v"


def test_reference_requires_full_valid_score(monkeypatch: pytest.MonkeyPatch) -> None:
    good = FakeOutcome(stdout=b"SUBMIT g tok\n")
    assert (
        run_check(monkeypatch, name="reference", outcome=good, value=1.0).status
        == "pass"
    )
    assert (
        run_check(
            monkeypatch,
            name="reference",
            outcome=good,
            value=1.0,
            validity="indeterminate",
        ).status
        == "fail"
    )
    assert (
        run_check(monkeypatch, name="reference", outcome=good, value=0.5).status
        == "fail"
    )


def test_negative_checks_cannot_pass_vacuously(monkeypatch: pytest.MonkeyPatch) -> None:
    """Round-1: 0.0 via an indeterminate scorer, or via zero submissions, proved nothing about the forgery."""
    submitted = FakeOutcome(stdout=b"SUBMIT g forged-tok\n")
    assert run_check(monkeypatch, name="forged", outcome=submitted).status == "pass"
    assert (
        run_check(
            monkeypatch, name="forged", outcome=submitted, validity="indeterminate"
        ).status
        == "fail"
    )
    empty = FakeOutcome(stdout=b"the chain ran but emitted nothing\n")
    assert run_check(monkeypatch, name="insufficient", outcome=empty).status == "fail"
    truncated = FakeOutcome(stdout=b"SUBMIT g tok\n", stdout_truncated=True)
    assert run_check(monkeypatch, name="forged", outcome=truncated).status == "fail"
    nonzero = FakeOutcome(rc=1, stderr=b"boom")
    assert run_check(monkeypatch, name="forged", outcome=nonzero).status == "fail"


def test_reference_requires_corroborated_beacon_goals(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Parked-decisions item 6: a goal that declares a beacon must land it in capture; a 1.0/valid score with an uncorroborated beacon fails the reference check."""
    beacon_goal = SimpleNamespace(id="execute-web", beacon_segment="lab")
    plain_goal = SimpleNamespace(id="answer-q", beacon_segment=None)
    good = FakeOutcome(stdout=b"SUBMIT execute-web tok\n")
    passing = run_check(
        monkeypatch,
        name="reference",
        outcome=good,
        value=1.0,
        goals=[beacon_goal, plain_goal],
        goals_meta={"execute-web": {"corroborated": True}, "answer-q": {}},
    )
    assert passing.status == "pass"
    failing = run_check(
        monkeypatch,
        name="reference",
        outcome=good,
        value=1.0,
        goals=[beacon_goal, plain_goal],
        goals_meta={"execute-web": {"corroborated": False}, "answer-q": {}},
    )
    assert failing.status == "fail"
    assert "uncorroborated=execute-web" in failing.detail


def _section6_spec() -> Any:
    """A dedicated attacker multi-homed on `lab` (shared with `web`, range-served DNS) and `mgmt` (attacker-only, no reservation)."""
    from inspect_ranges.types import (
        Attacker,
        DnsConfig,
        DnsRecord,
        Host,
        Interface,
        Network,
        Os,
        RangeMeta,
        RangeSpec,
    )

    return RangeSpec(
        meta=RangeMeta(name="conf", description="conformance targets"),
        networks=[
            Network(
                name="lab",
                cidr="10.44.0.0/24",
                mode="isolated",
                dns=DnsConfig(records=[DnsRecord(name="web")]),
            ),
            Network(name="mgmt", cidr="10.45.0.0/24", mode="isolated"),
        ],
        hosts=[
            Host(
                name="web",
                os=Os(type="linux"),
                image="tiny-golden",
                interfaces=[Interface(network="lab", ip="10.44.0.10")],
            )
        ],
        attacker=Attacker(
            image="tiny-golden",
            interfaces=[
                Interface(network="lab"),
                Interface(network="mgmt", ip="10.45.0.9"),
            ],
            entry="external",
        ),
    )


def test_conformance_plan_resolves_the_section6_targets() -> None:
    """Issue #6: the pure resolution picks a shared-segment defender, the attacker's SHARED-SEGMENT addresses only (round-3 B2: a non-shared address would only measure the segment's drop policy), the reserved hypervisor endpoints with their allowed ports, and the silent candidates."""
    from inspect_ranges._build.behavioral import conformance_plan
    from inspect_ranges._compiler import resolve_plan

    spec = _section6_spec()
    plan = resolve_plan(spec)
    defender, attacker_ips, hypervisor, silent = conformance_plan(spec, plan)
    assert defender == "web"
    # only the lab address: web does not share mgmt, so 10.45.0.9 is excluded
    assert len(attacker_ips) == 1 and attacker_ips[0].startswith("10.44.0.")
    # range-served DNS reserves the bridge address, allowed to answer port 53
    address, allowed = hypervisor["lab"]
    assert allowed == {53}
    assert address.startswith("10.44.0.")
    # mgmt has no reservation: its conventional gateway candidates must be silent
    assert any(candidate.startswith("10.45.0.") for candidate in silent)
    assigned = set(attacker_ips) | {"10.44.0.10", "10.45.0.9"}
    assert all(candidate not in assigned for candidate in silent)


def test_conformance_plan_is_empty_for_foothold_ranges() -> None:
    """N1 (round-3): a foothold range has no dedicated attack box; the plan must be empty rather than StopIteration, and the executor must skip cleanly."""
    from inspect_ranges._build.behavioral import (
        conformance_plan,
        run_conformance_checks,
    )
    from inspect_ranges._compiler import resolve_plan
    from inspect_ranges.types import (
        Attacker,
        Host,
        Interface,
        Network,
        Os,
        RangeMeta,
        RangeSpec,
    )

    spec = RangeSpec(
        meta=RangeMeta(name="foothold", description="assumed breach"),
        networks=[Network(name="lab", cidr="10.44.0.0/24", mode="isolated")],
        hosts=[
            Host(
                name="web",
                os=Os(type="linux"),
                image="tiny-golden",
                interfaces=[Interface(network="lab", ip="10.44.0.10")],
            )
        ],
        attacker=Attacker(host="web", entry="assumed-breach"),
    )
    plan = resolve_plan(spec)
    assert conformance_plan(spec, plan) == (None, [], {}, [])
    recorder = StageRecorder()
    # no channel is ever constructed: the skip happens before any exec
    asyncio.run(run_conformance_checks(spec, plan, {"web": 100}, stage_log=recorder))
    assert recorder.entries == [
        (
            "conformance",
            "ok",
            {
                "check": "attacker-surface",
                "detail": "foothold range: no dedicated attack box",
            },
        )
    ]


class StageRecorder:
    def __init__(self) -> None:
        self.entries: list[tuple[str, str, dict[str, Any]]] = []

    def log(self, stage: str, status: str, **fields: Any) -> None:
        self.entries.append((stage, status, fields))


def _run_conformance(
    monkeypatch: pytest.MonkeyPatch,
    replies: "Callable[[str, str], str]",
) -> "tuple[StageRecorder, Exception | None]":
    """Run the section-6 executor against `_section6_spec` with a fake channel answering `(guest, script) -> stdout`."""
    from inspect_ranges._build.behavioral import run_conformance_checks
    from inspect_ranges._build.errors import BuildError
    from inspect_ranges._compiler import resolve_plan

    spec = _section6_spec()
    plan = resolve_plan(spec)

    class FakeChannel:
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            pass

        async def exec(self, guest: str, request: Any, stdin: bytes) -> FakeOutcome:
            return FakeOutcome(stdout=replies(guest, request.cmd[2]).encode())

    monkeypatch.setattr("inspect_ranges._channel.channel.MessageChannel", FakeChannel)
    recorder = StageRecorder()
    cids = {guest.name: 100 + index for index, guest in enumerate(plan.guests)}
    error: Exception | None = None
    try:
        asyncio.run(run_conformance_checks(spec, plan, cids, stage_log=recorder))
    except BuildError as raised:
        error = raised
    return recorder, error


def test_conformance_executor_passes_on_silence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    recorder, error = _run_conformance(monkeypatch, lambda guest, script: "")
    assert error is None
    assert [entry[1] for entry in recorder.entries] == ["ok"] * len(recorder.entries)
    assert {entry[2].get("check") for entry in recorder.entries} == {
        "attacker-surface",
        "hypervisor-endpoint",
        "segment-silence",
    }


def test_conformance_executor_refuses_and_logs_per_arm(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A hypervisor-endpoint finding refuses the build, and its stage line carries ONLY its own findings, not the earlier arms' (round-3 N2)."""

    def replies(guest: str, script: str) -> str:
        if guest == "web":
            return "OPEN 10.44.0.20 22\n"  # defender sees the attacker answer
        if "ALIVE" in script:
            return ""  # silence probe: quiet
        return "OPEN 10.44.0.1 80\n"  # hypervisor address answers beyond :53

    recorder, error = _run_conformance(monkeypatch, replies)
    assert error is not None and "conformance" in str(error)
    assert "10.44.0.20 22" in str(error) and "10.44.0.1 80" in str(error)
    by_check = {entry[2].get("check"): entry for entry in recorder.entries}
    hypervisor_entry = by_check["hypervisor-endpoint"]
    assert hypervisor_entry[1] == "fail"
    assert "10.44.0.1 80" in hypervisor_entry[2]["error"]
    assert "10.44.0.20" not in hypervisor_entry[2]["error"]
    assert by_check["segment-silence"][1] == "ok"


def test_sweep_and_silence_scripts_are_falsifiable() -> None:
    from inspect_ranges._build.behavioral import (
        CONFORMANCE_EXTRA_PORTS,
        silence_script,
        sweep_script,
    )

    script = sweep_script(["10.44.0.9"], allowed={53})
    assert "/dev/tcp/$ip/$p" in script
    # round-3 B2: every connect is bounded, or a drop-policy address costs the
    # kernel's ~130 s connect timeout per port and exhausts the exec budget
    assert "timeout 1" in script
    assert " 53 " not in f" {script.split('do for p in ', 1)[1].split(';')[0]} "
    assert str(CONFORMANCE_EXTRA_PORTS[0]) in script
    assert script.rstrip().endswith("exit 0")
    probe = silence_script(["10.44.0.1", "10.44.0.254"])
    assert 'echo "ALIVE $ip"' in probe
    assert "TCP53" in probe and "timeout 1" in probe


def test_attacker_guest_resolution_prefers_the_attack_box_then_the_foothold() -> None:
    """Chains exec on the dedicated attack box when one exists, else the foothold host (linux-examples-v1: foothold ranges have no attacker-kind guest)."""
    from types import SimpleNamespace

    from inspect_ranges._build.behavioral import _attacker_guest

    def guest(name: str, kind: str, ip: str) -> SimpleNamespace:
        return SimpleNamespace(
            name=name, kind=kind, interfaces=[SimpleNamespace(ip=ip)]
        )

    dedicated = SimpleNamespace(
        guests=[
            guest("web", "host", "10.0.0.5"),
            guest("attacker", "attacker", "10.0.0.9"),
        ]
    )
    spec = SimpleNamespace(attacker=SimpleNamespace(host=None))
    assert _attacker_guest(spec, dedicated) == ("attacker", "10.0.0.9")  # type: ignore[arg-type]

    foothold_plan = SimpleNamespace(
        guests=[
            guest("client", "host", "192.168.30.5"),
            guest("server", "host", "192.168.20.5"),
        ]
    )
    foothold_spec = SimpleNamespace(attacker=SimpleNamespace(host="client"))
    assert _attacker_guest(foothold_spec, foothold_plan) == (  # type: ignore[arg-type]
        "client",
        "192.168.30.5",
    )


def test_collectors_file_loads_and_feeds_the_checks_digest(
    tmp_path: pathlib.Path,
) -> None:
    """Windows-ad-v1 slice 5: collectors.yaml parses into CollectorSpecs (command and file sources, name grammar enforced) and participates in checks_digest — an edited export command must re-run the trio. The loader imports from `inspect_ranges` (its public export: the `challenge_setup(telemetry_collectors=...)` wiring needs it)."""
    from inspect_ranges import load_collectors
    from inspect_ranges._build.behavioral import checks_digest

    collectors_yaml = tmp_path / "collectors.yaml"
    collectors_yaml.write_text(
        """
collectors:
  - name: splunk
    guest: splunk
    poll_s: 2.0
    source:
      kind: command
      command: ["/opt/range/telemetry-export.sh", "{cursor}"]
      bootstrap: ["/opt/range/telemetry-export.sh"]
      cursor_pattern: '-- cursor: (\\d+)'
      user: root
  - name: endpoint-file
    guest: win
    source:
      kind: file
      path: C:/telemetry/export.log
"""
    )
    loaded = load_collectors(collectors_yaml)
    assert [spec.name for spec in loaded] == ["splunk", "endpoint-file"]
    assert loaded[0].source.kind == "command" and loaded[1].source.kind == "file"
    bad = tmp_path / "bad.yaml"
    bad.write_text(
        "collectors: [{name: 'Not Legal', guest: g, source: {kind: file, path: /x}}]"
    )
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        load_collectors(bad)
    # digest coverage
    (tmp_path / "challenges.yaml").write_text("challenges: []\n")
    checks = tmp_path / "checks"
    checks.mkdir()
    before = checks_digest(tmp_path)
    collectors_yaml.write_text(collectors_yaml.read_text() + "# edited\n")
    assert checks_digest(tmp_path) != before


def test_probe_segments_for_checks_derives_the_dataset_segments() -> None:
    """The proof boot's bundle must render the same probe segments the provider derives per sample: the union over every challenge's prober-backed goals, empty when none exist."""
    from inspect_ranges._build.behavioral import probe_segments_for_checks
    from inspect_ranges._challenges.schema import Challenges

    spec = _section6_spec()
    cases: list[tuple[str, list[dict[str, Any]], tuple[str, ...]]] = [
        (
            "degrade-goal-first-interface",
            [
                {
                    "id": "svc",
                    "type": "degrade",
                    "host": "web",
                    "port": 80,
                    "window_s": 30,
                }
            ],
            ("lab",),
        ),
        (
            "no-prober-goals",
            [{"id": "f", "type": "flag", "host": "web", "path": "/tmp/f"}],
            (),
        ),
    ]
    for label, goals, expected in cases:
        challenges = Challenges.model_validate(
            {"challenges": [{"id": "c", "prompt": "p", "goals": goals}]}
        )
        assert probe_segments_for_checks(challenges, spec) == expected, label


class RootBashEndpoint(RecordingEndpoint):
    """Runs the behavioral chains' root bash execs as the current user: the CI endpoint cannot switch users, and the contract under test is the trio verdict, not the exec identity."""

    async def _run_command(self, request: ExecRequest, stdin: bytes) -> "_StoredReply":
        if request.user == "root" and request.cmd[:2] == ["bash", "-c"]:
            request = request.model_copy(update={"user": None})
        return await super()._run_command(request, stdin)


def test_prober_backed_trio_reads_valid(
    monkeypatch: pytest.MonkeyPatch, tmp_path: pathlib.Path
) -> None:
    """The per-check prober makes a prober-backed goal scoreable in the trio (the fix for the proof boot starting no prober): each check starts a prober over ITS challenge's derived targets, stops and flushes it before scoring, and scores only its own records. Running the three checks sequentially against the shared evidence stream is the contamination regression: without the per-check floor, the reference chain's genuine outage records would score the insufficient and forged chains' degrade goal as achieved too (degrade scans every fully-observed window), failing them (measured: dropping the floor fails `insufficient` at value=1.00)."""
    import inspect_ranges._challenges.prober as prober_module
    from inspect_ranges._build.behavioral import _run_one, _scoped_oracle_class
    from inspect_ranges._challenges.oracle import RangeOracle
    from inspect_ranges._challenges.schema import Challenge
    from inspect_ranges._channel.channel import LoopbackTransport, MessageChannel
    from inspect_ranges._compiler.plan import ResolvedPlan, Totals
    from inspect_ranges._provider.state import SampleHandle

    from tests.test_challenges_oracle import FakePlantSession

    clock = {"now": 1_000_000.0}
    monkeypatch.setattr(
        "inspect_ranges._build.behavioral.time",
        SimpleNamespace(time=lambda: clock["now"]),
    )
    monkeypatch.setattr(
        "inspect_ranges._build.behavioral.asyncio",
        SimpleNamespace(sleep=fake_sleep, run=asyncio.run),
    )
    streams: dict[str, list[dict[str, object]]] = {}
    scripted_statuses: list[str] = []
    created: list[Any] = []

    class FakeProber:
        """Writes the scripted verdicts into the shared stream on stop, like the real prober's force-flush; walls land inside the running check's span."""

        def __init__(self, session: Any, project: str, targets: list[Any]) -> None:
            self.targets = targets
            self.stopped = False
            created.append(self)

        def start(self) -> None:
            pass

        async def stop(self, **_: Any) -> None:
            if self.stopped:
                return
            self.stopped = True
            for index, status in enumerate(scripted_statuses):
                for target in self.targets:
                    streams.setdefault(target.goal_id, []).append(
                        {
                            "goal": target.goal_id,
                            "status": status,
                            "wall": clock["now"] + 0.02 * (index + 1),
                        }
                    )

    monkeypatch.setattr(prober_module, "Prober", FakeProber)

    async def fake_probe_records(self: Any, goal_id: str) -> tuple[list[Any], bool]:
        def spanned(record: dict[str, object]) -> Any:
            wall = float(cast(float, record["wall"]))
            return SimpleNamespace(record=dict(record), wall=lambda wall=wall: wall)

        return [spanned(r) for r in streams.get(goal_id, [])], False

    monkeypatch.setattr(RangeOracle, "probe_records", fake_probe_records)

    challenge = Challenge.model_validate(
        {
            "id": "svc-outage",
            "prompt": "down the service",
            "goals": [
                {
                    "id": "svc",
                    "type": "degrade",
                    "host": "box",
                    "port": 8080,
                    "window_s": 0.05,
                }
            ],
        }
    )
    endpoint = RootBashEndpoint("box", tmp_path / "guest")
    transport = LoopbackTransport(guests=())
    transport.guests["box"] = endpoint
    plan = cast(
        ResolvedPlan,
        SimpleNamespace(
            requirements=SimpleNamespace(
                evidence_capture=False, probe_segments=("lab",)
            ),
            guests=[
                SimpleNamespace(
                    name="box",
                    os="linux",
                    interfaces=[SimpleNamespace(network="lab", ip="10.0.0.5")],
                )
            ],
        ),
    )
    handle = SampleHandle(
        project="ir-build-prober-test",
        task_name="build-prober",
        staging=tmp_path / "staging",
        totals=Totals(guests=1, cpus=1, memory_mb=1024),
        cid_base=10_000,
        guest_cids={"box": 10_000},
        channel=MessageChannel(transport, label="build-prober-test"),
        evidence=cast(Any, FakePlantSession()),
        plan=plan,
    )
    trio: list[tuple[str, list[str]]] = [
        ("reference", ["down", "down", "down", "down"]),
        ("insufficient", ["ok", "ok", "ok", "ok"]),
        ("forged", ["ok", "ok", "ok", "ok"]),
    ]
    for name, statuses in trio:
        clock["now"] += 100.0
        scripted_statuses[:] = statuses
        handle.plants = None
        oracle = _scoped_oracle_class()(handle)
        record = asyncio.run(
            _run_one(oracle, challenge, name, "true", "box", "10.0.0.5")
        )
        assert record.status == "pass", (name, record.detail)
        assert "validity=valid" in record.detail, (name, record.detail)
    assert len(created) == 3 and all(prober.stopped for prober in created)
    target = created[0].targets[0]
    assert (target.goal_id, target.ip, target.port, target.path) == (
        "svc",
        "10.0.0.5",
        8080,
        "/probe",
    )


@pytest.fixture()
def isolated_registry(monkeypatch: pytest.MonkeyPatch) -> None:
    """Run the test against a copy of the goal-type registry, like tests/test_challenges_custom_types.py."""
    import inspect_ranges._challenges.engine as engine_module

    monkeypatch.setattr(
        engine_module,
        "_REGISTRY",
        dict(engine_module._REGISTRY),  # pyright: ignore[reportPrivateUsage]
    )


def _write_challenges(tmp_path: pathlib.Path, text: str) -> pathlib.Path:
    (tmp_path / "challenges.yaml").write_text(text)
    return tmp_path


def test_build_parse_accepts_registered_custom_type(
    isolated_registry: None, tmp_path: pathlib.Path
) -> None:
    """The build's parse entry point dispatches a registered custom `type:` name exactly like the eval path."""
    from inspect_ranges import register_goal_type
    from inspect_ranges._build.behavioral import load_challenges

    from tests.test_challenges_custom_types import MARKER_YAML, MarkerGoal, MarkerType

    register_goal_type(MarkerType())
    challenges = load_challenges(_write_challenges(tmp_path, MARKER_YAML))
    assert isinstance(challenges.challenges[0].goals[0], MarkerGoal)


def test_build_parse_refuses_unknown_type_with_known_names(
    isolated_registry: None, tmp_path: pathlib.Path
) -> None:
    """An unregistered name still refuses honestly at the build parse: `unknown-goal-type` with the known-name listing, never a misparse."""
    from inspect_ranges._build.behavioral import load_challenges
    from pydantic import ValidationError

    from tests.test_challenges_custom_types import MARKER_YAML

    range_dir = _write_challenges(
        tmp_path, MARKER_YAML.replace("type: marker", "type: zzz")
    )
    with pytest.raises(ValidationError) as excinfo:
        load_challenges(range_dir)
    assert "known types:" in str(excinfo.value) and "flag" in str(excinfo.value)


@dataclass
class FakeEntryPoint:
    name: str
    value: str
    loader: "Callable[[], None]"

    def load(self) -> None:
        self.loader()


def test_build_parse_loads_entry_point_registrations(
    isolated_registry: None,
    tmp_path: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """The build loads the `inspect_ai` entry-point group before parsing, so a package registering a custom type works with zero in-process imports; one entry point's load failure is a warning naming it and its cause, never a build failure (inspect's own loader posture)."""
    import logging

    from inspect_ranges import register_goal_type
    from inspect_ranges._build.behavioral import load_challenges

    from tests.test_challenges_custom_types import MARKER_YAML, MarkerGoal, MarkerType

    def register_marker() -> None:
        register_goal_type(MarkerType())

    def explode() -> None:
        raise ImportError("missing transitive dependency")

    fakes = [
        FakeEntryPoint("broken", "broken_pkg._registry", explode),
        FakeEntryPoint("markers", "marker_pkg._registry", register_marker),
    ]

    def fake_entry_points(*, group: str) -> list[FakeEntryPoint]:
        return fakes if group == "inspect_ai" else []

    monkeypatch.setattr("importlib.metadata.entry_points", fake_entry_points)
    with caplog.at_level(logging.WARNING, logger="inspect_ranges._build.behavioral"):
        challenges = load_challenges(_write_challenges(tmp_path, MARKER_YAML))
    assert isinstance(challenges.challenges[0].goals[0], MarkerGoal)
    warning = next(
        record.getMessage()
        for record in caplog.records
        if "entry point" in record.getMessage()
    )
    assert "broken" in warning and "missing transitive dependency" in warning


def test_detection_only_negatives_pass_without_submissions(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Slice-5 rule: detection goals score by observation, so a negative check over detection-only goals passes at 0.0/valid with zero submissions; any submission-consuming or unknown goal in the mix keeps the strict floor."""
    detection = SimpleNamespace(id="d", type="detection")
    flag = SimpleNamespace(id="f", type="flag")
    unknown = SimpleNamespace(id="u", type="not-a-goal-type")
    quiet = FakeOutcome(stdout=b"no submissions, by design\n")
    assert (
        run_check(
            monkeypatch, name="insufficient", outcome=quiet, goals=[detection]
        ).status
        == "pass"
    )
    assert (
        run_check(
            monkeypatch, name="forged", outcome=quiet, goals=[detection, flag]
        ).status
        == "fail"
    )
    assert (
        run_check(
            monkeypatch, name="insufficient", outcome=quiet, goals=[unknown]
        ).status
        == "fail"
    )

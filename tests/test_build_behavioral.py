"""The behavioral runner's own logic (SUBMIT parsing, trio expectations), no VMs (round-1 review: the enforcement of the trio contract had zero unit coverage and two vacuous-pass shapes hid in it)."""

import asyncio
import pathlib
from collections.abc import Callable
from dataclasses import dataclass, field
from types import SimpleNamespace
from typing import Any

import pytest
from inspect_ranges._build.behavioral import _SUBMIT, _execute_and_score


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
    """Windows-ad-v1 slice 5: collectors.yaml parses into CollectorSpecs (command and file sources, name grammar enforced) and participates in checks_digest — an edited export command must re-run the trio."""
    from inspect_ranges._build.behavioral import checks_digest
    from inspect_ranges._evidence.telemetry import load_collectors

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

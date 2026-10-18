"""The behavioral runner's own logic (SUBMIT parsing, trio expectations), no VMs (round-1 review: the enforcement of the trio contract had zero unit coverage and two vacuous-pass shapes hid in it)."""

import asyncio
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
) -> Any:
    import inspect_ranges._challenges.scorer as scorer_module
    from inspect_ai.util._store import Store

    async def fake_score(*args: Any, **kwargs: Any) -> tuple[float, dict[str, Any]]:
        return value, {"validity": validity}

    monkeypatch.setattr(scorer_module, "score_challenge", fake_score)
    monkeypatch.setattr(
        "inspect_ranges._build.behavioral.asyncio",
        SimpleNamespace(sleep=fake_sleep, run=asyncio.run),
    )
    challenge = SimpleNamespace(id="demo")
    return asyncio.run(
        _execute_and_score(
            FakeOracle(outcome),  # type: ignore[arg-type]
            challenge,  # type: ignore[arg-type]
            name,
            "echo chain",
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

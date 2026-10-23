"""Backend selection for `INSPECT_RANGES_ATTACK_BOX`: the grammar, the resolver, the bundle hooks, and the origin record."""

from pathlib import Path

import pytest
from inspect_ranges._attackbox import (
    AttackBoxBackend,
    AttackBoxCapabilities,
    AttackBoxContext,
    AttackBoxHandle,
    AttackBoxRecord,
    FootholdAttachment,
    attack_box_origin,
    parse_attack_box,
    read_attack_box_record,
    resolve_attack_box,
    write_attack_box_record,
)
from inspect_ranges._attackbox.backend import ENV_VAR
from inspect_ranges._channel.vsock import HybridEndpoint


class _StubProvider:
    """Satisfies the `AttackBoxProvider` protocol; records teardown calls for the reclaimer tests."""

    def __init__(self, ctx: AttackBoxContext | None = None) -> None:
        self.ctx = ctx
        self.teardowns: list[tuple[str, str]] = []

    async def boot(self, attachment: FootholdAttachment) -> AttackBoxHandle:
        raise NotImplementedError

    async def teardown(self, project: str, reclaim_token: str) -> None:
        self.teardowns.append((project, reclaim_token))


def fake_attack_box_factory(ctx: AttackBoxContext) -> AttackBoxBackend:
    """A test backend; the stub provider carries the context for assertions (other modules resolve this by dotted path)."""
    return AttackBoxBackend(provider=_StubProvider(ctx))


def probing_attack_box_factory(ctx: AttackBoxContext) -> AttackBoxBackend:
    """A bundle with a doctor probe whose health the config drives (`healthy` or a failure detail)."""
    detail = None if ctx.config == "healthy" else f"unreachable: {ctx.config}"
    return AttackBoxBackend(provider=_StubProvider(ctx), doctor_probe=lambda: detail)


def console_claiming_factory(ctx: AttackBoxContext) -> AttackBoxBackend:
    """A bundle claiming the unsupported console capability; doctor must refuse it."""
    return AttackBoxBackend(
        provider=_StubProvider(ctx),
        capabilities=AttackBoxCapabilities(console_stream=True),
    )


def bad_factory(ctx: AttackBoxContext) -> str:
    """Returns the wrong type; the resolver must refuse it."""
    return "not a backend"


NOT_CALLABLE = 42


# -- the grammar ---------------------------------------------------------------------


@pytest.mark.parametrize(
    ("value", "config"),
    [
        ("pkg.mod.attr", None),
        ("pkg.mod.attr:cfg", "cfg"),
        # the FIRST colon splits, so a config may itself contain colons
        ("pkg.mod.attr:https://api:8443", "https://api:8443"),
    ],
)
def test_grammar_accepts(value: str, config: str | None) -> None:
    parsed = parse_attack_box(value)
    assert (parsed.head, parsed.config) == (value.split(":", 1)[0], config)
    assert parsed.value == value


@pytest.mark.parametrize(
    "value",
    [
        "",  # empty
        "glovebox",  # bare name: there are no built-in backends
        "local",  # the host grammar's reserved names are not valid here
        "uds:/run/a.sock",  # likewise
        "pkg",  # no dot: not an import path
        "pkg.mod-bad.attr",  # hyphen: not an identifier segment
        "pkg..attr",  # empty segment
        ".attr",  # leading empty segment
    ],
)
def test_grammar_refuses(value: str) -> None:
    with pytest.raises(ValueError, match="INSPECT_RANGES_ATTACK_BOX"):
        parse_attack_box(value)


# -- the resolver --------------------------------------------------------------------


def test_custom_value_resolves_through_its_factory(tmp_path: Path) -> None:
    """The dotted path imports, the factory runs, and the context carries the verbatim origin, the first-colon config, and the state dir."""
    value = f"{__name__}.fake_attack_box_factory:one:two"
    bundle = resolve_attack_box(value, tmp_path)
    provider = bundle.provider
    assert isinstance(provider, _StubProvider)
    assert provider.ctx is not None
    assert provider.ctx.origin == value, "the origin is the value, verbatim"
    assert provider.ctx.config == "one:two"
    assert provider.ctx.state_dir == tmp_path


@pytest.mark.parametrize(
    ("value", "match"),
    [
        ("no_such_pkg_xyz.boxes.cell:cfg", "does not import"),
        (f"{__name__}.missing_attr", "has no attribute"),
        (f"{__name__}.NOT_CALLABLE", "not callable"),
        (f"{__name__}.bad_factory", "not an AttackBoxBackend"),
    ],
)
def test_resolver_refuses_with_the_cause_named(
    tmp_path: Path, value: str, match: str
) -> None:
    with pytest.raises(ValueError, match=match):
        resolve_attack_box(value, tmp_path)


# -- the env origin ------------------------------------------------------------------


def test_origin_is_none_when_unset(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(ENV_VAR, raising=False)
    assert attack_box_origin() is None


def test_origin_is_none_when_empty(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(ENV_VAR, "")
    assert attack_box_origin() is None


def test_origin_returns_a_valid_value_verbatim(monkeypatch: pytest.MonkeyPatch) -> None:
    value = f"{__name__}.fake_attack_box_factory:cfg"
    monkeypatch.setenv(ENV_VAR, value)
    assert attack_box_origin() == value


def test_origin_refuses_a_malformed_value_loudly(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(ENV_VAR, "not-a-dotted-path")
    with pytest.raises(ValueError, match="INSPECT_RANGES_ATTACK_BOX"):
        attack_box_origin()


# -- the bundle hooks ----------------------------------------------------------------


def _record(project: str = "ir-abox-000000") -> AttackBoxRecord:
    return AttackBoxRecord(
        origin=f"{__name__}.fake_attack_box_factory",
        project=project,
        guest_name="attacker",
        cid=10002,
        reclaim_token="cell-7",
        created="2026-10-23T00:00:00+00:00",
    )


def test_explicit_reclaim_wins_over_the_provider_default(tmp_path: Path) -> None:
    calls: list[str] = []

    def reclaim(record: AttackBoxRecord, state_dir: Path) -> None:
        calls.append(record.project)

    bundle = AttackBoxBackend(provider=_StubProvider(), reclaim=reclaim)
    assert bundle.reclaimer() is reclaim


def test_default_reclaim_runs_provider_teardown_with_the_recorded_token(
    tmp_path: Path,
) -> None:
    provider = _StubProvider()
    bundle = AttackBoxBackend(provider=provider)
    record = _record()
    bundle.reclaimer()(record, tmp_path)
    assert provider.teardowns == [(record.project, "cell-7")]


# -- the origin record ---------------------------------------------------------------


def test_record_round_trips(tmp_path: Path) -> None:
    record = _record()
    write_attack_box_record(tmp_path, record)
    assert read_attack_box_record(tmp_path, record.project) == record


def test_record_absent_reads_none(tmp_path: Path) -> None:
    assert read_attack_box_record(tmp_path, "ir-abox-000000") is None


def test_record_present_but_unreadable_raises(tmp_path: Path) -> None:
    """Absent and unreadable are different answers: reading corruption as 'no external box' would skip the deny-first reclaim and strand a live foreign VMM."""
    from inspect_ranges._attackbox.record import AttackBoxRecordError

    record = _record()
    path = tmp_path / record.project / "attackbox.json"
    path.parent.mkdir(parents=True)
    path.write_text("{not json")
    with pytest.raises(AttackBoxRecordError, match="does not parse"):
        read_attack_box_record(tmp_path, record.project)


def test_record_tolerates_unknown_fields() -> None:
    """Forward compatibility: an older process must still reclaim a record a newer one wrote."""
    parsed = AttackBoxRecord.model_validate(
        {**_record().model_dump(), "surprise": True},
    )
    assert parsed.reclaim_token == "cell-7"


def test_handle_defaults_and_endpoint_shape(tmp_path: Path) -> None:
    handle = AttackBoxHandle(exec_endpoint=HybridEndpoint(tmp_path / "a.sock", 1000))
    assert handle.reclaim_token == ""
    assert handle.exec_endpoint.peer_uid == 1000

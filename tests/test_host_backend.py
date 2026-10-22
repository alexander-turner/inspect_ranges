"""Backend selection for `INSPECT_RANGES_HOST`: the grammar, the resolver, and the bundle hooks (host-provider registration)."""

from pathlib import Path
from typing import cast

import pytest
from inspect_ranges._channel.channel import ByteStream, MessageChannel
from inspect_ranges._host import (
    HostBackend,
    HostBackendContext,
    HostFacts,
    HostLease,
    LeasePlacement,
    LeaseStore,
    LocalHostProvider,
    RangeHost,
    RemoteHostProvider,
    SampleSpec,
    parse_host_backend,
    resolve_host_backend,
)


class _StubProvider:
    """Satisfies the `HostProvider` protocol for bundles whose tests never acquire."""

    def __init__(self, ctx: HostBackendContext | None = None) -> None:
        self.ctx = ctx

    async def acquire(self, sample: SampleSpec, placement: LeasePlacement) -> RangeHost:
        raise NotImplementedError

    async def release(self, host: RangeHost) -> None:
        raise NotImplementedError

    async def abandon(self, host: RangeHost) -> None:
        raise NotImplementedError


class _NeverTransport:
    """A `Transport` that proves resolution never dials anything."""

    async def connect(self, endpoint: str) -> ByteStream:
        raise AssertionError("resolution must not dial")


def fake_backend_factory(ctx: HostBackendContext) -> HostBackend:
    """A co-resident test backend; the stub provider carries the context for assertions."""
    return HostBackend(provider=_StubProvider(ctx))


def separated_backend_factory(ctx: HostBackendContext) -> HostBackend:
    """A separated test backend (channel hook present, never dialed); other test modules resolve it by dotted path."""
    return HostBackend(
        provider=_StubProvider(ctx),
        channel_for_lease=lambda lease: MessageChannel(
            _NeverTransport(), label=lease.project
        ),
    )


def probing_backend_factory(ctx: HostBackendContext) -> HostBackend:
    """A bundle with a doctor probe whose health the config drives (`healthy` or a failure detail)."""
    detail = None if ctx.config == "healthy" else f"unreachable: {ctx.config}"
    return HostBackend(provider=_StubProvider(ctx), doctor_probe=lambda: detail)


def bad_factory(ctx: HostBackendContext) -> str:
    """Returns the wrong type; the resolver must refuse it."""
    return "not a backend"


NOT_CALLABLE = 42


# -- the grammar ---------------------------------------------------------------------


@pytest.mark.parametrize(
    ("value", "kind", "config"),
    [
        ("local", "local", None),
        ("uds:/run/user/1000/a.sock", "uds", "/run/user/1000/a.sock"),
        ("pkg.mod.attr", "custom", None),
        ("pkg.mod.attr:region-a", "custom", "region-a"),
        # the FIRST colon splits, so a config may itself contain colons
        ("pkg.mod.attr:https://api:8443", "custom", "https://api:8443"),
    ],
)
def test_grammar_accepts(value: str, kind: str, config: str | None) -> None:
    parsed = parse_host_backend(value)
    assert (parsed.kind, parsed.config) == (kind, config)
    assert parsed.value == value


@pytest.mark.parametrize(
    "value",
    [
        "",  # empty
        "fleet",  # bare name: neither reserved nor a dotted path
        "local:x",  # the local backend takes no config
        "uds",  # socket path required
        "uds:",  # empty socket path
        "pkg",  # no dot: not an import path
        "pkg.mod-bad.attr",  # hyphen: not an identifier segment
        "pkg..attr",  # empty segment
        ".attr",  # leading empty segment
    ],
)
def test_grammar_refuses(value: str) -> None:
    with pytest.raises(ValueError, match="INSPECT_RANGES_HOST"):
        parse_host_backend(value)


# -- the resolver --------------------------------------------------------------------


def test_local_resolves_to_the_co_resident_bundle(tmp_path: Path) -> None:
    bundle = resolve_host_backend("local", tmp_path)
    assert isinstance(bundle.provider, LocalHostProvider)
    assert not bundle.separated
    assert bundle.reclaimer() is None, "the reaper's direct down applies"


def test_uds_resolves_to_the_separated_bundle(tmp_path: Path) -> None:
    bundle = resolve_host_backend("uds:/tmp/a.sock", tmp_path)
    assert isinstance(bundle.provider, RemoteHostProvider)
    assert bundle.separated
    assert bundle.reclaim is not None, (
        "the uds bundle carries its applier-with-direct-down-fallback connector"
    )


def test_custom_value_resolves_through_its_factory(tmp_path: Path) -> None:
    """The dotted path imports, the factory runs, and the context carries the verbatim origin, the first-colon config, and the state dir."""
    value = f"{__name__}.fake_backend_factory:one:two"
    bundle = resolve_host_backend(value, tmp_path)
    provider = bundle.provider
    assert isinstance(provider, _StubProvider)
    assert provider.ctx is not None
    assert provider.ctx.origin == value, "the origin is the value, verbatim"
    assert provider.ctx.config == "one:two"
    assert provider.ctx.state_dir == tmp_path


@pytest.mark.parametrize(
    ("value", "match"),
    [
        ("no_such_pkg_xyz.hosts.fleet:cfg", "does not import"),
        (f"{__name__}.missing_attr", "has no attribute"),
        (f"{__name__}.NOT_CALLABLE", "not callable"),
        (f"{__name__}.bad_factory", "not a HostBackend"),
    ],
)
def test_resolver_refuses_with_the_cause_named(
    tmp_path: Path, value: str, match: str
) -> None:
    with pytest.raises(ValueError, match=match):
        resolve_host_backend(value, tmp_path)


# -- the bundle hooks ----------------------------------------------------------------


def _lease(state_dir: Path) -> HostLease:
    return LeaseStore(state_dir).acquire(
        project="ir-bundle-000000",
        task_name="t",
        sample_id="s1",
        isolation="shared",
        origin="tests.test_host_backend.separated_backend_factory",
        bundle_path="/b",
        bundle_digest="ab" * 32,
        staging="/s",
        host_facts=HostFacts(arch="x86_64", hostname="h", host_class="test"),
        ttl_s=60,
    )


def test_explicit_reclaim_wins_over_the_channel_default(tmp_path: Path) -> None:
    def reclaim(lease: HostLease, state_dir: Path) -> None:
        pass

    bundle = HostBackend(
        provider=_StubProvider(),
        channel_for_lease=lambda lease: MessageChannel(
            _NeverTransport(), label=lease.project
        ),
        reclaim=reclaim,
    )
    assert bundle.reclaimer() is reclaim


def test_separated_bundle_defaults_to_channel_teardown(tmp_path: Path) -> None:
    """A separated bundle without an explicit reclaim tears down through `channel_for_lease(lease).teardown()`."""
    teardowns: list[str] = []

    class _TeardownChannel:
        def __init__(self, lease_id: str) -> None:
            self._lease_id = lease_id

        async def teardown(self) -> None:
            teardowns.append(self._lease_id)

    bundle = HostBackend(
        provider=_StubProvider(),
        channel_for_lease=lambda lease: cast(
            MessageChannel, _TeardownChannel(lease.lease_id)
        ),
    )
    reclaim = bundle.reclaimer()
    assert reclaim is not None
    lease = _lease(tmp_path)
    reclaim(lease, tmp_path)
    assert teardowns == [lease.lease_id]

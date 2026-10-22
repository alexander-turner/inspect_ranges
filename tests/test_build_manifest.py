"""Build-manifest keys, projection semantics, and cache round-trips, all pure (no guest, no boot)."""

from pathlib import Path

import pytest
from inspect_ranges._build.manifest import (
    BuildManifest,
    GuestRecord,
    RecipeRecord,
    VerificationRecord,
    guest_build_key,
    load_manifest,
    manifest_matches_spec,
    now_iso,
    realized_file_name,
    save_manifest,
    spec_projection,
    vars_hash,
)
from inspect_ranges._build.recipes import RecipeSpec, ResolvedRecipe
from inspect_ranges.types import (
    AclRule,
    Host,
    Interface,
    Os,
    ProvisioningStep,
    Resources,
    Router,
    Service,
    User,
    Vulnerability,
)


def make_host(**overrides: object) -> Host:
    base: dict[str, object] = {
        "name": "web",
        "os": Os(type="linux"),
        "image": "focal-guest",
        "interfaces": [Interface(network="lab")],
        "provisioning": [ProvisioningStep(recipe="acme.web", vars={"marker": "x"})],
        "services": [Service(name="nginx", port=80, version="1.18")],
        "vulnerabilities": [Vulnerability(id="v1", service="nginx", description="d")],
    }
    base.update(overrides)
    return Host.model_validate(base)


def make_router(**overrides: object) -> Router:
    base: dict[str, object] = {
        "name": "fw",
        "image": "noble-guest",
        "interfaces": [Interface(network="dmz"), Interface(network="internal")],
        "users": [User(name="robot.abc", password="abcrb1357")],
        "provisioning": [ProvisioningStep(recipe="acme.fw", vars={"marker": "x"})],
    }
    base.update(overrides)
    return Router.model_validate(base)


def resolved(digest: str) -> ResolvedRecipe:
    return ResolvedRecipe(
        spec=RecipeSpec(name="acme.web", version="1", entrypoint="run.sh"),
        bundle_dir=Path("/tmp/x"),
        entrypoint=Path("/tmp/x/run.sh"),
        digest=digest,
        source="range",
    )


def test_projection_covers_only_realized_sections() -> None:
    host = make_host()
    same = spec_projection(host)
    # resources/addresses are outside the projection
    other = make_host(interfaces=[Interface(network="lab", ip="10.0.0.9")])
    assert spec_projection(other) == same
    # realized sections participate
    changed = make_host(services=[Service(name="nginx", port=81)])
    assert spec_projection(changed) != same


LAB_STATE: dict[str, object] = {
    "networks": [{"name": "lab", "cidr": "10.0.0.0/24", "mode": "isolated"}],
    "routers": [],
}


def win_projection(host: Host, network_state: dict[str, object] = LAB_STATE) -> str:
    return spec_projection(host, network_state=network_state)


def test_windows_projection_keys_on_name_and_addressing() -> None:
    """A Windows capture bakes its hostname and static addresses into the disk (the specialize pass runs once), so an IP or name edit must rebuild rather than re-render against a stale disk; Linux addressing stays outside the key (cloud-init re-seeds per boot)."""
    host = make_host(os=Os(type="windows"))
    same = win_projection(host)
    assert win_projection(make_host(os=Os(type="windows"))) == same
    moved = make_host(
        os=Os(type="windows"),
        interfaces=[Interface(network="lab", ip="10.0.0.9")],
    )
    assert win_projection(moved) != same
    renamed = make_host(os=Os(type="windows"), name="dc2")
    assert win_projection(renamed) != same


def test_windows_projection_keys_on_baked_network_state(tmp_path: Path) -> None:
    """Phase-review B1 (round 2 shape): the key sees the PLAN-RESOLVED facts the seed bakes — an authoritative resolver guest's ip edit moves OTHER Windows guests' facts, an unrelated isolated network does not; a Windows host with no network state refuses (fail closed); Linux hosts ignore it."""
    import pytest as _pytest
    from inspect_ranges._build.manifest import windows_key_facts
    from inspect_ranges.types import Attacker, DnsConfig, Network, RangeMeta, RangeSpec

    host = make_host(os=Os(type="windows"))
    with _pytest.raises(ValueError, match="network state"):
        spec_projection(host)
    # linux hosts never consume it: byte-stable with or without
    linux = make_host()
    assert spec_projection(linux) == spec_projection(
        linux, network_state={"hostname": "x", "interfaces": []}
    )

    def forest_spec(dc_ip: str) -> RangeSpec:
        return RangeSpec(
            meta=RangeMeta(name="r", description="d"),
            networks=[
                Network(
                    name="lab",
                    cidr="10.0.0.0/24",
                    mode="isolated",
                    dns=DnsConfig(authoritative=["dc"]),
                ),
            ],
            hosts=[
                Host.model_validate(
                    {
                        "name": "dc",
                        "os": Os(type="windows"),
                        "image": "win-golden",
                        "interfaces": [Interface(network="lab", ip=dc_ip)],
                    }
                ),
                Host.model_validate(
                    {
                        "name": "member",
                        "os": Os(type="windows"),
                        "image": "win-golden",
                        "interfaces": [Interface(network="lab", ip="10.0.0.20")],
                    }
                ),
            ],
            attacker=Attacker(interfaces=[Interface(network="lab")], entry="external"),
        )

    cache = tmp_path / "cache"
    cache.mkdir()
    base = windows_key_facts(forest_spec("10.0.0.10"), "member", image_cache=cache)
    from typing import Any, cast

    base_interfaces = cast("list[dict[str, Any]]", base["interfaces"])
    assert any("10.0.0.10" in str(i["resolvers"]) for i in base_interfaces), (
        "the authoritative DC's ip must appear in the member's baked resolvers"
    )
    # the resolver guest's ip edit moves the OTHER guest's facts (the round-2
    # escape class: spec-level projection could not see this)
    moved = windows_key_facts(forest_spec("10.0.0.11"), "member", image_cache=cache)
    assert moved != base
    # an unrelated isolated network leaves a single-homed guest's facts alone
    extra = forest_spec("10.0.0.10").model_copy(
        update={
            "networks": [
                forest_spec("10.0.0.10").networks[0],
                Network(name="aside", cidr="10.9.0.0/24", mode="isolated"),
            ]
        }
    )
    assert windows_key_facts(extra, "member", image_cache=cache) == base


Steps = list[tuple[ResolvedRecipe, dict[str, str | int | bool]]]


def test_build_key_moves_with_each_input() -> None:
    host = make_host()
    steps: Steps = [(resolved("d1"), {"marker": "x"})]
    other_digest: Steps = [(resolved("d2"), {"marker": "x"})]
    other_vars: Steps = [(resolved("d1"), {"marker": "y"})]
    same_again: Steps = [(resolved("d1"), {"marker": "x"})]
    key = guest_build_key("sha-golden", host, steps, range_name="keyed")
    assert guest_build_key("sha-other", host, steps, range_name="keyed") != key
    assert guest_build_key("sha-golden", host, other_digest, range_name="keyed") != key
    assert guest_build_key("sha-golden", host, other_vars, range_name="keyed") != key
    assert (
        guest_build_key("sha-golden", make_host(services=[]), steps, range_name="keyed")
        != key
    )
    # and it is stable for identical inputs
    assert (
        guest_build_key("sha-golden", make_host(), same_again, range_name="keyed")
        == key
    )


def test_vars_hash_is_order_insensitive() -> None:
    assert vars_hash({"a": 1, "b": "x"}) == vars_hash({"b": "x", "a": 1})


def test_manifest_round_trip_and_spec_match(tmp_path: Path) -> None:
    manifest = BuildManifest(
        range_name="bvok",
        schema_version="0.3",
        spec_sha256="77ab",
        built_at=now_iso(),
        guests=(
            GuestRecord(
                name="web",
                golden_reference="focal-guest",
                golden_digest="sha-golden",
                realized_file=realized_file_name("bvok", "web", "k" * 64),
                realized_sha256="sha-realized",
                build_key="k" * 64,
                recipes=(
                    RecipeRecord(
                        name="acme.web", version="1", digest="d1", vars_hash="v1"
                    ),
                ),
            ),
        ),
        verification=VerificationRecord(verified_at=now_iso(), declarations=()),
    )
    path = save_manifest(manifest, tmp_path)
    assert path.name == "manifest.json" and path.parent.name == "bvok"
    loaded = load_manifest(tmp_path, "bvok")
    assert loaded is not None and loaded == manifest
    assert manifest_matches_spec(loaded, "77ab")
    assert not manifest_matches_spec(loaded, "deadbeef")
    assert loaded.guest("web") is not None and loaded.guest("ghost") is None


def test_load_manifest_absent_or_corrupt_is_none(tmp_path: Path) -> None:
    assert load_manifest(tmp_path, "nothing") is None
    bad = tmp_path / "bad" / "manifest.json"
    bad.parent.mkdir(parents=True)
    bad.write_text("{not json")
    assert load_manifest(tmp_path, "bad") is None


def test_realized_file_name_distinguishes_generations() -> None:
    a = realized_file_name("r", "web", "a" * 64)
    b = realized_file_name("r", "web", "b" * 64)
    assert a != b and a.endswith(".qcow2") and "r-web-" in a


def test_range_name_grammar_gate() -> None:
    """Parked-decisions item 5: the schema's strict slug is the v1 contract; org-prefixed one-slash names arrive with the distribution phase."""
    from inspect_ranges._build.manifest import validate_range_name

    assert validate_range_name("vulhub-zabbix") is None
    assert validate_range_name("buildme_2") is None
    for bad in ("acme/payroll", "a.b", "../escape", "/abs", "UPPER", ".lead"):
        issue = validate_range_name(bad)
        assert issue is not None and issue.code == "range-name-invalid", bad


def test_file_name_flattening_survives_future_slashed_names() -> None:
    """The slash-flattening in `realized_file_name` and the nested `manifest_path` are unreachable under the v1 grammar but stay correct for the distribution-phase grammar."""
    name = realized_file_name("acme/payroll", "web", "k" * 64)
    assert "/" not in name and name.startswith("acme-payroll-web-")
    from inspect_ranges._build.manifest import manifest_path

    path = manifest_path(Path("/builds"), "acme/payroll")
    assert path == Path("/builds/acme/payroll/manifest.json")


def test_apply_build_manifest_gate(tmp_path: Path) -> None:
    import hashlib

    from inspect_ranges._build.manifest import apply_build_manifest
    from inspect_ranges._compiler.plan import spec_sha256
    from inspect_ranges.types import (
        Attacker,
        IssueError,
        Network,
        RangeMeta,
        RangeSpec,
    )
    from inspect_ranges.types import (
        Interface as I,
    )

    spec = RangeSpec(
        meta=RangeMeta(name="gated", description="x"),
        networks=[Network(name="lab", cidr="10.0.0.0/24", mode="isolated")],
        hosts=[make_host(name="web", image="focal-guest")],
        attacker=Attacker(
            image="focal-guest", interfaces=[I(network="lab")], entry="external"
        ),
    )
    image_cache = tmp_path / "images"
    image_cache.mkdir()
    builds = tmp_path / "builds"

    # no manifest: refuse range-not-built
    try:
        apply_build_manifest(spec, image_cache=image_cache, build_cache=builds)
        raise AssertionError("should refuse")
    except IssueError as error:
        assert error.issues[0].code == "range-not-built"
        assert "inspect-ranges build" in (error.issues[0].hint or "")

    # a matching manifest with a verifiable realized image AND its verified
    # golden backing: swap + realized sections (the gate re-checks both ends
    # of the chain since round-1: an overlay boots OVER the golden)
    realized = image_cache / "gated-web-abcdefabcdef.qcow2"
    realized.write_bytes(b"realized-bytes")
    golden = image_cache / "focal-guest.qcow2"
    golden.write_bytes(b"golden-bytes")
    golden_digest = f"sha256:{hashlib.sha256(b'golden-bytes').hexdigest()}"
    manifest = BuildManifest(
        range_name="gated",
        schema_version="0.3",
        spec_sha256=spec_sha256(spec),
        built_at=now_iso(),
        project="ir-gated-x",
        guests=(
            GuestRecord(
                name="web",
                golden_reference="focal-guest",
                golden_digest=golden_digest,
                realized_file=realized.name,
                realized_sha256=hashlib.sha256(b"realized-bytes").hexdigest(),
                build_key="k" * 64,
                recipes=(),
            ),
        ),
        verification=VerificationRecord(verified_at=now_iso(), declarations=()),
    )
    save_manifest(manifest, builds)
    swapped, sections, consumed = apply_build_manifest(
        spec, image_cache=image_cache, build_cache=builds
    )
    assert swapped.hosts[0].image == realized.name
    assert "services" in sections and "provisioning" in sections
    assert consumed is not None and consumed.project == "ir-gated-x"
    # the original spec is untouched
    assert spec.hosts[0].image == "focal-guest"

    # spec edited after the build: refuse with the revision hint
    spec.meta.description = "edited"
    try:
        apply_build_manifest(spec, image_cache=image_cache, build_cache=builds)
        raise AssertionError("should refuse")
    except IssueError as error:
        assert "different spec revision" in error.issues[0].message

    # a re-derived golden under the same name: refuse (the overlay would boot
    # over a composition that was never verified; round-1 blocking finding)
    spec.meta.description = "x"
    golden.write_bytes(b"golden-v2")
    try:
        apply_build_manifest(spec, image_cache=image_cache, build_cache=builds)
        raise AssertionError("should refuse")
    except IssueError as error:
        assert "changed since the build" in error.issues[0].message
    golden.write_bytes(b"golden-bytes")

    # a missing golden: refuse naming the pull/derive remedy
    golden.unlink()
    try:
        apply_build_manifest(spec, image_cache=image_cache, build_cache=builds)
        raise AssertionError("should refuse")
    except IssueError as error:
        assert "is not in the image cache" in error.issues[0].message
    golden.write_bytes(b"golden-bytes")

    # a missing realized image: refuse naming the pull remedy (round-1 gap)
    realized_bytes = realized.read_bytes()
    realized.unlink()
    try:
        apply_build_manifest(spec, image_cache=image_cache, build_cache=builds)
        raise AssertionError("should refuse")
    except IssueError as error:
        assert "pull the build artifacts" in (error.issues[0].hint or "")
    realized.write_bytes(realized_bytes)

    # tampered realized image: refuse
    realized.write_bytes(b"tampered")
    try:
        apply_build_manifest(spec, image_cache=image_cache, build_cache=builds)
        raise AssertionError("should refuse")
    except IssueError as error:
        assert "does not match the manifest's digest" in error.issues[0].message

    # a content host the manifest never recorded: refuse (round-1 gap)
    realized.write_bytes(b"realized-bytes")
    renamed = manifest.model_copy(
        update={"guests": (manifest.guests[0].model_copy(update={"name": "other"}),)}
    )
    save_manifest(renamed, builds)
    try:
        apply_build_manifest(spec, image_cache=image_cache, build_cache=builds)
        raise AssertionError("should refuse")
    except IssueError as error:
        assert "has no record for guest" in error.issues[0].message


def test_apply_build_manifest_passthrough_without_content(tmp_path: Path) -> None:
    from inspect_ranges._build.manifest import apply_build_manifest
    from inspect_ranges.types import (
        Attacker,
        Host,
        Network,
        Os,
        RangeMeta,
        RangeSpec,
    )
    from inspect_ranges.types import (
        Interface as I,
    )

    spec = RangeSpec(
        meta=RangeMeta(name="plain", description="x"),
        networks=[Network(name="lab", cidr="10.0.0.0/24", mode="isolated")],
        hosts=[
            Host(
                name="web",
                os=Os(type="linux"),
                image="g",
                interfaces=[I(network="lab")],
            )
        ],
        attacker=Attacker(image="g", interfaces=[I(network="lab")], entry="external"),
    )
    same, sections, consumed = apply_build_manifest(
        spec, image_cache=tmp_path, build_cache=tmp_path / "builds"
    )
    assert same is spec and sections == frozenset() and consumed is None


def test_router_projection_covers_provisioning_only() -> None:
    """A router's realized disk holds its recipes' output alone: ACL, routes, addressing, and sizing re-render per boot, and declared `users` ride the recipes the key already carries, so only `provisioning` participates in the projection."""
    same = spec_projection(make_router())
    unchanged: list[Router] = [
        make_router(acl=[AclRule(from_="dmz", to="internal", allow=["tcp/25"])]),
        make_router(users=[]),
        make_router(
            interfaces=[
                Interface(network="dmz", ip="10.80.10.1"),
                Interface(network="internal"),
            ]
        ),
        make_router(resources=Resources(cpus=2, memory_mb=2048)),
    ]
    for other in unchanged:
        assert spec_projection(other) == same
    moved = make_router(
        provisioning=[ProvisioningStep(recipe="acme.fw", vars={"marker": "y"})]
    )
    assert spec_projection(moved) != same


def test_router_build_key_moves_with_each_input() -> None:
    """The host build-key algebra applied to a router: golden digest, recipe digest, vars, and identity all move the key; a host with identical provisioning never shares it (the projections differ by shape, and identity differs by name anyway)."""
    router = make_router()
    steps: Steps = [(resolved("recipe-digest-1"), {"marker": "x"})]
    key = guest_build_key("sha-golden", router, steps, range_name="keyed")
    assert guest_build_key("sha-other", router, steps, range_name="keyed") != key
    other_digest: Steps = [(resolved("recipe-digest-2"), {"marker": "x"})]
    assert (
        guest_build_key("sha-golden", router, other_digest, range_name="keyed") != key
    )
    other_vars: Steps = [(resolved("recipe-digest-1"), {"marker": "y"})]
    assert guest_build_key("sha-golden", router, other_vars, range_name="keyed") != key
    assert guest_build_key("sha-golden", router, steps, range_name="other") != key
    twin_host = make_host(
        name="fw",
        services=[],
        vulnerabilities=[],
        provisioning=list(router.provisioning),
    )
    assert guest_build_key("sha-golden", twin_host, steps, range_name="keyed") != key


def test_apply_build_manifest_covers_routers(tmp_path: Path) -> None:
    """The range-not-built gate sees router content: a provisioned router demands a manifest, swaps to its digest-verified realized image when one matches, and refuses when the manifest never recorded it."""
    import hashlib

    from inspect_ranges._build.manifest import apply_build_manifest
    from inspect_ranges._compiler.plan import spec_sha256
    from inspect_ranges.types import (
        Attacker,
        IssueError,
        Network,
        RangeMeta,
        RangeSpec,
    )

    spec = RangeSpec(
        meta=RangeMeta(name="routed", description="x"),
        networks=[
            Network(name="dmz", cidr="10.80.10.0/24", mode="isolated"),
            Network(name="internal", cidr="10.80.20.0/24", mode="isolated"),
        ],
        routers=[make_router()],
        hosts=[
            Host(
                name="plain",
                os=Os(type="linux"),
                image="focal-guest",
                interfaces=[Interface(network="dmz")],
            )
        ],
        attacker=Attacker(host="plain", entry="assumed-breach"),
    )
    image_cache = tmp_path / "images"
    image_cache.mkdir()
    builds = tmp_path / "builds"

    with pytest.raises(IssueError) as excinfo:
        apply_build_manifest(spec, image_cache=image_cache, build_cache=builds)
    assert excinfo.value.issues[0].code == "range-not-built"

    realized = image_cache / "routed-fw-abcdefabcdef.qcow2"
    realized.write_bytes(b"realized-router")
    golden = image_cache / "noble-guest.qcow2"
    golden.write_bytes(b"golden-bytes")
    manifest = BuildManifest(
        range_name="routed",
        schema_version="0.3",
        spec_sha256=spec_sha256(spec),
        built_at=now_iso(),
        project="ir-routed-x",
        guests=(
            GuestRecord(
                name="fw",
                golden_reference="noble-guest",
                golden_digest=f"sha256:{hashlib.sha256(b'golden-bytes').hexdigest()}",
                realized_file=realized.name,
                realized_sha256=hashlib.sha256(b"realized-router").hexdigest(),
                build_key="k" * 64,
                recipes=(),
            ),
        ),
        verification=VerificationRecord(verified_at=now_iso(), declarations=()),
    )
    save_manifest(manifest, builds)
    swapped, sections, consumed = apply_build_manifest(
        spec, image_cache=image_cache, build_cache=builds
    )
    assert swapped.routers[0].image == realized.name
    assert "users" in sections and "provisioning" in sections
    assert consumed is not None
    assert spec.routers[0].image == "noble-guest"  # the input spec is untouched

    renamed = manifest.model_copy(
        update={"guests": (manifest.guests[0].model_copy(update={"name": "other"}),)}
    )
    save_manifest(renamed, builds)
    with pytest.raises(IssueError) as excinfo:
        apply_build_manifest(spec, image_cache=image_cache, build_cache=builds)
    assert "has no record for guest 'fw'" in excinfo.value.issues[0].message


def test_identity_participates_in_the_build_key() -> None:
    """Round-1: two ranges (or guests) with byte-identical content must never share a key or a realized file name (collisions caused last-writer-wins captures)."""
    host = make_host()
    key_a = guest_build_key("sha-golden", host, [], range_name="range-a")
    key_b = guest_build_key("sha-golden", host, [], range_name="range-b")
    assert key_a != key_b
    other = make_host(name="other")
    assert guest_build_key("sha-golden", other, [], range_name="range-a") != key_a


def test_stamp_bundle_sha256_is_guarded_and_locked(tmp_path: Path) -> None:
    """Round-1: the render write-back must not clobber a concurrent rebuild (same or different spec); the stamp lands only on the revision the render consumed."""
    from inspect_ranges._build.manifest import (
        BuildManifest,
        VerificationRecord,
        load_manifest,
        now_iso,
        save_manifest,
        stamp_bundle_sha256,
    )

    builds = tmp_path / "builds"

    def manifest_for(spec_hash: str) -> BuildManifest:
        return BuildManifest(
            range_name="stamped",
            schema_version="0.3",
            spec_sha256=spec_hash,
            built_at=now_iso(),
            guests=(),
            verification=VerificationRecord(verified_at=now_iso(), declarations=()),
        )

    assert not stamp_bundle_sha256(builds, "stamped", "a" * 64, "d1")  # nothing yet
    save_manifest(manifest_for("a" * 64), builds)
    assert stamp_bundle_sha256(builds, "stamped", "a" * 64, "d1")
    loaded = load_manifest(builds, "stamped")
    assert loaded is not None and loaded.bundle_sha256 == "d1"
    # a rebuild landed a NEW revision between this render's gate check and its
    # stamp: the stale stamp must not land
    save_manifest(manifest_for("b" * 64), builds)
    assert not stamp_bundle_sha256(builds, "stamped", "a" * 64, "d2")
    loaded = load_manifest(builds, "stamped")
    assert loaded is not None
    assert loaded.spec_sha256 == "b" * 64 and loaded.bundle_sha256 is None


def test_provider_resolve_config_applies_the_gate(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Round-2 gap: the provider-side gate (slice 6's headline behavior) had no unit coverage; a dropped gate call would have passed the whole suite."""
    import hashlib as hashlib_module

    from inspect_ranges._build.manifest import (
        BuildManifest,
        GuestRecord,
        VerificationRecord,
        now_iso,
        save_manifest,
    )
    from inspect_ranges._compiler.plan import spec_sha256
    from inspect_ranges._provider.state import ProviderRuntime
    from inspect_ranges.types import (
        Attacker,
        Host,
        Network,
        Os,
        ProvisioningStep,
        RangeMeta,
        RangeSpec,
    )
    from inspect_ranges.types import Interface as I

    image_cache = tmp_path / "images"
    image_cache.mkdir()
    builds = tmp_path / "builds"
    monkeypatch.setenv("INSPECT_RANGES_IMAGE_CACHE", str(image_cache))
    monkeypatch.setenv("INSPECT_RANGES_BUILD_CACHE", str(builds))
    (image_cache / "focal-guest.qcow2").write_bytes(b"golden-bytes")
    (image_cache / "ubuntu-noble.qcow2").write_bytes(b"attacker-golden")
    spec = RangeSpec(
        meta=RangeMeta(name="provgate", description="gate through the provider"),
        networks=[Network(name="lab", cidr="10.0.0.0/24", mode="isolated")],
        hosts=[
            Host(
                name="web",
                os=Os(type="linux"),
                image="focal-guest",
                interfaces=[I(network="lab")],
                provisioning=[ProvisioningStep(recipe="acme.web")],
            )
        ],
        attacker=Attacker(
            image="ubuntu-noble", interfaces=[I(network="lab")], entry="external"
        ),
    )
    runtime = ProviderRuntime()
    # with no matching local build, init now runs the implicit resolve-fetch
    # first (slice 4): an empty hermetic search path refuses no-build-for-spec
    # (never the public-org default inside a test), and the never-pull knob
    # refuses before any network with its own code
    from inspect_ai._util.error import PrerequisiteError
    from inspect_ranges._dist import OciLayout

    empty_location = tmp_path / "empty-registry"
    OciLayout(empty_location).ensure()
    monkeypatch.setenv("INSPECT_RANGES_REGISTRY", str(empty_location))
    # the refusal surfaces as inspect's clean prerequisite error (round-4 B1):
    # the coded message, which inspect renders without a traceback
    with pytest.raises(PrerequisiteError, match="no-build-for-spec"):
        runtime.resolve_config("provgate.yaml", lambda: spec)
    monkeypatch.setenv("INSPECT_RANGES_NEVER_PULL", "1")
    with pytest.raises(PrerequisiteError, match="never-pull"):
        runtime.resolve_config("provgate.yaml", lambda: spec)
    monkeypatch.delenv("INSPECT_RANGES_NEVER_PULL")

    realized = image_cache / "provgate-web-abcdefabcdef.qcow2"
    realized.write_bytes(b"realized-bytes")
    manifest = BuildManifest(
        range_name="provgate",
        schema_version="0.3",
        spec_sha256=spec_sha256(spec),
        built_at=now_iso(),
        guests=(
            GuestRecord(
                name="web",
                golden_reference="focal-guest",
                golden_digest=f"sha256:{hashlib_module.sha256(b'golden-bytes').hexdigest()}",
                realized_file=realized.name,
                realized_sha256=hashlib_module.sha256(b"realized-bytes").hexdigest(),
                build_key="k" * 64,
                recipes=(),
            ),
        ),
        verification=VerificationRecord(verified_at=now_iso(), declarations=()),
    )
    save_manifest(manifest, builds)
    swapped, plan, sections, backings = runtime.resolve_config(
        "provgate.yaml", lambda: spec
    )
    assert swapped.hosts[0].image == realized.name
    assert "provisioning" in sections
    assert backings == {"web": ("focal-guest.qcow2", manifest.guests[0].golden_digest)}
    web_guest = next(guest for guest in plan.guests if guest.name == "web")
    assert web_guest.image.file == realized.name
    # the batch cache serves the same resolution without re-running the gate
    again = runtime.resolve_config("provgate.yaml", lambda: spec)
    assert again[0] is swapped


def test_realized_section_edits_move_the_windows_projection() -> None:
    """Slice-4 exit properties: roles/defense/fqdn edits rebuild (they are realized into the disk), and a host declaring none of them keeps its projection byte-identical (existing manifests stay valid)."""
    plain = make_host(os=Os(type="windows"))
    base = win_projection(plain)
    assert win_projection(make_host(os=Os(type="windows"))) == base
    assert win_projection(make_host(os=Os(type="windows"), roles=["iis"])) != base
    from inspect_ranges.types import HostDefense

    assert (
        win_projection(
            make_host(os=Os(type="windows"), defense=HostDefense(defender=False))
        )
        != base
    )
    assert (
        win_projection(make_host(os=Os(type="windows"), fqdn="web.corp.local")) != base
    )


def test_active_directory_hash_moves_every_content_guest_key() -> None:
    """The AD data is range-scoped: a user edit changes guest_build_key for any host passed with the hash; None (no AD declared) reproduces the pre-slice-4 key exactly."""
    from inspect_ranges._build.manifest import active_directory_hash
    from inspect_ranges.types import ActiveDirectory, AdDomain, AdUser, RangeSpec

    host = make_host()
    without = guest_build_key("sha256:d", host, [], range_name="r")
    assert (
        guest_build_key(
            "sha256:d", host, [], range_name="r", active_directory_hash=None
        )
        == without
    )

    def spec_with(password: str) -> RangeSpec:
        from inspect_ranges.types import Attacker, Interface, Network, Os, RangeMeta

        return RangeSpec(
            meta=RangeMeta(name="adr", description="d"),
            networks=[Network(name="lab", cidr="10.0.0.0/24", mode="isolated")],
            hosts=[make_host(os=Os(type="windows"))],
            attacker=Attacker(interfaces=[Interface(network="lab")], entry="external"),
            active_directory=ActiveDirectory(
                forest="corp.local",
                domains=[
                    AdDomain(
                        name="corp.local",
                        netbios="CORP",
                        dc="web",
                        users=[AdUser(name="alice", password=password)],
                    )
                ],
            ),
        )

    first = active_directory_hash(spec_with("one"))
    second = active_directory_hash(spec_with("two"))
    assert first is not None and second is not None and first != second
    assert guest_build_key(
        "sha256:d", host, [], range_name="r", active_directory_hash=first
    ) != guest_build_key(
        "sha256:d", host, [], range_name="r", active_directory_hash=second
    )
    assert (
        guest_build_key(
            "sha256:d", host, [], range_name="r", active_directory_hash=first
        )
        != without
    )


def test_activities_move_the_projection_and_the_key() -> None:
    """A scheduled-activity declaration joins the projection only when declared (existing hashes stay put), and the script's content digest moves the key on its own (scheduled-activity-v1)."""
    from inspect_ranges.types import ScheduledActivity

    steps: Steps = [(resolved("d1"), {"marker": "x"})]
    plain = make_host()
    declared = make_host(
        scheduled_activity=[ScheduledActivity(script="tick.sh", schedule="every 5m")]
    )
    assert spec_projection(plain) != spec_projection(declared)
    rescheduled = make_host(
        scheduled_activity=[ScheduledActivity(script="tick.sh", schedule="@boot")]
    )
    assert spec_projection(declared) != spec_projection(rescheduled)
    key = guest_build_key(
        "sha-golden", declared, steps, range_name="keyed", activity_digests=("s1",)
    )
    assert (
        guest_build_key(
            "sha-golden", declared, steps, range_name="keyed", activity_digests=("s2",)
        )
        != key
    )
    assert guest_build_key("sha-golden", declared, steps, range_name="keyed") != key


def test_activity_only_host_is_content_and_requires_a_build(tmp_path: Path) -> None:
    """A host declaring only `scheduled_activity` is a content guest: the gate refuses `range-not-built` until a manifest matches (scheduled-activity-v1)."""
    from inspect_ranges._build.manifest import apply_build_manifest
    from inspect_ranges.types import (
        Attacker,
        IssueError,
        Network,
        RangeMeta,
        RangeSpec,
        ScheduledActivity,
    )

    host = make_host(
        provisioning=[],
        services=[],
        vulnerabilities=[],
        scheduled_activity=[ScheduledActivity(script="tick.sh", schedule="every 5m")],
    )
    spec = RangeSpec(
        meta=RangeMeta(name="acts-only", description="x"),
        networks=[Network(name="lab", cidr="10.0.0.0/24", mode="isolated")],
        hosts=[host],
        attacker=Attacker(
            image="focal-guest",
            interfaces=[Interface(network="lab")],
            entry="external",
        ),
    )
    image_cache = tmp_path / "images"
    image_cache.mkdir()
    builds = tmp_path / "builds"
    with pytest.raises(IssueError) as excinfo:
        apply_build_manifest(spec, image_cache=image_cache, build_cache=builds)
    assert excinfo.value.issues[0].code == "range-not-built"

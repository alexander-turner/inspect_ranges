"""Build-manifest keys, projection semantics, and cache round-trips, all pure (no guest, no boot)."""

from pathlib import Path

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
    Host,
    Interface,
    Os,
    ProvisioningStep,
    Service,
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


Steps = list[tuple[ResolvedRecipe, dict[str, str | int | bool]]]


def test_build_key_moves_with_each_input() -> None:
    host = make_host()
    steps: Steps = [(resolved("d1"), {"marker": "x"})]
    other_digest: Steps = [(resolved("d2"), {"marker": "x"})]
    other_vars: Steps = [(resolved("d1"), {"marker": "y"})]
    same_again: Steps = [(resolved("d1"), {"marker": "x"})]
    key = guest_build_key("sha-golden", host, steps)
    assert guest_build_key("sha-other", host, steps) != key
    assert guest_build_key("sha-golden", host, other_digest) != key
    assert guest_build_key("sha-golden", host, other_vars) != key
    assert guest_build_key("sha-golden", make_host(services=[]), steps) != key
    # and it is stable for identical inputs
    assert guest_build_key("sha-golden", make_host(), same_again) == key


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
    from inspect_ranges._build.manifest import validate_range_name

    assert validate_range_name("vulhub-zabbix") is None
    assert validate_range_name("acme/payroll") is None
    for bad in ("../escape", "/abs", "a/b/c", "UPPER", "trail-", ".lead"):
        issue = validate_range_name(bad)
        assert issue is not None and issue.code == "range-name-invalid", bad


def test_slashed_range_names_flatten_in_file_names_and_nest_in_builds() -> None:
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

    # a matching manifest with a verifiable realized image: swap + realized sections
    realized = image_cache / "gated-web-abcdefabcdef.qcow2"
    realized.write_bytes(b"realized-bytes")
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
                golden_digest="sha256:g",
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

    # tampered realized image: refuse
    spec.meta.description = "x"
    realized.write_bytes(b"tampered")
    try:
        apply_build_manifest(spec, image_cache=image_cache, build_cache=builds)
        raise AssertionError("should refuse")
    except IssueError as error:
        assert "does not match the manifest's digest" in error.issues[0].message


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

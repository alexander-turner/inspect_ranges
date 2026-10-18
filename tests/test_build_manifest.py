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
    (image_cache / "noble-range-guest.qcow2").write_bytes(b"attacker-golden")
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
            image="noble-range-guest", interfaces=[I(network="lab")], entry="external"
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

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


def test_build_key_moves_with_each_input() -> None:
    host = make_host()
    steps: list[tuple[ResolvedRecipe, dict[str, str | int | bool]]] = [
        (resolved("d1"), {"marker": "x"})
    ]
    key = guest_build_key("sha-golden", host, steps)
    assert guest_build_key("sha-other", host, steps) != key
    assert guest_build_key("sha-golden", host, [(resolved("d2"), {"marker": "x"})])  # pyright: ignore[reportArgumentType] != key
    assert guest_build_key("sha-golden", host, [(resolved("d1"), {"marker": "y"})])  # pyright: ignore[reportArgumentType] != key
    assert guest_build_key("sha-golden", make_host(services=[]), steps) != key
    # and it is stable for identical inputs
    assert guest_build_key(
        "sha-golden", make_host(), [(resolved("d1"), {"marker": "x"})]
    )  # pyright: ignore[reportArgumentType] == key


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

"""The mirror engine and the GC chain tier (no VMs; layouts, the in-process registry, and a synthetic cache)."""

import json
from pathlib import Path

import pytest
from inspect_ranges._dist import DistError, parse_location, pull_range, push_range
from inspect_ranges._dist.gc import unreferenced_chain_files
from inspect_ranges._dist.mirror import mirror_names, mirror_one, source_names

from tests.test_dist_encode import Fixture, fresh_dirs
from tests.test_dist_resolve import (  # noqa: F401  (autouse fixture)
    _spec_for_fixture,
    fake_backing_probe,  # pyright: ignore[reportUnusedImport]
)


def test_source_names_lists_layout_refs_without_spec_aliases(tmp_path: Path) -> None:
    fixture = Fixture(tmp_path)
    _spec_for_fixture(fixture, tmp_path)
    location = parse_location(str(tmp_path / "mirror"))
    push_range(
        fixture.manifest,
        location,
        image_cache=fixture.image_cache,
        build_cache=fixture.build_cache,
        range_dir=fixture.range_dir,
    )
    assert source_names(location) == ["distfix"]


def test_hub_sources_refuse_enumeration() -> None:
    with pytest.raises(DistError, match="location-unenumerable"):
        source_names(parse_location("docker.io/meridianlabsai"))


def test_mirror_carries_the_spec_ref_and_feeds_spec_pull(tmp_path: Path) -> None:
    """The disconnected session (Journey B): spec-driven pull works FROM the mirror because the exact-spec ref travels with the root."""
    fixture = Fixture(tmp_path)
    spec = _spec_for_fixture(fixture, tmp_path)
    origin = parse_location(str(tmp_path / "origin"))
    push_range(
        fixture.manifest,
        origin,
        image_cache=fixture.image_cache,
        build_cache=fixture.build_cache,
        range_dir=fixture.range_dir,
    )
    archive = parse_location(str(tmp_path / "archive"))
    result = mirror_one("distfix", origin, archive)
    assert result.copied and not result.present
    again = mirror_one("distfix", origin, archive)
    assert not again.copied and again.present
    images, builds, recipes = fresh_dirs(tmp_path)
    report = pull_range(
        spec,  # type: ignore[arg-type]
        [archive],
        image_cache=images,
        build_cache=builds,
        recipe_cache=recipes,
    )
    assert report.location == archive.describe()
    assert report.root == result.root


def test_whole_location_mirror(tmp_path: Path) -> None:
    fixture = Fixture(tmp_path)
    _spec_for_fixture(fixture, tmp_path)
    origin = parse_location(str(tmp_path / "origin"))
    push_range(
        fixture.manifest,
        origin,
        image_cache=fixture.image_cache,
        build_cache=fixture.build_cache,
        range_dir=fixture.range_dir,
    )
    destination = parse_location(str(tmp_path / "dest"))
    report = mirror_names(source_names(origin), origin, destination)
    assert report.copied > 0
    assert source_names(destination) == ["distfix"]


def test_unreferenced_chain_files_scan(tmp_path: Path) -> None:
    """The chain tier: a golden survives while a realized sidecar or manifest names it; a vendor survives while a surviving golden's provenance names it; orphan chains leave together."""
    fixture = Fixture(tmp_path)
    cache = fixture.image_cache
    # an orphan chain: a golden + vendor nothing references
    (cache / "orphan-vendor.img").write_bytes(b"orphan vendor")
    (cache / "orphan-golden.qcow2").write_bytes(b"orphan golden")
    (cache / "orphan-golden.json").write_text(
        json.dumps(
            {
                "name": "orphan-golden",
                "file": "orphan-golden.qcow2",
                "recipe_version": "4",
                "derivation_key": "k" * 64,
                "vendor_file": "orphan-vendor.img",
                "vendor_sha256": "0" * 64,
                "daemon": {"name": "vsockd", "version": "3.1.0", "sha256": "d" * 64},
                "golden_sha256": "0" * 64,
                "created": "2026-10-18T00:00:00Z",
            }
        )
    )
    victims, frozen = unreferenced_chain_files(cache, fixture.build_cache, set())
    assert not frozen
    names = {path.name for path, _ in victims}
    assert names == {
        "orphan-golden.qcow2",
        "orphan-golden.json",
        "orphan-vendor.img",
    }
    # the referenced chain (focal-guest + noble.img) is protected by the
    # manifest's records and the realized sidecar; the live set protects too
    protected, _ = unreferenced_chain_files(
        cache, fixture.build_cache, {"orphan-golden.qcow2"}
    )
    assert {path.name for path, _ in protected} == set()


def test_unreadable_golden_sidecar_freezes_the_vendor_tier(tmp_path: Path) -> None:
    """Round-5 B1: a golden whose provenance cannot be read freezes its vendor in place; nothing vendor-shaped is offered, loudly."""
    fixture = Fixture(tmp_path)
    cache = fixture.image_cache
    (cache / "mystery-golden.qcow2").write_bytes(b"golden with no story")
    (cache / "mystery-golden.json").write_text("{corrupt")
    (cache / "orphan-vendor.img").write_bytes(b"would-be victim")
    victims, frozen = unreferenced_chain_files(cache, fixture.build_cache, set())
    assert frozen and "mystery-golden" in frozen[0]
    assert not any("vendor" in kind for _, kind in victims)
    # a MISSING sidecar freezes identically
    (cache / "mystery-golden.json").unlink()
    victims, frozen = unreferenced_chain_files(cache, fixture.build_cache, set())
    assert frozen
    assert not any("vendor" in kind for _, kind in victims)


def test_qcow2_vendors_leave_with_their_chain(tmp_path: Path) -> None:
    """Round-5 N1: vendors are attributed by sidecars, never extensions, so a .qcow2 vendor evicts with its orphan golden."""
    fixture = Fixture(tmp_path)
    cache = fixture.image_cache
    (cache / "qv-vendor.qcow2").write_bytes(b"qcow2 vendor bytes")
    (cache / "qv-golden.qcow2").write_bytes(b"qcow2 golden bytes")
    (cache / "qv-golden.json").write_text(
        json.dumps(
            {
                "name": "qv-golden",
                "file": "qv-golden.qcow2",
                "recipe_version": "4",
                "derivation_key": "k" * 64,
                "vendor_file": "qv-vendor.qcow2",
                "vendor_sha256": "0" * 64,
                "daemon": {"name": "vsockd", "version": "3.1.0", "sha256": "d" * 64},
                "golden_sha256": "0" * 64,
                "created": "2026-10-18T00:00:00Z",
            }
        )
    )
    victims, frozen = unreferenced_chain_files(cache, fixture.build_cache, set())
    assert not frozen
    names = {path.name for path, _ in victims}
    assert {"qv-golden.qcow2", "qv-golden.json", "qv-vendor.qcow2"} <= names


def test_whole_location_mirror_carries_every_build(tmp_path: Path) -> None:
    """Round-5 B3: a source serving two builds of one range mirrors BOTH spec refs; the archive serves the older spec too."""
    from inspect_ranges._build.manifest import save_manifest

    fixture = Fixture(tmp_path)
    spec = _spec_for_fixture(fixture, tmp_path)
    origin = parse_location(str(tmp_path / "origin"))
    push_range(
        fixture.manifest,
        origin,
        image_cache=fixture.image_cache,
        build_cache=fixture.build_cache,
        range_dir=fixture.range_dir,
    )
    newer = fixture.manifest.model_copy(
        update={"spec_sha256": "feed" * 16, "built_at": "2099-03-03T00:00:00Z"}
    )
    save_manifest(newer, fixture.build_cache)
    push_range(
        newer,
        origin,
        image_cache=fixture.image_cache,
        build_cache=fixture.build_cache,
        range_dir=fixture.range_dir,
    )
    archive = parse_location(str(tmp_path / "archive"))
    mirror_names(source_names(origin), origin, archive)
    # the OLDER build (the spec fixture's hash) still pulls from the archive
    images, builds, recipes = fresh_dirs(tmp_path)
    report = pull_range(
        spec,  # type: ignore[arg-type]
        [archive],
        image_cache=images,
        build_cache=builds,
        recipe_cache=recipes,
    )
    assert report.location == archive.describe()


def test_explicit_root_never_regresses_latest(tmp_path: Path) -> None:
    """Round-5 N6: pinning an older build into a destination already serving a newer one lands the spec ref and keeps latest."""
    from inspect_ranges._build.manifest import save_manifest

    fixture = Fixture(tmp_path)
    _spec_for_fixture(fixture, tmp_path)
    origin = parse_location(str(tmp_path / "origin"))
    old_root = push_range(
        fixture.manifest,
        origin,
        image_cache=fixture.image_cache,
        build_cache=fixture.build_cache,
        range_dir=fixture.range_dir,
    )
    newer = fixture.manifest.model_copy(
        update={"spec_sha256": "feed" * 16, "built_at": "2099-03-03T00:00:00Z"}
    )
    save_manifest(newer, fixture.build_cache)
    destination = parse_location(str(tmp_path / "dest"))
    push_range(
        newer,
        destination,
        image_cache=fixture.image_cache,
        build_cache=fixture.build_cache,
        range_dir=fixture.range_dir,
    )
    newest = destination.store_for("distfix").ref("distfix").digest
    mirror_one("distfix", origin, destination, root=old_root)
    assert destination.store_for("distfix").ref("distfix").digest == newest

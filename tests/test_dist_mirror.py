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
    victims = unreferenced_chain_files(cache, fixture.build_cache, set())
    names = {path.name for path, _ in victims}
    assert names == {
        "orphan-golden.qcow2",
        "orphan-golden.json",
        "orphan-vendor.img",
    }
    # the referenced chain (focal-guest + noble.img) is protected by the
    # manifest's records and the realized sidecar; the live set protects too
    protected = unreferenced_chain_files(
        cache, fixture.build_cache, {"orphan-golden.qcow2"}
    )
    assert {path.name for path, _ in protected} == set()

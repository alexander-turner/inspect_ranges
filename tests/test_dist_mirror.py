"""The mirror engine and the GC chain tier (no VMs; layouts, the in-process registry, and a synthetic cache)."""

import json
from pathlib import Path

import pytest
from inspect_ranges._dist import DistError, parse_location, pull_range, push_range
from inspect_ranges._dist.gc import unreferenced_chain_files
from inspect_ranges._dist.mirror import mirror_names, mirror_one, source_names

from tests.test_dist_encode import GOLDEN, Fixture, fresh_dirs
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


def test_prune_delete_pass_routing(tmp_path: Path) -> None:
    """Phase round-2 B1: provenance sidecars are chain victims (they live or die with the fresh scan), and realized victims re-check fresh liveness."""
    from inspect_ranges._cli.imagescmd import prune_delete_pass

    golden = tmp_path / "g.qcow2"
    sidecar = tmp_path / "g.json"
    realized = tmp_path / "r-web-abc.qcow2"
    realized_sidecar = tmp_path / "r-web-abc.realized.json"
    for path in (golden, sidecar, realized, realized_sidecar):
        path.write_bytes(b"x")
    victims = [
        (golden, 1, "unreferenced golden"),
        (sidecar, 1, "its provenance sidecar"),
        (realized, 1, "superseded realized image"),
        (realized_sidecar, 1, "its sidecar"),
    ]
    # the world moved: the golden became referenced (not in `still`) and the
    # realized image's manifest landed (fresh_live) between scan and delete
    deleted = prune_delete_pass(victims, still=set(), fresh_live={"r-web-abc.qcow2"})
    assert deleted == set()
    assert golden.exists() and sidecar.exists()
    assert realized.exists() and realized_sidecar.exists()
    # nothing moved: everything goes, the provenance sidecar WITH its golden
    deleted = prune_delete_pass(victims, still={golden, sidecar}, fresh_live=set())
    assert deleted == {golden, sidecar, realized, realized_sidecar}


def test_push_refuses_unpublishable_names(tmp_path: Path) -> None:
    """Phase round-2 N2: a name outside the cache grammar fails at PUBLISH with the named value, not at every consumer."""
    from inspect_ranges._dist import OciLayout, push_build

    fixture = Fixture(tmp_path)
    bad = fixture.manifest.model_copy(
        update={
            "guests": (
                fixture.manifest.guests[0].model_copy(
                    update={"realized_file": "evil *glob*.qcow2"}
                ),
            )
        }
    )
    layout = OciLayout(tmp_path / "layout").ensure()
    with pytest.raises(DistError, match="not a cache file name"):
        push_build(
            bad,
            layout,
            image_cache=fixture.image_cache,
            build_cache=fixture.build_cache,
            range_dir=fixture.range_dir,
        )


def test_publish_realized_promotes_to_the_bare_name(tmp_path: Path) -> None:
    """Catalog slice 2: a built guest's realized image publishes under the bare catalog name, consumers land it as <name>.qcow2 with its chain and provenance, and the catalog list carries it."""
    from inspect_ranges._dist import pull_image
    from inspect_ranges._dist.catalog import catalog_names, publish_realized

    fixture = Fixture(tmp_path)
    location = parse_location(str(tmp_path / "catalog-loc"))
    root = publish_realized(
        fixture.manifest, "web", "attack", location, image_cache=fixture.image_cache
    )
    assert root.digest.startswith("sha256:")
    assert catalog_names(location) == ["attack"]
    consumer = tmp_path / "consumer-images"
    consumer.mkdir()
    pulled = pull_image("attack", [location], image_cache=consumer)
    assert pulled is not None
    assert (consumer / "attack.qcow2").read_bytes() == (
        fixture.image_cache / fixture.realized_file
    ).read_bytes()
    assert (consumer / "attack.realized.json").is_file()
    # the chain traveled: the golden and vendor landed for the boot path
    assert (consumer / "focal-guest.qcow2").is_file()
    assert (consumer / "noble.img").is_file()


def test_publish_golden_and_catalog_enumeration(tmp_path: Path) -> None:
    """Publish --golden promotes a golden chain; source_names enumerates via the catalog artifact (the hub-shaped path)."""
    from inspect_ranges._dist.catalog import catalog_names, publish_golden

    fixture = Fixture(tmp_path)
    location = parse_location(str(tmp_path / "catalog-loc"))
    publish_golden("focal-guest", location, image_cache=fixture.image_cache)
    assert catalog_names(location) == ["focal-guest"]
    assert source_names(location) == ["focal-guest"]


def test_pin_file_round_trip_and_mismatch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Q11: pins consume as @sha256 pins: a moved catalog still lands the PINNED root from origin by digest, and only a gone pinned root refuses pin-mismatch."""
    import hashlib as hashlib_module

    from inspect_ranges._dist import pull_image
    from inspect_ranges._dist.catalog import generate_pin_file, publish_golden
    from inspect_ranges._dist.resolve import PIN_FILE_ENV

    fixture = Fixture(tmp_path)
    location = parse_location(str(tmp_path / "catalog-loc"))
    publish_golden("focal-guest", location, image_cache=fixture.image_cache)
    pin_file = tmp_path / "pins.json"
    pins = generate_pin_file(location, pin_file)
    assert set(pins) == {"focal-guest"}
    monkeypatch.setenv(PIN_FILE_ENV, str(pin_file))
    consumer = tmp_path / "pinned-images"
    consumer.mkdir()
    assert pull_image("focal-guest", [location], image_cache=consumer) is not None
    # the publisher moves the catalog past the pin
    moved = b"golden-image-bytes-moved"
    (fixture.image_cache / "focal-guest.qcow2").write_bytes(moved)
    meta = json.loads((fixture.image_cache / "focal-guest.json").read_text())
    meta["golden_sha256"] = hashlib_module.sha256(moved).hexdigest()
    (fixture.image_cache / "focal-guest.json").write_text(json.dumps(meta))
    publish_golden("focal-guest", location, image_cache=fixture.image_cache)
    # the pin consumes as an @sha256 pin: the moved tag is ignored and the
    # PINNED root lands from origin (it stays fetchable by digest)
    fresh = tmp_path / "fresh-images"
    fresh.mkdir()
    pinned_pull = pull_image("focal-guest", [location], image_cache=fresh)
    assert pinned_pull is not None
    assert (fresh / "focal-guest.qcow2").read_bytes() == GOLDEN
    # only a GONE pinned root refuses
    from inspect_ranges._dist import OciLayout

    layout = OciLayout(tmp_path / "catalog-loc").open()
    layout.blob_path(pins["focal-guest"]).unlink()
    gone = tmp_path / "gone-images"
    gone.mkdir()
    with pytest.raises(DistError, match="pin-mismatch"):
        pull_image("focal-guest", [location], image_cache=gone)


def test_refresh_moves_a_promoted_catalog_name(tmp_path: Path) -> None:
    """Slice-2 review N4: refresh of a promoted (renamed) realized name lands image and sidecar together through the replace barrier; the chain converges."""
    import hashlib as hashlib_module

    from inspect_ranges._build.manifest import save_manifest
    from inspect_ranges._dist import pull_image, refresh_image
    from inspect_ranges._dist.catalog import publish_realized

    fixture = Fixture(tmp_path)
    location = parse_location(str(tmp_path / "catalog-loc"))
    publish_realized(
        fixture.manifest, "web", "attack", location, image_cache=fixture.image_cache
    )
    consumer = tmp_path / "consumer-images"
    consumer.mkdir()
    pull_image("attack", [location], image_cache=consumer)
    # the factory republishes with new bytes (new build key, new realized file)
    moved = b"realized-image-bytes-v2"
    new_file = fixture.realized_file.replace("b" * 12, "c" * 12)
    (fixture.image_cache / new_file).write_bytes(moved)
    (
        fixture.image_cache / (new_file.removesuffix(".qcow2") + ".realized.json")
    ).write_text(
        json.dumps(
            {
                "type": "realized",
                "range_name": "distfix",
                "guest": "web",
                "build_key": "c" * 64,
                "golden_file": "focal-guest.qcow2",
                "sha256": hashlib_module.sha256(moved).hexdigest(),
                "created": "2026-10-19T00:00:00Z",
            }
        )
    )
    republished = fixture.manifest.model_copy(
        update={
            "guests": (
                fixture.manifest.guests[0].model_copy(
                    update={
                        "realized_file": new_file,
                        "realized_sha256": hashlib_module.sha256(moved).hexdigest(),
                        "build_key": "c" * 64,
                    }
                ),
            )
        }
    )
    save_manifest(republished, fixture.build_cache)
    publish_realized(
        republished, "web", "attack", location, image_cache=fixture.image_cache
    )
    # sticky first, then the explicit move-forward
    with pytest.raises(DistError, match="cache-name-conflict"):
        pull_image("attack", [location], image_cache=consumer)
    refreshed = refresh_image("attack", [location], image_cache=consumer)
    assert refreshed is not None
    assert (consumer / "attack.qcow2").read_bytes() == moved
    sidecar = json.loads((consumer / "attack.realized.json").read_text())
    assert sidecar["build_key"] == "c" * 64


def test_catalog_name_is_reserved_everywhere(tmp_path: Path) -> None:
    """Slice-2 review B2: nothing publishes under the catalog's own ref."""
    from inspect_ranges._dist.catalog import publish_golden, publish_realized

    fixture = Fixture(tmp_path)
    location = parse_location(str(tmp_path / "catalog-loc"))
    with pytest.raises(DistError, match="name-reserved"):
        publish_golden("catalog", location, image_cache=fixture.image_cache)
    with pytest.raises(DistError, match="name-reserved"):
        publish_realized(
            fixture.manifest,
            "web",
            "catalog",
            location,
            image_cache=fixture.image_cache,
        )
    reserved_range = fixture.manifest.model_copy(update={"range_name": "catalog"})
    with pytest.raises(DistError, match="name-reserved"):
        push_range(
            reserved_range,
            location,
            image_cache=fixture.image_cache,
            build_cache=fixture.build_cache,
            range_dir=fixture.range_dir,
        )


def test_publish_refuses_unproven_manifests(tmp_path: Path) -> None:
    """Slice-2 review N1: a refused (failing-checks) build never publishes to the catalog."""
    from inspect_ranges._build.manifest import (
        BehavioralCheckRecord,
        VerificationRecord,
        now_iso,
    )
    from inspect_ranges._dist.catalog import publish_realized

    fixture = Fixture(tmp_path)
    refused = fixture.manifest.model_copy(
        update={
            "verification": VerificationRecord(
                verified_at=now_iso(),
                declarations=(),
                behavioral_checks=(
                    BehavioralCheckRecord(
                        challenge="demo", check="reference", status="fail", detail="0.0"
                    ),
                ),
            )
        }
    )
    location = parse_location(str(tmp_path / "catalog-loc"))
    with pytest.raises(DistError, match="range-unproven"):
        publish_realized(
            refused, "web", "attack", location, image_cache=fixture.image_cache
        )


def test_pulled_catalog_realized_is_not_prune_bait(tmp_path: Path) -> None:
    """Slice-2 review B1: a pulled catalog image is sticky: never 'superseded', never offered by the realized tier, and its chain survives --chains."""
    from inspect_ranges._build.manifest import is_catalog_realized
    from inspect_ranges._dist import pull_image
    from inspect_ranges._dist.catalog import publish_realized
    from inspect_ranges._dist.gc import unreferenced_chain_files

    fixture = Fixture(tmp_path)
    location = parse_location(str(tmp_path / "catalog-loc"))
    publish_realized(
        fixture.manifest, "web", "attack", location, image_cache=fixture.image_cache
    )
    consumer = tmp_path / "consumer-images"
    consumer.mkdir()
    pull_image("attack", [location], image_cache=consumer)
    assert is_catalog_realized("distfix", "web", "b" * 64, "attack.qcow2")
    assert not is_catalog_realized("distfix", "web", "b" * 64, fixture.realized_file)
    # the chain scan on the consumer (no build manifests at all): the catalog
    # image's golden is attributed by its sidecar, so nothing leaves
    victims, frozen = unreferenced_chain_files(
        consumer, tmp_path / "empty-builds", set()
    )
    assert not frozen
    assert victims == []


# -- standard-images-v1 slice 4: the published daemon bundle ---------------------


def test_daemon_bundle_publish_and_fetch_round_trip(tmp_path: Path) -> None:
    """The daemon artifact publishes under the reserved ref and a consumer fetch lands a consumable artifact dir (what `images derive` reads), no Go toolchain involved."""
    from inspect_ranges._channel.bundle import write_bundle
    from inspect_ranges._dist.catalog import fetch_daemon_bundle, publish_daemon_bundle
    from inspect_ranges._doctor.checks import _artifact_state

    artifacts = tmp_path / "artifacts"
    built = write_bundle(artifacts, b"fake daemon binary", version="9.9.9-test")
    location = parse_location(str(tmp_path / "loc"))
    publish_daemon_bundle(artifacts, location)
    out = tmp_path / "fetched"
    info = fetch_daemon_bundle([location], out)
    assert info == built
    assert _artifact_state(out / "daemon.json") == "ok"


def test_daemon_bundle_publish_refuses_a_tampered_tar(tmp_path: Path) -> None:
    from inspect_ranges._channel.bundle import bundle_file_name, write_bundle
    from inspect_ranges._dist.catalog import publish_daemon_bundle

    artifacts = tmp_path / "artifacts"
    write_bundle(artifacts, b"fake daemon binary", version="9.9.9-test")
    with (artifacts / bundle_file_name("9.9.9-test")).open("ab") as handle:
        handle.write(b"tamper")
    location = parse_location(str(tmp_path / "loc"))
    with pytest.raises(DistError) as excinfo:
        publish_daemon_bundle(artifacts, location)
    assert excinfo.value.code == "digest-mismatch"


def test_daemon_bundle_name_is_reserved_for_images_and_ranges(tmp_path: Path) -> None:
    from inspect_ranges._dist.catalog import publish_golden

    location = parse_location(str(tmp_path / "loc"))
    with pytest.raises(DistError) as excinfo:
        publish_golden("daemon-bundle", location, image_cache=tmp_path)
    assert excinfo.value.code == "name-reserved"


def test_daemon_bundle_travels_with_whole_location_mirrors(tmp_path: Path) -> None:
    """An air-gapped fleet's mirror carries the daemon bundle beside the catalog, so derive works there without Go."""
    from inspect_ranges._channel.bundle import write_bundle
    from inspect_ranges._dist.catalog import (
        fetch_daemon_bundle,
        publish_daemon_bundle,
        publish_golden,
    )

    fixture = Fixture(tmp_path)
    source = parse_location(str(tmp_path / "source-loc"))
    publish_golden("focal-guest", source, image_cache=fixture.image_cache)
    artifacts = tmp_path / "artifacts"
    write_bundle(artifacts, b"fake daemon binary", version="9.9.9-test")
    publish_daemon_bundle(artifacts, source)
    destination = parse_location(str(tmp_path / "dest-loc"))
    mirror_names(source_names(source), source, destination)
    info = fetch_daemon_bundle([destination], tmp_path / "fetched")
    assert info.version == "9.9.9-test"


def test_daemon_bundle_fetch_names_the_searched_locations(tmp_path: Path) -> None:
    """A valid location that publishes no bundle: the refusal lists what was searched."""
    from inspect_ranges._dist.catalog import fetch_daemon_bundle, publish_golden

    fixture = Fixture(tmp_path)
    location = parse_location(str(tmp_path / "golden-only-loc"))
    publish_golden("focal-guest", location, image_cache=fixture.image_cache)
    with pytest.raises(DistError) as excinfo:
        fetch_daemon_bundle([location], tmp_path / "out")
    assert excinfo.value.code == "artifact-missing"
    assert "golden-only-loc" in str(excinfo.value)


def test_pull_image_refuses_a_repointed_reference(tmp_path: Path) -> None:
    """Phase review round-1 B1: the root a name resolves to must RECORD that name; a mutable tag re-pointed at another image's root refuses `published-mismatch` instead of landing foreign bytes under a success message."""
    from inspect_ranges._dist.catalog import publish_golden
    from inspect_ranges._dist.resolve import pull_image

    fixture = Fixture(tmp_path)
    location = parse_location(str(tmp_path / "loc"))
    publish_golden("focal-guest", location, image_cache=fixture.image_cache)
    # the registry (or an operator mistake) re-points another name's tag at
    # focal-guest's root
    store = location.store_for("noble-range-guest", create=True)
    root = store.ref(location.latest_ref("focal-guest"))
    store.put_index(location.latest_ref("noble-range-guest"), store.read_index(root))
    consumer = tmp_path / "consumer"
    consumer.mkdir()
    with pytest.raises(DistError) as excinfo:
        pull_image("noble-range-guest", [location], image_cache=consumer)
    assert excinfo.value.code == "published-mismatch"
    assert list(consumer.iterdir()) == [], "nothing may land from a refused pull"


def test_daemon_bundle_pull_honors_the_operator_pin(tmp_path: Path) -> None:
    """The sidecar travels with the artifact, so only the out-of-band pin catches a registry serving a regenerated pair."""
    from inspect_ranges._channel.bundle import write_bundle
    from inspect_ranges._dist.catalog import fetch_daemon_bundle, publish_daemon_bundle

    artifacts = tmp_path / "artifacts"
    built = write_bundle(artifacts, b"fake daemon binary", version="9.9.9-test")
    location = parse_location(str(tmp_path / "loc"))
    publish_daemon_bundle(artifacts, location)
    out = tmp_path / "fetched"
    with pytest.raises(DistError) as excinfo:
        fetch_daemon_bundle([location], out, expected_sha256="f" * 64)
    assert excinfo.value.code == "digest-mismatch"
    assert not (out / "daemon.json").exists(), "a refused fetch lands nothing"
    info = fetch_daemon_bundle([location], out, expected_sha256=built.bundle_sha256)
    assert info == built

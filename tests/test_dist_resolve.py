"""Resolution and the spec-driven verbs: location parsing, search-path shadowing, the exact-spec match and its refusal, the pin form, sticky image resolution, and the explicit refresh (no VMs; layouts and the in-process fake registry)."""

import hashlib
import json
from pathlib import Path

import pytest
from inspect_ranges._compiler.plan import spec_sha256
from inspect_ranges._dist import (
    DistError,
    parse_location,
    pull_image,
    pull_range,
    push_image_artifact,
    push_range,
    refresh_image,
    registry_locations,
)
from inspect_ranges._dist.location import DEFAULT_REGISTRY, REGISTRY_ENV
from inspect_ranges._runtime.images import ImageMetadata
from inspect_ranges.schema import load_range

from tests.test_dist_encode import GOLDEN, VENDOR, Fixture, fresh_dirs

SPEC_YAML = """
range:
  name: distfix
  schema_version: "0.3"
  description: resolve fixture
networks:
  - name: lab
    cidr: 10.95.0.0/24
    mode: isolated
hosts:
  - name: web
    os: {{ type: linux }}
    image: focal-guest
    interfaces: [{{ network: lab, ip: 10.95.0.10 }}]
    services:
      - name: marker
        port: 80{extra}
attacker:
  image: focal-guest
  interfaces: [{{ network: lab }}]
  entry: external
"""


def spec_file(tmp_path: Path, *, extra: str = "") -> Path:
    path = tmp_path / f"range-{abs(hash(extra))}.yaml"
    path.write_text(SPEC_YAML.format(extra=extra))
    return path


@pytest.fixture(autouse=True)
def fake_backing_probe(monkeypatch: pytest.MonkeyPatch) -> None:
    def probe(path: Path) -> str | None:
        if path.name.startswith("distfix-web-"):
            return "focal-guest.qcow2"
        return {"focal-guest.qcow2": "noble.img"}.get(path.name)

    monkeypatch.setattr("inspect_ranges._dist.materialize._qcow2_backing_name", probe)
    monkeypatch.setattr("inspect_ranges._dist.encode.qcow2_backing_name", probe)


def test_location_parsing_table(tmp_path: Path) -> None:
    directory = tmp_path / "mirror"
    directory.mkdir()
    cases: list[tuple[str, bool]] = [
        (str(directory), True),
        ("./relative/archive", True),
        ("/abs/archive", True),
        ("docker.io/meridianlabsai", False),
        ("registry.acme-evals.net/ranges", False),
        ("http://127.0.0.1:5056/ranges", False),
    ]
    for raw, is_dir in cases:
        assert parse_location(raw).is_directory == is_dir, raw
    for bad in ("", "noslash-nodot"):
        with pytest.raises(DistError, match="location-invalid"):
            parse_location(bad)
    hub = parse_location("docker.io/meridianlabsai")
    assert hub.latest_ref("ubuntu-focal") == "latest"
    assert hub.spec_ref("r", "ab" * 32) == f"spec-{'ab' * 32}"
    layout_location = parse_location(str(directory))
    assert layout_location.latest_ref("ubuntu-focal") == "ubuntu-focal"
    assert layout_location.spec_ref("r", "ab" * 32) == f"r:spec-{'ab' * 32}"


def test_registry_locations_env_and_default(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(REGISTRY_ENV, raising=False)
    assert [loc.describe() for loc in registry_locations()] == [DEFAULT_REGISTRY]
    monkeypatch.setenv(
        REGISTRY_ENV, "registry.acme.net/ranges, docker.io/meridianlabsai"
    )
    assert [loc.describe() for loc in registry_locations()] == [
        "registry.acme.net/ranges",
        "docker.io/meridianlabsai",
    ]
    assert registry_locations("./override")[0].describe() == "./override"


def _spec_for_fixture(fixture: Fixture, tmp_path: Path) -> "object":
    spec = load_range(spec_file(tmp_path))
    fixture.manifest = fixture.manifest.model_copy(
        update={"spec_sha256": spec_sha256(spec)}
    )
    from inspect_ranges._build.manifest import save_manifest

    save_manifest(fixture.manifest, fixture.build_cache)
    return spec


def test_spec_pull_resolves_first_match_and_shadows(tmp_path: Path) -> None:
    """The deployment location (first in the path) shadows the fallback deterministically for the same range name."""
    fixture = Fixture(tmp_path)
    spec = _spec_for_fixture(fixture, tmp_path)
    fallback = parse_location(str(tmp_path / "fallback"))
    primary = parse_location(str(tmp_path / "primary"))
    push_range(
        fixture.manifest,
        fallback,
        image_cache=fixture.image_cache,
        build_cache=fixture.build_cache,
        range_dir=fixture.range_dir,
    )
    shadowed = fixture.manifest.model_copy(update={"built_at": "2099-02-02T00:00:00Z"})
    from inspect_ranges._build.manifest import save_manifest

    save_manifest(shadowed, fixture.build_cache)
    push_range(
        shadowed,
        primary,
        image_cache=fixture.image_cache,
        build_cache=fixture.build_cache,
        range_dir=fixture.range_dir,
    )
    images, builds, recipes = fresh_dirs(tmp_path)
    report = pull_range(
        spec,  # type: ignore[arg-type]
        [primary, fallback],
        image_cache=images,
        build_cache=builds,
        recipe_cache=recipes,
    )
    assert report.location == primary.describe()
    from inspect_ranges._build.manifest import load_manifest

    pulled = load_manifest(builds, "distfix")
    assert pulled is not None and pulled.built_at == "2099-02-02T00:00:00Z"


def test_spec_mismatch_refuses_with_nearest(tmp_path: Path) -> None:
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
    edited = load_range(
        spec_file(tmp_path, extra="\n      - name: extra\n        port: 81")
    )
    images, builds, recipes = fresh_dirs(tmp_path)
    with pytest.raises(DistError, match="no-build-for-spec") as excinfo:
        pull_range(
            edited,
            [location],
            image_cache=images,
            build_cache=builds,
            recipe_cache=recipes,
        )
    assert "nearest" in str(excinfo.value)
    assert fixture.manifest.spec_sha256[:12] in str(excinfo.value)
    from inspect_ranges._build.manifest import load_manifest

    assert load_manifest(builds, "distfix") is None


def test_pin_form_pulls_without_spec_match(tmp_path: Path) -> None:
    fixture = Fixture(tmp_path)
    _spec_for_fixture(fixture, tmp_path)
    location = parse_location(str(tmp_path / "mirror"))
    root = push_range(
        fixture.manifest,
        location,
        image_cache=fixture.image_cache,
        build_cache=fixture.build_cache,
        range_dir=fixture.range_dir,
    )
    edited = load_range(
        spec_file(tmp_path, extra="\n      - name: extra\n        port: 81")
    )
    images, builds, recipes = fresh_dirs(tmp_path)
    report = pull_range(
        edited,
        [location],
        image_cache=images,
        build_cache=builds,
        recipe_cache=recipes,
        pin=root.digest,
    )
    assert report.root == root.digest


def test_image_pull_sticky_then_explicit_refresh(tmp_path: Path) -> None:
    """Freezing is automatic (the cache answers, even when the registry moved on); moving forward is the explicit refresh, chain and sidecar together."""
    fixture = Fixture(tmp_path)
    location = parse_location(str(tmp_path / "catalog"))
    push_image_artifact("focal-guest", location, image_cache=fixture.image_cache)

    consumer_cache = tmp_path / "consumer-images"
    consumer_cache.mkdir()
    pulled = pull_image("focal-guest", [location], image_cache=consumer_cache)
    assert pulled is not None
    assert (consumer_cache / "focal-guest.qcow2").read_bytes() == GOLDEN
    assert (consumer_cache / "noble.img").read_bytes() == VENDOR
    assert (consumer_cache / "focal-guest.json").is_file()

    # the publisher moves the name forward (new golden content + sidecar)
    new_golden = b"golden-image-bytes-v2"
    (fixture.image_cache / "focal-guest.qcow2").write_bytes(new_golden)
    metadata = ImageMetadata.model_validate_json(
        (fixture.image_cache / "focal-guest.json").read_text()
    )
    (fixture.image_cache / "focal-guest.json").write_text(
        metadata.model_copy(
            update={"golden_sha256": hashlib.sha256(new_golden).hexdigest()}
        ).model_dump_json()
    )
    push_image_artifact("focal-guest", location, image_cache=fixture.image_cache)

    # sticky: a plain pull refuses to silently replace the cached name
    with pytest.raises(DistError, match="cache-name-conflict"):
        pull_image("focal-guest", [location], image_cache=consumer_cache)
    assert (consumer_cache / "focal-guest.qcow2").read_bytes() == GOLDEN

    # explicit refresh moves the name forward, sidecar included
    refreshed = refresh_image("focal-guest", [location], image_cache=consumer_cache)
    assert refreshed is not None
    assert (consumer_cache / "focal-guest.qcow2").read_bytes() == new_golden
    sidecar = json.loads((consumer_cache / "focal-guest.json").read_text())
    assert sidecar["golden_sha256"] == hashlib.sha256(new_golden).hexdigest()

    # unpublished names refuse with the coded cause
    with pytest.raises(DistError, match="image-not-published"):
        refresh_image("absent-name", [location], image_cache=consumer_cache)

"""Resolution and the spec-driven verbs: location parsing, search-path shadowing, the exact-spec match and its refusal, the pin form, sticky image resolution, and the explicit refresh (no VMs; layouts and the in-process fake registry)."""

import hashlib
import json
from pathlib import Path
from typing import cast

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
from inspect_ranges._dist.resolve import read_image_pull_record
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
        if path.name.startswith("distfix-web-") or path.name == "attack.qcow2":
            # a renamed overlay still embeds its original backing by name
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
    # the pull records the published root it landed from (the build's
    # cache-vs-pin check reads this)
    record = read_image_pull_record(consumer_cache, "focal-guest")
    assert record is not None and record.name == "focal-guest"
    first_root = record.root

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
    moved = read_image_pull_record(consumer_cache, "focal-guest")
    assert moved is not None and moved.root != first_root

    # unpublished names refuse with the coded cause
    with pytest.raises(DistError, match="image-not-published"):
        refresh_image("absent-name", [location], image_cache=consumer_cache)


def test_pinned_image_only_root_refuses(tmp_path: Path) -> None:
    """Round-3 B1a: a pin that names an image-only closure must refuse, never report pull OK with nothing consumable."""
    from inspect_ranges._dist.resolve import pull_pinned

    fixture = Fixture(tmp_path)
    location = parse_location(str(tmp_path / "catalog"))
    image_root = push_image_artifact(
        "focal-guest", location, image_cache=fixture.image_cache
    )
    images, builds, recipes = fresh_dirs(tmp_path)
    with pytest.raises(DistError, match="manifest-invalid"):
        pull_pinned(
            "focal-guest",
            image_root.digest,
            [location],
            image_cache=images,
            build_cache=builds,
            recipe_cache=recipes,
        )
    assert not any(builds.iterdir())


def test_repointed_spec_tag_refuses_before_landing(tmp_path: Path) -> None:
    """Round-3 B1b: tags are mutable; a spec ref re-pointed at a different build refuses published-spec-mismatch with nothing landed."""
    from inspect_ranges._dist import OciLayout

    fixture = Fixture(tmp_path)
    spec = _spec_for_fixture(fixture, tmp_path)
    location = parse_location(str(tmp_path / "mirror"))
    push_range(
        fixture.manifest,
        location,
        image_cache=fixture.image_cache,
        build_cache=fixture.build_cache,
        range_dir=fixture.range_dir,
    )
    # an attacker (or confused publisher) re-points the exact-spec ref at a
    # build of a DIFFERENT spec
    other = fixture.manifest.model_copy(update={"spec_sha256": "feed" * 16})
    from inspect_ranges._build.manifest import save_manifest

    save_manifest(other, fixture.build_cache)
    layout = OciLayout(tmp_path / "mirror").open()
    from inspect_ranges._dist import push_build

    wrong_root = push_build(
        other,
        layout,
        image_cache=fixture.image_cache,
        build_cache=fixture.build_cache,
        range_dir=fixture.range_dir,
        ref="decoy",
    )
    from inspect_ranges._compiler.plan import spec_sha256 as hash_spec

    layout.set_ref(
        location.spec_ref("distfix", hash_spec(spec)),  # type: ignore[arg-type]
        wrong_root,
    )
    images, builds, recipes = fresh_dirs(tmp_path)
    with pytest.raises(DistError, match="published-spec-mismatch"):
        pull_range(
            spec,  # type: ignore[arg-type]
            [location],
            image_cache=images,
            build_cache=builds,
            recipe_cache=recipes,
        )
    from inspect_ranges._build.manifest import load_manifest

    assert load_manifest(builds, "distfix") is None


def test_broken_location_aborts_instead_of_de_shadowing(tmp_path: Path) -> None:
    """Round-3 B2: a broken first location aborts the search; silently falling through would de-shadow the deployment registry."""
    fixture = Fixture(tmp_path)
    spec = _spec_for_fixture(fixture, tmp_path)
    fallback = parse_location(str(tmp_path / "fallback"))
    push_range(
        fixture.manifest,
        fallback,
        image_cache=fixture.image_cache,
        build_cache=fixture.build_cache,
        range_dir=fixture.range_dir,
    )
    broken = parse_location(str(tmp_path / "not-a-layout"))
    (tmp_path / "not-a-layout").mkdir()  # exists but is not an OCI layout
    images, builds, recipes = fresh_dirs(tmp_path)
    with pytest.raises(DistError, match="layout-invalid"):
        pull_range(
            spec,  # type: ignore[arg-type]
            [broken, fallback],
            image_cache=images,
            build_cache=builds,
            recipe_cache=recipes,
        )


def test_pull_pinned_needs_no_spec(tmp_path: Path) -> None:
    """Round-3 B5: the name@sha256 form pulls with no range.yaml in hand."""
    from inspect_ranges._dist.resolve import pull_pinned

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
    images, builds, recipes = fresh_dirs(tmp_path)
    report = pull_pinned(
        "distfix",
        root.digest,
        [location],
        image_cache=images,
        build_cache=builds,
        recipe_cache=recipes,
    )
    assert report.root == root.digest
    from inspect_ranges._build.manifest import load_manifest

    assert load_manifest(builds, "distfix") is not None


def test_pinned_cli_form_parses() -> None:
    from inspect_ranges._cli.distcmd import _parse_pinned

    assert _parse_pinned("vulhub-zabbix@sha256:" + "ab" * 32) == (
        "vulhub-zabbix",
        "sha256:" + "ab" * 32,
    )
    assert _parse_pinned("./range.yaml") is None
    assert _parse_pinned(None) is None
    assert _parse_pinned("name@sha256:short") is None


def test_hub_two_level_depth_refuses(tmp_path: Path) -> None:
    """Round-3 N2: a one-slash published name against the two-level hub refuses where the docstring says it does."""
    hub = parse_location("docker.io/meridianlabsai")
    with pytest.raises(DistError, match="registry-protocol"):
        hub.store_for("acme/payroll-db")


def test_location_parsing_is_cwd_independent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Round-3 N4: a bare word never resolves as a directory, even when one exists in the cwd."""
    (tmp_path / "mirror").mkdir()
    monkeypatch.chdir(tmp_path)
    with pytest.raises(DistError, match="location-invalid"):
        parse_location("mirror")
    assert parse_location("./mirror").is_directory


def test_sticky_pull_never_mutates_present_sidecars(tmp_path: Path) -> None:
    """Round-3 N3: the converge heal writes a MISSING sidecar only; present provenance is never rewritten outside the explicit refresh."""
    fixture = Fixture(tmp_path)
    location = parse_location(str(tmp_path / "catalog"))
    push_image_artifact("focal-guest", location, image_cache=fixture.image_cache)
    consumer = tmp_path / "consumer-images"
    consumer.mkdir()
    pull_image("focal-guest", [location], image_cache=consumer)
    (consumer / "focal-guest.json").write_text('{"local": "annotation"}')
    again = pull_image("focal-guest", [location], image_cache=consumer)
    assert again is not None
    assert (consumer / "focal-guest.json").read_text() == '{"local": "annotation"}'
    assert "focal-guest.json" not in again[1].fetched


def test_push_cli_refuses_without_destination(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Round-3 N5: bare push with nothing configured refuses rather than aiming at the public org."""
    from click.testing import CliRunner
    from inspect_ranges._cli.distcmd import push as push_cmd

    monkeypatch.delenv(REGISTRY_ENV, raising=False)
    runner = CliRunner()
    spec_path = spec_file(tmp_path)
    result = runner.invoke(push_cmd, [str(spec_path)])
    assert result.exit_code != 0
    assert "no-push-location" in result.output


def test_ensure_build_available_warm_cold_and_never_pull(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Slice 4: the provider's implicit fetch. Warm = matching local manifest, zero network (a broken search path proves nothing was consulted); cold = pull through the search path; never-pull = coded refusal before any network."""
    from inspect_ranges._build.manifest import load_manifest
    from inspect_ranges._dist.resolve import NEVER_PULL_ENV, ensure_build_available

    fixture = Fixture(tmp_path)
    spec = _spec_for_fixture(fixture, tmp_path)
    location = parse_location(str(tmp_path / "mirror"))
    push_range(
        fixture.manifest,
        location,
        image_cache=fixture.image_cache,
        build_cache=fixture.build_cache,
        range_dir=fixture.range_dir,
    )
    # warm: the builder's own caches hold the matching manifest; a search path
    # pointing at a BROKEN location proves no network/location is consulted
    monkeypatch.setenv(REGISTRY_ENV, "/nonexistent-mirror-path")
    assert (
        ensure_build_available(
            spec,  # type: ignore[arg-type]
            image_cache=fixture.image_cache,
            build_cache=fixture.build_cache,
            recipe_cache=tmp_path / "rc",
        )
        is None
    )
    # never-pull: a cold consumer refuses with the knob named
    images, builds, recipes = fresh_dirs(tmp_path)
    monkeypatch.setenv(NEVER_PULL_ENV, "1")
    with pytest.raises(DistError, match="never-pull"):
        ensure_build_available(
            spec,  # type: ignore[arg-type]
            image_cache=images,
            build_cache=builds,
            recipe_cache=recipes,
        )
    monkeypatch.delenv(NEVER_PULL_ENV)
    # cold: the fetch runs through the search path with progress events
    monkeypatch.setenv(REGISTRY_ENV, str(tmp_path / "mirror"))
    events: list[tuple[str, str]] = []

    def record(digest: str, state: str, done: int, total: int) -> None:
        events.append((digest[:19], state))

    report = ensure_build_available(
        spec,  # type: ignore[arg-type]
        image_cache=images,
        build_cache=builds,
        recipe_cache=recipes,
        progress=record,
    )
    assert report is not None and report.location == str(tmp_path / "mirror")
    assert load_manifest(builds, "distfix") is not None
    states = {state for _, state in events}
    assert "downloading" in states and "done" in states
    # a content-free spec never pulls
    free = load_range(spec_file(tmp_path, extra=""))
    stripped = free.model_copy(
        update={"hosts": [h.model_copy(update={"services": None}) for h in free.hosts]}
    )
    assert (
        ensure_build_available(
            stripped,
            image_cache=images,
            build_cache=tmp_path / "other-builds",
            recipe_cache=recipes,
        )
        is None
    )


class FakeTty:
    def __init__(self) -> None:
        self.buffer = ""

    def write(self, text: str) -> None:
        self.buffer += text

    def flush(self) -> None:
        pass

    def isatty(self) -> bool:
        return True


def test_transfer_display_tty_shape() -> None:
    """Round-4 N6: the TTY renderer redraws in place, prints Already exists and Complete on their own lines, and close() never leaves a half-drawn bar."""
    from inspect_ranges._dist.progress import TransferDisplay

    out = FakeTty()
    display = TransferDisplay(out=out)  # type: ignore[arg-type]
    digest = "sha256:" + "ab" * 32
    display(digest, "downloading", 512, 1024)
    display(digest, "downloading", 1024, 1024)
    assert out.buffer.count("\r") == 2 and "Downloading" in out.buffer
    display(digest, "done", 1024, 1024)
    assert out.buffer.endswith("abababababab: Complete\n")
    display("sha256:" + "cd" * 32, "exists", 0, 0)
    assert out.buffer.endswith("cdcdcdcdcdcd: Already exists\n")
    # a half-drawn line closes cleanly on failure paths
    display("sha256:" + "ef" * 32, "downloading", 1, 2)
    display.close()
    assert out.buffer.endswith("\n")
    display.final("pull OK   r@sha256:feed")
    assert out.buffer.endswith("pull OK   r@sha256:feed\n")


def test_warm_path_heals_pruned_artifacts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Round-4 N2: a matching manifest whose artifacts were pruned falls through to the pull (seamless healing), never a range-not-built dead end."""
    from inspect_ranges._build.manifest import load_manifest
    from inspect_ranges._dist.resolve import ensure_build_available

    fixture = Fixture(tmp_path)
    spec = _spec_for_fixture(fixture, tmp_path)
    location = parse_location(str(tmp_path / "mirror"))
    push_range(
        fixture.manifest,
        location,
        image_cache=fixture.image_cache,
        build_cache=fixture.build_cache,
        range_dir=fixture.range_dir,
    )
    images, builds, recipes = fresh_dirs(tmp_path)
    monkeypatch.setenv(REGISTRY_ENV, str(tmp_path / "mirror"))
    first = ensure_build_available(
        spec,  # type: ignore[arg-type]
        image_cache=images,
        build_cache=builds,
        recipe_cache=recipes,
    )
    assert first is not None
    # prune the realized image; the manifest still matches the spec
    (images / fixture.realized_file).unlink()
    healed = ensure_build_available(
        spec,  # type: ignore[arg-type]
        image_cache=images,
        build_cache=builds,
        recipe_cache=recipes,
    )
    assert healed is not None
    assert (images / fixture.realized_file).is_file()
    assert load_manifest(builds, "distfix") is not None


def test_catalog_image_references_applies_defaults() -> None:
    """The pre-plan reference sweep mirrors planning: content hosts excluded (the build closure owns them), router and attacker defaults applied, foothold attackers boot nothing, duplicates collapse."""
    from inspect_ranges._dist.resolve import catalog_image_references
    from inspect_ranges.types import (
        Attacker,
        Host,
        Interface,
        Network,
        Os,
        ProvisioningStep,
        RangeMeta,
        RangeSpec,
        Router,
    )

    spec = RangeSpec(
        meta=RangeMeta(name="refs", description="reference sweep"),
        networks=[
            Network(name="lab", cidr="10.0.0.0/24", mode="isolated"),
            Network(name="dmz", cidr="10.0.1.0/24", mode="isolated"),
        ],
        routers=[
            Router(
                name="r",
                interfaces=[Interface(network="lab"), Interface(network="dmz")],
            )
        ],
        hosts=[
            Host(
                name="plain",
                os=Os(type="linux"),
                image="ubuntu-noble",
                interfaces=[Interface(network="lab")],
            ),
            Host(
                name="built",
                os=Os(type="linux"),
                image="focal-guest",
                interfaces=[Interface(network="lab")],
                provisioning=[ProvisioningStep(recipe="acme.web")],
            ),
        ],
        attacker=Attacker(interfaces=[Interface(network="lab")], entry="external"),
    )
    assert catalog_image_references(spec) == ["ubuntu-noble", "attack"]
    # a content ROUTER'S artifacts land via the build pull, exactly like a
    # content host's: its golden leaves the catalog sweep
    provisioned = spec.model_copy(deep=True)
    provisioned.routers[0].image = "fw-golden"
    provisioned.routers[0].provisioning = [ProvisioningStep(recipe="acme.fw")]
    assert catalog_image_references(provisioned) == ["ubuntu-noble", "attack"]
    foothold = spec.model_copy(
        update={
            "attacker": Attacker(host="plain", entry="assumed-breach"),
            "routers": [],
        }
    )
    assert catalog_image_references(foothold) == ["ubuntu-noble"]


def test_ensure_images_available_warm_cold_and_never_pull(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The catalog tier of the implicit fetch (slice 4): a clean machine's eval pulls bare-name images through the search path; warm costs zero network; never-pull refuses coded; an unpublished name names what was searched."""
    from inspect_ranges._dist.errors import DistError
    from inspect_ranges._dist.resolve import NEVER_PULL_ENV, ensure_images_available

    fixture = Fixture(tmp_path)
    location = parse_location(str(tmp_path / "catalog-loc"))
    from inspect_ranges._dist.catalog import publish_golden

    publish_golden("focal-guest", location, image_cache=fixture.image_cache)
    spec = load_range(spec_file(tmp_path))
    monkeypatch.setenv(REGISTRY_ENV, str(tmp_path / "catalog-loc"))

    consumer = tmp_path / "consumer-images"
    consumer.mkdir()
    pulled = ensure_images_available(spec, image_cache=consumer)
    assert pulled == ["focal-guest"]
    assert (consumer / "focal-guest.qcow2").exists()

    # warm: everything cached; a broken search path proves zero network
    monkeypatch.setenv(REGISTRY_ENV, "/nonexistent-mirror-path")
    assert ensure_images_available(spec, image_cache=consumer) == []

    # never-pull: a missing image refuses before any location is consulted
    cold = tmp_path / "cold-images"
    cold.mkdir()
    monkeypatch.setenv(NEVER_PULL_ENV, "1")
    with pytest.raises(DistError) as excinfo:
        ensure_images_available(spec, image_cache=cold)
    assert excinfo.value.code == "never-pull"
    monkeypatch.delenv(NEVER_PULL_ENV)

    # an unpublished name: the refusal names the searched locations
    monkeypatch.setenv(REGISTRY_ENV, str(tmp_path / "catalog-loc"))
    ghost = spec.model_copy(
        update={"attacker": spec.attacker.model_copy(update={"image": "ghost"})}
    )
    with pytest.raises(DistError) as excinfo:
        ensure_images_available(ghost, image_cache=cold)
    assert excinfo.value.code == "image-not-published"
    assert "catalog-loc" in str(excinfo.value)


def test_hub_name_prefix_spells_repos(tmp_path: Path) -> None:
    """The hub form's third segment is a repo-NAME prefix (user decision, 2026-10-19): `docker.io/<org>/<prefix>` spells name `attack` as repo `<org>/<prefix>-attack`, keeping a shared org's namespace clean; deeper nesting refuses, and the one-slash-name refusal still holds."""
    from inspect_ranges._dist.registry import RegistryRepo

    prefixed = parse_location("docker.io/meridianlabsai/inspect-ranges")
    store = prefixed.store_for("attack")
    assert isinstance(store, RegistryRepo)
    assert store.repo == "meridianlabsai/inspect-ranges-attack"
    bare = parse_location("docker.io/meridianlabsai")
    assert cast(RegistryRepo, bare.store_for("attack")).repo == "meridianlabsai/attack"
    with pytest.raises(DistError, match="location-invalid"):
        parse_location("docker.io/meridianlabsai/inspect-ranges/deeper")
    with pytest.raises(DistError, match="registry-protocol"):
        prefixed.store_for("acme/payroll-db")
    # non-hub registries keep PATH prefixes untouched (nested repos are native)
    acme = parse_location("registry.acme.net/ranges")
    assert cast(RegistryRepo, acme.store_for("attack")).repo == "ranges/attack"


def test_hub_empty_name_prefix_refuses() -> None:
    """A trailing slash (empty third segment) refuses instead of silently degrading to the bare-org form."""
    with pytest.raises(DistError, match="location-invalid"):
        parse_location("docker.io/meridianlabsai/")

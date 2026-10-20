"""Push/materialize closure round trips over a synthetic cache (no VMs; the qcow2 backing probe is faked here, proven real by the dist-oci battery)."""

import hashlib
from collections.abc import Callable
from pathlib import Path

import pytest
from inspect_ranges._build.manifest import (
    BaseImageRecord,
    BuildManifest,
    GuestRecord,
    RecipeRecord,
    VerificationRecord,
    load_manifest,
    now_iso,
    realized_file_name,
    save_manifest,
)
from inspect_ranges._build.recipes import recipe_digest, resolve_recipe
from inspect_ranges._dist import (
    Descriptor,
    DistError,
    OciLayout,
    materialize_closure,
    push_build,
)
from inspect_ranges._dist.materialize import MaterializeResult
from inspect_ranges._runtime.images import DaemonPin, ImageMetadata

from tests.test_build_recipes import write_recipe

VENDOR = b"vendor-image-bytes"
GOLDEN = b"golden-image-bytes"
REALIZED = b"realized-image-bytes"


def _hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class Fixture:
    """A synthetic built range: image cache, builds cache, and a range dir with its recipe."""

    def __init__(self, tmp_path: Path) -> None:
        self.image_cache = tmp_path / "images"
        self.build_cache = tmp_path / "builds"
        self.range_dir = tmp_path / "range"
        self.image_cache.mkdir()
        write_recipe(self.range_dir, name="acme.web")
        recipe = resolve_recipe("acme.web", range_dir=self.range_dir)

        (self.image_cache / "noble.img").write_bytes(VENDOR)
        (self.image_cache / "focal-guest.qcow2").write_bytes(GOLDEN)
        (self.image_cache / "focal-guest.json").write_text(
            ImageMetadata(
                name="focal-guest",
                file="focal-guest.qcow2",
                recipe_version="4",
                derivation_key="k" * 64,
                vendor_file="noble.img",
                vendor_sha256=_hex(VENDOR),
                daemon=DaemonPin(name="vsockd", version="3.1.0", sha256="d" * 64),
                golden_sha256=_hex(GOLDEN),
                created=now_iso(),
            ).model_dump_json()
        )
        self.realized_file = realized_file_name("distfix", "web", "b" * 64)
        (self.image_cache / self.realized_file).write_bytes(REALIZED)
        sidecar = self.realized_file.removesuffix(".qcow2") + ".realized.json"
        (self.image_cache / sidecar).write_text(
            '{"type": "realized", "range_name": "distfix", "guest": "web", '
            f'"build_key": "{"b" * 64}", "golden_file": "focal-guest.qcow2", '
            f'"sha256": "{_hex(REALIZED)}", "created": "{now_iso()}"}}'
        )
        self.manifest = BuildManifest(
            range_name="distfix",
            schema_version="0.3",
            spec_sha256="77ab",
            built_at=now_iso(),
            base_images=(
                BaseImageRecord(
                    guest="attacker",
                    kind="attacker",
                    reference="focal-guest",
                    file="focal-guest.qcow2",
                    digest=f"sha256:{_hex(GOLDEN)}",
                ),
            ),
            guests=(
                GuestRecord(
                    name="web",
                    golden_reference="focal-guest",
                    golden_digest=f"sha256:{_hex(GOLDEN)}",
                    realized_file=self.realized_file,
                    realized_sha256=_hex(REALIZED),
                    build_key="b" * 64,
                    recipes=(
                        RecipeRecord(
                            name="acme.web",
                            version=recipe.version,
                            digest=recipe.digest,
                            vars_hash="v1",
                        ),
                    ),
                ),
            ),
            verification=VerificationRecord(verified_at=now_iso(), declarations=()),
        )
        save_manifest(self.manifest, self.build_cache)

    def push(self, tmp_path: Path) -> tuple[OciLayout, "object"]:
        layout = OciLayout(tmp_path / "layout").ensure()
        root = push_build(
            self.manifest,
            layout,
            image_cache=self.image_cache,
            build_cache=self.build_cache,
            range_dir=self.range_dir,
        )
        return layout, root


@pytest.fixture(autouse=True)
def fake_backing_probe(monkeypatch: pytest.MonkeyPatch) -> None:
    """The unit tier fakes the qcow2 header read (synthetic blobs are not qcow2s); the battery proves the real probe."""
    backings = {"focal-guest.qcow2": "noble.img"}

    def probe(path: Path) -> str | None:
        if path.name.startswith("distfix-web-"):
            return "focal-guest.qcow2"
        return backings.get(path.name)

    monkeypatch.setattr("inspect_ranges._dist.materialize._qcow2_backing_name", probe)


def fresh_dirs(tmp_path: Path) -> tuple[Path, Path, Path]:
    dirs = (tmp_path / "c-images", tmp_path / "c-builds", tmp_path / "c-recipes")
    for d in dirs:
        d.mkdir(exist_ok=True)
    return dirs


def test_closure_round_trip(tmp_path: Path) -> None:
    fixture = Fixture(tmp_path)
    layout, root = fixture.push(tmp_path)
    images, builds, recipes = fresh_dirs(tmp_path)
    result = materialize_closure(
        layout,
        root,  # type: ignore[arg-type]
        image_cache=images,
        build_cache=builds,
        recipe_cache=recipes,
    )
    assert isinstance(result, MaterializeResult)
    assert (images / "noble.img").read_bytes() == VENDOR
    assert (images / "focal-guest.qcow2").read_bytes() == GOLDEN
    assert (images / "focal-guest.json").read_text() == (
        fixture.image_cache / "focal-guest.json"
    ).read_text()
    assert (images / fixture.realized_file).read_bytes() == REALIZED
    assert (
        images / (fixture.realized_file.removesuffix(".qcow2") + ".realized.json")
    ).is_file()
    assert (
        recipe_digest(recipes / "acme.web")
        == resolve_recipe("acme.web", range_dir=fixture.range_dir).digest
    )
    pulled = load_manifest(builds, "distfix")
    assert pulled is not None and pulled == fixture.manifest
    assert result.superseded_built_at is None
    assert len(result.fetched) > 0 and result.present == ()

    # converge: a second materialization fetches nothing
    again = materialize_closure(
        layout,
        root,  # type: ignore[arg-type]
        image_cache=images,
        build_cache=builds,
        recipe_cache=recipes,
    )
    assert again.fetched == () and len(again.present) > 0


def test_manifest_lands_last_on_refusal(tmp_path: Path) -> None:
    """A refusal mid-materialization leaves NO consumable build manifest dangling."""
    fixture = Fixture(tmp_path)
    layout, root = fixture.push(tmp_path)
    realized_digest = f"sha256:{_hex(REALIZED)}"
    layout.blob_path(realized_digest).write_bytes(b"tampered-realized-bytes!")
    images, builds, recipes = fresh_dirs(tmp_path)
    with pytest.raises(DistError, match="blob-digest-mismatch"):
        materialize_closure(
            layout,
            root,  # type: ignore[arg-type]
            image_cache=images,
            build_cache=builds,
            recipe_cache=recipes,
        )
    assert load_manifest(builds, "distfix") is None
    assert not (images / fixture.realized_file).exists()


def test_cache_name_conflict_refuses(tmp_path: Path) -> None:
    fixture = Fixture(tmp_path)
    layout, root = fixture.push(tmp_path)
    images, builds, recipes = fresh_dirs(tmp_path)
    (images / "focal-guest.qcow2").write_bytes(b"a different local golden")
    with pytest.raises(DistError, match="cache-name-conflict"):
        materialize_closure(
            layout,
            root,  # type: ignore[arg-type]
            image_cache=images,
            build_cache=builds,
            recipe_cache=recipes,
        )


def test_chain_annotation_mismatch_refuses(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fixture = Fixture(tmp_path)
    layout, root = fixture.push(tmp_path)

    def wrong_backing(path: Path) -> str | None:
        return "somewhere-else.img"

    monkeypatch.setattr(
        "inspect_ranges._dist.materialize._qcow2_backing_name", wrong_backing
    )
    images, builds, recipes = fresh_dirs(tmp_path)
    with pytest.raises(DistError, match="chain-invalid"):
        materialize_closure(
            layout,
            root,  # type: ignore[arg-type]
            image_cache=images,
            build_cache=builds,
            recipe_cache=recipes,
        )


def test_push_refuses_corrupt_cache(tmp_path: Path) -> None:
    """The push verifies cache bytes against the manifest's recorded digests."""
    fixture = Fixture(tmp_path)
    (fixture.image_cache / fixture.realized_file).write_bytes(b"rotted bytes")
    layout = OciLayout(tmp_path / "layout").ensure()
    with pytest.raises(DistError, match="blob-digest-mismatch"):
        push_build(
            fixture.manifest,
            layout,
            image_cache=fixture.image_cache,
            build_cache=fixture.build_cache,
            range_dir=fixture.range_dir,
        )


def test_push_refuses_recipe_drift(tmp_path: Path) -> None:
    fixture = Fixture(tmp_path)
    entry = next((fixture.range_dir / "recipes" / "acme.web").rglob("*.sh"), None)
    assert entry is not None
    entry.write_text(entry.read_text() + "\n# drifted\n")
    layout = OciLayout(tmp_path / "layout").ensure()
    with pytest.raises(DistError, match="recipe-closure-broken"):
        push_build(
            fixture.manifest,
            layout,
            image_cache=fixture.image_cache,
            build_cache=fixture.build_cache,
            range_dir=fixture.range_dir,
        )


def test_pull_supersedes_a_different_manifest(tmp_path: Path) -> None:
    fixture = Fixture(tmp_path)
    layout, root = fixture.push(tmp_path)
    images, builds, recipes = fresh_dirs(tmp_path)
    prior = fixture.manifest.model_copy(
        update={"spec_sha256": "older", "built_at": "2026-01-01T00:00:00Z"}
    )
    save_manifest(prior, builds)
    result = materialize_closure(
        layout,
        root,  # type: ignore[arg-type]
        image_cache=images,
        build_cache=builds,
        recipe_cache=recipes,
    )
    assert result.superseded_built_at == "2026-01-01T00:00:00Z"
    pulled = load_manifest(builds, "distfix")
    assert pulled is not None and pulled.spec_sha256 == "77ab"


def _rebuilt_root(layout: OciLayout, keep: "Callable[[object], bool]") -> "object":
    """A new digest-valid root index keeping only the members `keep` accepts."""
    from inspect_ranges._dist.oci import OciIndex

    original = layout.ref("distfix")
    index = OciIndex.model_validate_json(layout.read_blob(original))
    index.manifests = [m for m in index.manifests if keep(m)]
    data = index.canonical_bytes()
    digest = layout.put_blob_bytes(data)
    return Descriptor(media_type=index.media_type, digest=digest, size=len(data))


def test_pruned_closure_refuses_before_the_manifest_lands(tmp_path: Path) -> None:
    """Round-1 B1: a digest-valid root missing a referenced artifact must refuse, never report success over a partial publication."""
    from inspect_ranges._dist.encode import ARTIFACT_REALIZED

    fixture = Fixture(tmp_path)
    layout, _ = fixture.push(tmp_path)
    root = _rebuilt_root(
        layout, lambda m: getattr(m, "artifact_type", None) != ARTIFACT_REALIZED
    )
    images, builds, recipes = fresh_dirs(tmp_path)
    with pytest.raises(DistError, match="closure-incomplete"):
        materialize_closure(
            layout,
            root,  # type: ignore[arg-type]
            image_cache=images,
            build_cache=builds,
            recipe_cache=recipes,
        )
    assert load_manifest(builds, "distfix") is None


def test_garbage_root_index_is_a_coded_refusal(tmp_path: Path) -> None:
    """Round-1 B3: a digest-valid but unparseable root index refuses with manifest-invalid, never a raw ValidationError."""
    from inspect_ranges._dist.oci import MEDIA_TYPE_INDEX

    fixture = Fixture(tmp_path)
    layout, _ = fixture.push(tmp_path)
    garbage = b'{"schemaVersion": 2, "manifests": "truncated...'
    digest = layout.put_blob_bytes(garbage)
    root = Descriptor(media_type=MEDIA_TYPE_INDEX, digest=digest, size=len(garbage))
    images, builds, recipes = fresh_dirs(tmp_path)
    with pytest.raises(DistError, match="manifest-invalid"):
        materialize_closure(
            layout,
            root,
            image_cache=images,
            build_cache=builds,
            recipe_cache=recipes,
        )


def test_missing_blob_is_a_coded_refusal(tmp_path: Path) -> None:
    fixture = Fixture(tmp_path)
    layout, root = fixture.push(tmp_path)
    layout.blob_path(f"sha256:{_hex(VENDOR)}").unlink()
    images, builds, recipes = fresh_dirs(tmp_path)
    with pytest.raises(DistError, match="missing-blob"):
        materialize_closure(
            layout,
            root,  # type: ignore[arg-type]
            image_cache=images,
            build_cache=builds,
            recipe_cache=recipes,
        )
    assert load_manifest(builds, "distfix") is None


def test_drifted_backing_digest_annotation_refuses(tmp_path: Path) -> None:
    """Round-1 B3: an annotation declaring a different backing digest than the blob that landed refuses chain-invalid."""
    from inspect_ranges._dist.encode import ANN_BACKING_DIGEST, ARTIFACT_GOLDEN
    from inspect_ranges._dist.oci import OciIndex

    fixture = Fixture(tmp_path)
    layout, _ = fixture.push(tmp_path)
    original = layout.ref("distfix")
    index = OciIndex.model_validate_json(layout.read_blob(original))
    members: list[Descriptor] = []
    for member in index.manifests:
        if member.artifact_type == ARTIFACT_GOLDEN:
            manifest = layout.manifest(member)
            annotations = dict(manifest.annotations or {})
            annotations[ANN_BACKING_DIGEST] = "sha256:" + "e" * 64
            member = layout.put_manifest(
                manifest.model_copy(update={"annotations": annotations})
            )
        members.append(member)
    index.manifests = members
    data = index.canonical_bytes()
    root = Descriptor(
        media_type=index.media_type,
        digest=layout.put_blob_bytes(data),
        size=len(data),
    )
    images, builds, recipes = fresh_dirs(tmp_path)
    with pytest.raises(DistError, match="chain-invalid"):
        materialize_closure(
            layout,
            root,
            image_cache=images,
            build_cache=builds,
            recipe_cache=recipes,
        )


def test_converge_heals_a_missing_sidecar(tmp_path: Path) -> None:
    """Round-1 N4: the crash window between image and sidecar must not become a permanent fully-present-but-unmanaged state."""
    fixture = Fixture(tmp_path)
    layout, root = fixture.push(tmp_path)
    images, builds, recipes = fresh_dirs(tmp_path)
    materialize_closure(
        layout,
        root,  # type: ignore[arg-type]
        image_cache=images,
        build_cache=builds,
        recipe_cache=recipes,
    )
    sidecar = images / (fixture.realized_file.removesuffix(".qcow2") + ".realized.json")
    sidecar.unlink()
    result = materialize_closure(
        layout,
        root,  # type: ignore[arg-type]
        image_cache=images,
        build_cache=builds,
        recipe_cache=recipes,
    )
    assert sidecar.is_file()
    assert sidecar.name in result.fetched


def test_stale_pulling_temp_is_swept(tmp_path: Path) -> None:
    """Round-1 N5: a hard-killed pull's temp is reclaimed by the next attempt on that name."""
    fixture = Fixture(tmp_path)
    layout, root = fixture.push(tmp_path)
    images, builds, recipes = fresh_dirs(tmp_path)
    stale = images / f".{fixture.realized_file}.pulling-dead"
    stale.write_bytes(b"x" * 100)
    materialize_closure(
        layout,
        root,  # type: ignore[arg-type]
        image_cache=images,
        build_cache=builds,
        recipe_cache=recipes,
    )
    assert not stale.exists()
    assert not list(images.glob(".*.pulling-*"))


def test_push_refuses_a_concurrently_rebuilt_manifest(tmp_path: Path) -> None:
    """Round-1 N7: the pull root's manifest bytes must belong to the closure that was just encoded."""
    from inspect_ranges._build.manifest import save_manifest as save

    fixture = Fixture(tmp_path)
    rebuilt = fixture.manifest.model_copy(update={"built_at": "2099-01-01T00:00:00Z"})
    save(rebuilt, fixture.build_cache)
    layout = OciLayout(tmp_path / "layout").ensure()
    with pytest.raises(DistError, match="manifest-changed"):
        push_build(
            fixture.manifest,
            layout,
            image_cache=fixture.image_cache,
            build_cache=fixture.build_cache,
            range_dir=fixture.range_dir,
        )


def test_sidecarless_image_with_embedded_backing_refuses_at_push(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Round-1 N6: a bare vendor base must be chainless; an embedded backing with no sidecar would publish a chain that cannot boot."""
    from inspect_ranges._build.manifest import BaseImageRecord as Base

    fixture = Fixture(tmp_path)
    (fixture.image_cache / "plain.qcow2").write_bytes(b"orphan overlay")

    def fake_backing(path: Path) -> str | None:
        return "lost-parent.qcow2" if path.name == "plain.qcow2" else None

    monkeypatch.setattr("inspect_ranges._dist.encode.qcow2_backing_name", fake_backing)
    manifest = fixture.manifest.model_copy(
        update={
            "base_images": (
                *fixture.manifest.base_images,
                Base(
                    guest="router",
                    kind="router",
                    reference="plain",
                    file="plain.qcow2",
                    digest="",
                ),
            )
        }
    )
    layout = OciLayout(tmp_path / "layout").ensure()
    with pytest.raises(DistError, match="chain-invalid"):
        push_build(
            manifest,
            layout,
            image_cache=fixture.image_cache,
            build_cache=fixture.build_cache,
            range_dir=fixture.range_dir,
        )

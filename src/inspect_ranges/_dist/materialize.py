"""Materializing a pulled closure into the local caches: the consume side of distribution-v1 slice 1.

The ordering is the integrity contract made operational: vendor bases land before the goldens that back onto them, goldens before realized images, recipe bundles next, and the build manifest LAST, so a consumer that observes the manifest can always resolve every artifact it names (no partial publication observed as complete). Images land under the cache's own per-name advisory lock (the same `.{file}.lock` the derive and capture paths take, so a concurrent derive and a concurrent pull of one name serialize), with each kind's established write order (golden sidecar first, realized image first). An existing cache file either matches the incoming digest (converge, skip) or refuses: the flat cache holds one meaning per name, and shadowing is resolution's job, never the cache's.

Backing-chain validation runs at materialization: the qcow2 header's embedded backing reference must equal the manifest annotation's backing file, and the annotated backing digest must equal the digest its blob actually landed under. A chain whose bytes and annotations disagree refuses before anything could boot it.
"""

import fcntl
import hashlib
import os
import shutil
import tarfile
import tempfile
from contextlib import contextmanager
from pathlib import Path
from typing import TYPE_CHECKING

from pydantic import BaseModel, ConfigDict

from .._build.manifest import BuildManifest, load_manifest, save_manifest
from .._build.recipes import recipe_digest
from .._compiler.plan import image_file_name
from .encode import (
    ANN_BACKING_DIGEST,
    ANN_BACKING_FILE,
    ANN_NAME,
    ANN_RECIPE_DIGEST,
    ARTIFACT_BUILD_MANIFEST,
    ARTIFACT_GOLDEN,
    ARTIFACT_REALIZED,
    ARTIFACT_RECIPE_BUNDLE,
    ARTIFACT_VENDOR_BASE,
    LAYER_BUILD_MANIFEST,
    LAYER_QCOW2,
    LAYER_RECIPE_TAR,
    LAYER_SIDECAR,
)
from .encode import (
    qcow2_backing_name as _qcow2_backing_name,
)
from .errors import DistError
from .oci import (
    MEDIA_TYPE_INDEX,
    ContentStore,
    Descriptor,
    OciManifest,
    ProgressFn,
    atomic_write,
)

if TYPE_CHECKING:
    from collections.abc import Generator

__all__ = ["MaterializeResult", "materialize_closure"]


_KIND_ORDER = (
    ARTIFACT_VENDOR_BASE,
    ARTIFACT_GOLDEN,
    ARTIFACT_REALIZED,
    ARTIFACT_RECIPE_BUNDLE,
    ARTIFACT_BUILD_MANIFEST,
)


class MaterializeResult(BaseModel):
    """What a materialization did, for the caller's transfer report."""

    model_config = ConfigDict(frozen=True)

    range_name: str | None
    """The pulled build manifest's range; `None` for an image-only closure."""

    fetched: tuple[str, ...]
    """Cache files and bundles written by this call."""

    present: tuple[str, ...]
    """Closure members that already matched by digest (the `Already exists` lines)."""

    superseded_built_at: str | None = None
    """The prior build manifest this pull replaced, when one existed."""


@contextmanager
def _name_lock(cache: Path, file: str) -> "Generator[None]":
    """The image cache's per-name advisory lock (shared lock-file path with derive and capture)."""
    cache.mkdir(parents=True, exist_ok=True)
    lock_path = cache / f".{file}.lock"
    with open(lock_path, "w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(lock, fcntl.LOCK_UN)


def _annotation(manifest: OciManifest, key: str) -> str:
    value = (manifest.annotations or {}).get(key)
    if not value:
        raise DistError(
            "manifest-invalid",
            f"artifact manifest {manifest.artifact_type} lacks the {key} annotation",
        )
    return value


def _layer(manifest: OciManifest, media_type: str) -> Descriptor:
    for layer in manifest.layers:
        if layer.media_type == media_type:
            return layer
    raise DistError(
        "manifest-invalid",
        f"artifact manifest {manifest.artifact_type} carries no {media_type} layer",
    )


def _cache_converges(target: Path, blob: Descriptor) -> bool:
    """Whether an existing cache file converges with the incoming blob WITHOUT re-hashing multi-GB bytes at init (round-4 N3): size must match, and byte integrity is re-verified on every boot by up's verify-images, so a same-size divergent file still refuses at boot with a named cause rather than booting."""
    if target.stat().st_size != blob.size:
        return False
    if blob.size <= _SMALL_CONVERGE_CAP:
        hasher = hashlib.sha256()
        with target.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1 << 20), b""):
                hasher.update(chunk)
        return f"sha256:{hasher.hexdigest()}" == blob.digest
    return True


_SMALL_CONVERGE_CAP = 64 * 1024 * 1024
"""Files up to this size still hash at converge (cheap and exact); above it, size plus the boot-time verification carry the contract."""


def _land_image(
    store: ContentStore,
    manifest: OciManifest,
    image_cache: Path,
    *,
    sidecar_suffix: str | None,
    sidecar_first: bool,
    fetched: list[str],
    present: list[str],
    replace: bool = False,
    progress: "ProgressFn | None" = None,
) -> None:
    """Land one image artifact (and its sidecar) under the cache's lock and write-order conventions."""
    name = _annotation(manifest, ANN_NAME)
    if "/" in name or name.startswith("."):
        raise DistError("manifest-invalid", f"{name!r} is not a cache file name")
    blob = _layer(manifest, LAYER_QCOW2)
    target = image_cache / name
    with _name_lock(image_cache, name):
        # a hard-killed pull of this name strands a `.{name}.pulling-*` temp;
        # under the lock it is debris by definition (the derive/capture lesson)
        for stale in image_cache.glob(f".{name}.pulling-*"):
            stale.unlink(missing_ok=True)

        def write_sidecar(*, heal: bool = False) -> None:
            if sidecar_suffix is None:
                return
            sidecar_path = image_cache / (name.removesuffix(".qcow2") + sidecar_suffix)
            if heal and sidecar_path.is_file():
                # the sticky path never mutates present provenance (round-3 N3);
                # healing covers only the crash window's MISSING sidecar
                return
            data = store.read_blob(_layer(manifest, LAYER_SIDECAR))
            atomic_write(sidecar_path, data)
            fetched.append(sidecar_path.name)

        if target.is_file():
            if _cache_converges(target, blob):
                # converge, but HEAL a missing sidecar: a crash window between
                # image and sidecar must not become permanent (round-1 N4)
                write_sidecar(heal=True)
                present.append(name)
                if progress is not None:
                    progress(blob.digest, "exists", 0, 0)
                return
            if not replace:
                raise DistError(
                    "cache-name-conflict",
                    f"{target} already holds different content than {blob.digest}; the flat cache holds one meaning per name (prune or rename the local file, or refresh to move the name forward)",
                )
            # the explicit move-forward act: land the new bytes atomically over
            # the old name, sidecar refreshed with its kind's write order
            if sidecar_first:
                write_sidecar()
                store.copy_blob_to(blob, target, temp_prefix=f".{name}.pulling-")
            else:
                store.copy_blob_to(blob, target, temp_prefix=f".{name}.pulling-")
                write_sidecar()
            fetched.append(name)
            return
        if sidecar_first:
            write_sidecar()
            store.copy_blob_to(
                blob, target, temp_prefix=f".{name}.pulling-", progress=progress
            )
        else:
            store.copy_blob_to(
                blob, target, temp_prefix=f".{name}.pulling-", progress=progress
            )
            write_sidecar()
        fetched.append(name)


def _validate_chain(
    manifest: OciManifest, image_cache: Path, landed_digests: dict[str, str]
) -> None:
    """The materialization-time chain check: embedded backing name equals the annotation, annotated backing digest equals what the backing landed as."""
    name = _annotation(manifest, ANN_NAME)
    declared_file = _annotation(manifest, ANN_BACKING_FILE)
    declared_digest = _annotation(manifest, ANN_BACKING_DIGEST)
    embedded = _qcow2_backing_name(image_cache / name)
    if embedded != declared_file:
        raise DistError(
            "chain-invalid",
            f"{name} embeds backing {embedded!r} but its manifest declares {declared_file!r}",
        )
    landed = landed_digests.get(declared_file)
    if landed is None:
        raise DistError(
            "chain-invalid",
            f"{name} backs onto {declared_file}, which is not part of this closure",
        )
    if landed != declared_digest:
        raise DistError(
            "chain-invalid",
            f"{name} declares backing digest {declared_digest} but {declared_file} landed as {landed}",
        )


def materialize_closure(
    store: ContentStore,
    root: Descriptor,
    *,
    image_cache: Path,
    build_cache: Path | None = None,
    recipe_cache: Path | None = None,
    replace_images: bool = False,
    require_manifest: bool = False,
    expect_range: str | None = None,
    expect_spec: str | None = None,
    progress: "ProgressFn | None" = None,
) -> MaterializeResult:
    """Materialize a pull root's closure into the local caches, verified end to end; returns what was fetched versus already present.

    A range closure carries exactly one build manifest and needs all three caches; an image-only closure (a published golden chain) carries none and touches only the image cache, with `build_cache`/`recipe_cache` permitted to be `None`. Range pulls pass `require_manifest` (a manifest-less root refuses rather than reporting vacuous success) and `expect_range`/`expect_spec`: tags are mutable, so what a ref RESOLVED TO is untrusted until the landed manifest's recorded identity equals what was asked for, checked BEFORE the manifest lands (round-3 review B1). `replace_images` is the explicit move-forward act (`images refresh`): a cache name holding DIFFERENT content is overwritten instead of refusing, chain and sidecars together, and the next build's keys change accordingly; it never applies to range closures, whose cache names are content-addressed by construction.

    Raises:
        DistError: missing or corrupt blobs, invalid manifests, cache name conflicts, broken backing chains, or recipe bundles whose extracted content does not reproduce the recorded recipe digest. On refusal the build manifest has NOT landed, so nothing consumable dangles.
    """
    if root.media_type != MEDIA_TYPE_INDEX:
        raise DistError(
            "manifest-invalid",
            f"a pull root is an OCI index, not {root.media_type}",
        )
    index = store.read_index(root)
    artifacts: dict[str, list[OciManifest]] = {kind: [] for kind in _KIND_ORDER}
    for member in index.manifests:
        manifest = store.manifest(member)
        if manifest.artifact_type not in artifacts:
            raise DistError(
                "manifest-invalid",
                f"unknown artifact type {manifest.artifact_type!r} in the closure",
            )
        artifacts[manifest.artifact_type].append(manifest)
    builds = artifacts[ARTIFACT_BUILD_MANIFEST]
    if len(builds) > 1:
        raise DistError(
            "manifest-invalid",
            f"a pull root carries at most one build manifest; this one carries {len(builds)}",
        )
    if require_manifest and not builds:
        raise DistError(
            "manifest-invalid",
            "this root is not a range closure (it carries no build manifest)",
        )
    if builds and (build_cache is None or recipe_cache is None):
        raise DistError(
            "manifest-invalid",
            "this closure carries a build manifest, which needs the builds and recipe caches",
        )
    if artifacts[ARTIFACT_RECIPE_BUNDLE] and recipe_cache is None:
        raise DistError(
            "manifest-invalid",
            "this closure carries recipe bundles, which need the recipe cache",
        )

    fetched: list[str] = []
    present: list[str] = []
    landed_digests: dict[str, str] = {}

    from .gc import chains_lock

    with chains_lock(image_cache, exclusive=False):
        _land_images(
            store,
            artifacts,
            image_cache,
            replace_images=replace_images,
            fetched=fetched,
            present=present,
            landed_digests=landed_digests,
            progress=progress,
        )
    return _finish_closure(
        store,
        artifacts,
        landed_digests,
        build_cache=build_cache,
        recipe_cache=recipe_cache,
        require_manifest=require_manifest,
        expect_range=expect_range,
        expect_spec=expect_spec,
        fetched=fetched,
        present=present,
    )


def _land_images(
    store: ContentStore,
    artifacts: dict[str, list[OciManifest]],
    image_cache: Path,
    *,
    replace_images: bool,
    fetched: list[str],
    present: list[str],
    landed_digests: dict[str, str],
    progress: "ProgressFn | None",
) -> None:
    """The image-landing phase, held under the shared chains lock so the GC's exclusive scan never observes a half-landed chain (round-5 B2)."""
    if replace_images:
        # the refresh barrier (round-3 B4): every image in the closure stages
        # fully under every member's lock, then the renames happen together,
        # so the mixed-chain window is two renames wide instead of a multi-GB
        # download wide; a crash inside even that window is caught by up's
        # full-chain verification, never booted silently
        _replace_chain(
            store,
            [
                (manifest, suffix, first)
                for kind, suffix, first in (
                    (ARTIFACT_VENDOR_BASE, None, False),
                    (ARTIFACT_GOLDEN, ".json", True),
                    (ARTIFACT_REALIZED, ".realized.json", False),
                )
                for manifest in artifacts[kind]
            ],
            image_cache,
            fetched=fetched,
            present=present,
            progress=progress,
        )
        for kind in (ARTIFACT_VENDOR_BASE, ARTIFACT_GOLDEN, ARTIFACT_REALIZED):
            for manifest in artifacts[kind]:
                landed_digests[_annotation(manifest, ANN_NAME)] = _layer(
                    manifest, LAYER_QCOW2
                ).digest
                if kind != ARTIFACT_VENDOR_BASE:
                    _validate_chain(manifest, image_cache, landed_digests)
        return

    for manifest in artifacts[ARTIFACT_VENDOR_BASE]:
        _land_image(
            store,
            manifest,
            image_cache,
            sidecar_suffix=None,
            sidecar_first=False,
            fetched=fetched,
            present=present,
            replace=replace_images,
            progress=progress,
        )
        landed_digests[_annotation(manifest, ANN_NAME)] = _layer(
            manifest, LAYER_QCOW2
        ).digest
    for manifest in artifacts[ARTIFACT_GOLDEN]:
        _land_image(
            store,
            manifest,
            image_cache,
            sidecar_suffix=".json",
            sidecar_first=True,
            fetched=fetched,
            present=present,
            replace=replace_images,
            progress=progress,
        )
        landed_digests[_annotation(manifest, ANN_NAME)] = _layer(
            manifest, LAYER_QCOW2
        ).digest
        _validate_chain(manifest, image_cache, landed_digests)
    for manifest in artifacts[ARTIFACT_REALIZED]:
        _land_image(
            store,
            manifest,
            image_cache,
            sidecar_suffix=".realized.json",
            sidecar_first=False,
            fetched=fetched,
            present=present,
            replace=replace_images,
            progress=progress,
        )
        landed_digests[_annotation(manifest, ANN_NAME)] = _layer(
            manifest, LAYER_QCOW2
        ).digest
        _validate_chain(manifest, image_cache, landed_digests)


def _replace_chain(
    store: ContentStore,
    members: "list[tuple[OciManifest, str | None, bool]]",
    image_cache: Path,
    *,
    fetched: list[str],
    present: list[str],
    progress: "ProgressFn | None" = None,
) -> None:
    """The refresh barrier: hold every member's name lock, stage every changed image fully, then rename the whole set together (sidecars with their kind's order)."""
    from contextlib import ExitStack

    plans: list[tuple[str, OciManifest, str | None, bool]] = []
    for manifest, suffix, sidecar_first in members:
        name = _annotation(manifest, ANN_NAME)
        if "/" in name or name.startswith("."):
            raise DistError("manifest-invalid", f"{name!r} is not a cache file name")
        plans.append((name, manifest, suffix, sidecar_first))
    with ExitStack() as stack:
        for name, _, _, _ in sorted(plans):  # sorted: one lock order, no deadlock
            stack.enter_context(_name_lock(image_cache, name))
        staged: list[tuple[Path, Path, OciManifest, str | None, bool]] = []
        for name, manifest, suffix, sidecar_first in plans:
            for stale in image_cache.glob(f".{name}.pulling-*"):
                stale.unlink(missing_ok=True)
            blob = _layer(manifest, LAYER_QCOW2)
            target = image_cache / name
            if target.is_file() and _cache_converges(target, blob):
                present.append(name)
                continue
            stage = image_cache / f".{name}.pulling-staged"
            store.copy_blob_to(
                blob, stage, temp_prefix=f".{name}.pulling-", progress=progress
            )
            staged.append((stage, target, manifest, suffix, sidecar_first))
        try:
            for stage, target, manifest, suffix, sidecar_first in staged:
                name = target.name
                if sidecar_first and suffix is not None:
                    _write_replace_sidecar(
                        store, manifest, image_cache, suffix, fetched
                    )
                os.replace(stage, target)
                if not sidecar_first and suffix is not None:
                    _write_replace_sidecar(
                        store, manifest, image_cache, suffix, fetched
                    )
                fetched.append(name)
        finally:
            for stage, _, _, _, _ in staged:
                stage.unlink(missing_ok=True)


def _write_replace_sidecar(
    store: ContentStore,
    manifest: OciManifest,
    image_cache: Path,
    suffix: str,
    fetched: list[str],
) -> None:
    name = _annotation(manifest, ANN_NAME)
    sidecar_path = image_cache / (name.removesuffix(".qcow2") + suffix)
    atomic_write(sidecar_path, store.read_blob(_layer(manifest, LAYER_SIDECAR)))
    fetched.append(sidecar_path.name)


def _finish_closure(
    store: ContentStore,
    artifacts: dict[str, list[OciManifest]],
    landed_digests: dict[str, str],
    *,
    build_cache: Path | None,
    recipe_cache: Path | None,
    require_manifest: bool,
    expect_range: str | None,
    expect_spec: str | None,
    fetched: list[str],
    present: list[str],
) -> MaterializeResult:
    """The closure's tail, shared by the normal and replace paths: recipes, the identity and completeness gates, and the manifest landing LAST."""
    builds = artifacts[ARTIFACT_BUILD_MANIFEST]
    landed_recipes: dict[str, str] = {}
    for manifest in artifacts[ARTIFACT_RECIPE_BUNDLE]:
        assert recipe_cache is not None  # refused above when absent
        landed = _land_recipe(
            store, manifest, recipe_cache, fetched=fetched, present=present
        )
        landed_recipes[landed] = _annotation(manifest, ANN_RECIPE_DIGEST)

    if not builds:
        return MaterializeResult(
            range_name=None, fetched=tuple(fetched), present=tuple(present)
        )
    build = builds[0]
    assert build_cache is not None  # refused above when absent
    manifest_bytes = store.read_blob(_layer(build, LAYER_BUILD_MANIFEST))
    try:
        build_manifest = BuildManifest.model_validate_json(manifest_bytes)
    except ValueError as error:
        raise DistError(
            "manifest-invalid", f"the pulled build manifest does not parse: {error}"
        ) from error
    if expect_range is not None and build_manifest.range_name != expect_range:
        raise DistError(
            "published-mismatch",
            f"this root carries a build of {build_manifest.range_name!r}, not {expect_range!r}; the location's reference points at the wrong range",
        )
    if expect_spec is not None and build_manifest.spec_sha256 != expect_spec:
        raise DistError(
            "published-spec-mismatch",
            f"this root's build manifest records spec {build_manifest.spec_sha256[:12]}..., not the requested {expect_spec[:12]}...; the location's spec reference was re-pointed at a different build",
        )
    # the completeness gate (round-1 B1): the build manifest lands only when
    # the closure actually delivered every artifact it references, so a pruned
    # or partial root can never materialize as a consumable range (and a
    # slice-5 mirror of such a root refuses here rather than propagating)
    _validate_completeness(build_manifest, landed_digests, landed_recipes)
    prior = load_manifest(build_cache, build_manifest.range_name)
    superseded: str | None = None
    if prior is not None and (
        prior.spec_sha256 != build_manifest.spec_sha256
        or prior.built_at != build_manifest.built_at
    ):
        superseded = prior.built_at
    if prior is None or superseded is not None:
        save_manifest(build_manifest, build_cache)
        fetched.append(f"{build_manifest.range_name}/manifest.json")
    else:
        present.append(f"{build_manifest.range_name}/manifest.json")

    return MaterializeResult(
        range_name=build_manifest.range_name,
        fetched=tuple(fetched),
        present=tuple(present),
        superseded_built_at=superseded,
    )


def _validate_completeness(
    build_manifest: BuildManifest,
    landed_digests: dict[str, str],
    landed_recipes: dict[str, str],
) -> None:
    """Every artifact the build manifest references must have landed (or converged) from this closure, at the recorded digest."""

    def require(file: str, digest: str | None, what: str) -> None:
        landed = landed_digests.get(file)
        if landed is None:
            raise DistError(
                "closure-incomplete",
                f"the build manifest references {what} {file!r} but the closure does not carry it",
            )
        if digest:
            expected = digest if digest.startswith("sha256:") else f"sha256:{digest}"
            if landed != expected:
                raise DistError(
                    "closure-incomplete",
                    f"{what} {file!r} landed as {landed}, but the build manifest records {expected}",
                )

    for base in build_manifest.base_images:
        require(base.file, base.digest or None, "base image")
    for guest in build_manifest.guests:
        require(guest.realized_file, guest.realized_sha256, "realized image")
        require(image_file_name(guest.golden_reference), guest.golden_digest, "golden")
        for record in guest.recipes:
            landed = landed_recipes.get(record.name)
            if landed is None:
                raise DistError(
                    "closure-incomplete",
                    f"the build manifest references recipe {record.name!r} but the closure does not carry it",
                )
            if landed != record.digest:
                raise DistError(
                    "closure-incomplete",
                    f"recipe {record.name!r} landed at digest {landed[:12]}, but the build manifest records {record.digest[:12]}",
                )


def _land_recipe(
    store: ContentStore,
    manifest: OciManifest,
    recipe_cache: Path,
    *,
    fetched: list[str],
    present: list[str],
) -> str:
    """Extract a recipe bundle into the flat name-keyed recipe cache; the recorded recipe digest must reproduce from the extracted tree. Returns the landed name.

    Concurrency follows the image cache's discipline: a per-name advisory lock (`.{name}.lock` in the recipe cache) serializes pullers of one bundle, staging directories are uniquely named and swept under the lock, and the tar bytes are verified into a private copy before anything parses them.
    """
    name = _annotation(manifest, ANN_NAME)
    declared = _annotation(manifest, ANN_RECIPE_DIGEST)
    if "/" in name or name.startswith("."):
        raise DistError("manifest-invalid", f"{name!r} is not a recipe name")
    recipe_cache.mkdir(parents=True, exist_ok=True)
    target = recipe_cache / name
    with _name_lock(recipe_cache, name):
        for stale in recipe_cache.glob(f".{name}.pulling-*"):
            _rmtree(stale)
        if target.is_dir():
            try:
                existing = recipe_digest(target)
            except Exception as error:
                raise DistError(
                    "cache-name-conflict",
                    f"recipe cache entry {name!r} is not a digestable bundle ({error}); remove it to pull this bundle",
                ) from error
            if existing == declared:
                present.append(f"recipes/{name}")
                return name
            raise DistError(
                "cache-name-conflict",
                f"recipe cache already holds {name!r} at digest {existing[:12]}, not {declared[:12]}; remove it to pull this bundle",
            )
        staging = Path(tempfile.mkdtemp(dir=recipe_cache, prefix=f".{name}.pulling-"))
        try:
            # verify-while-copy into a private file, then parse only verified
            # bytes (read_blob's in-memory cap does not bound bundle size)
            tar_path = staging / "bundle.tar"
            store.copy_blob_to(_layer(manifest, LAYER_RECIPE_TAR), tar_path)
            tree = staging / "tree"
            tree.mkdir()
            with tarfile.open(tar_path) as tar:
                for member in tar.getmembers():
                    if not member.isfile() or member.name.startswith(("/", "..")):
                        raise DistError(
                            "recipe-bundle-invalid",
                            f"bundle member {member.name!r} is not a safe regular file",
                        )
                tar.extractall(tree, filter="data")
            extracted = recipe_digest(tree)
            if extracted != declared:
                raise DistError(
                    "blob-digest-mismatch",
                    f"recipe {name!r} extracted to digest {extracted[:12]}, expected {declared[:12]}",
                )
            tree.rename(target)
            fetched.append(f"recipes/{name}")
            return name
        finally:
            _rmtree(staging)


def _rmtree(path: Path) -> None:
    shutil.rmtree(path, ignore_errors=True)

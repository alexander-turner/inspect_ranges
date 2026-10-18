"""Materializing a pulled closure into the local caches: the consume side of distribution-v1 slice 1.

The ordering is the integrity contract made operational: vendor bases land before the goldens that back onto them, goldens before realized images, recipe bundles next, and the build manifest LAST, so a consumer that observes the manifest can always resolve every artifact it names (no partial publication observed as complete). Images land under the cache's own per-name advisory lock (the same `.{file}.lock` the derive and capture paths take, so a concurrent derive and a concurrent pull of one name serialize), with each kind's established write order (golden sidecar first, realized image first). An existing cache file either matches the incoming digest (converge, skip) or refuses: the flat cache holds one meaning per name, and shadowing is resolution's job, never the cache's.

Backing-chain validation runs at materialization: the qcow2 header's embedded backing reference must equal the manifest annotation's backing file, and the annotated backing digest must equal the digest its blob actually landed under. A chain whose bytes and annotations disagree refuses before anything could boot it.
"""

import fcntl
import hashlib
import io
import json
import shutil
import subprocess
import tarfile
from contextlib import contextmanager
from pathlib import Path
from typing import TYPE_CHECKING

from pydantic import BaseModel, ConfigDict

from .._build.manifest import BuildManifest, load_manifest, save_manifest
from .._build.recipes import recipe_digest
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
from .errors import DistError
from .oci import MEDIA_TYPE_INDEX, Descriptor, OciIndex, OciLayout, OciManifest

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

    range_name: str
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


def _qcow2_backing_name(path: Path) -> str | None:
    """The qcow2 header's embedded backing reference (relative file name), via qemu-img."""
    result = subprocess.run(
        ["qemu-img", "info", "--output=json", str(path)],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise DistError(
            "chain-invalid",
            f"qemu-img could not read {path.name}: {result.stderr.strip()[:200]}",
        )
    info = json.loads(result.stdout)
    backing = info.get("backing-filename")
    return str(backing) if backing is not None else None


def _land_image(
    layout: OciLayout,
    manifest: OciManifest,
    image_cache: Path,
    *,
    sidecar_suffix: str | None,
    sidecar_first: bool,
    fetched: list[str],
    present: list[str],
) -> None:
    """Land one image artifact (and its sidecar) under the cache's lock and write-order conventions."""
    name = _annotation(manifest, ANN_NAME)
    if "/" in name or name.startswith("."):
        raise DistError("manifest-invalid", f"{name!r} is not a cache file name")
    blob = _layer(manifest, LAYER_QCOW2)
    target = image_cache / name
    with _name_lock(image_cache, name):
        if target.is_file():
            hasher = hashlib.sha256()
            with target.open("rb") as handle:
                for chunk in iter(lambda: handle.read(1 << 20), b""):
                    hasher.update(chunk)
            if f"sha256:{hasher.hexdigest()}" == blob.digest:
                present.append(name)
                return
            raise DistError(
                "cache-name-conflict",
                f"{target} already holds different content than {blob.digest}; the flat cache holds one meaning per name (prune or rename the local file, then pull again)",
            )

        def write_sidecar() -> None:
            if sidecar_suffix is None:
                return
            sidecar = _layer(manifest, LAYER_SIDECAR)
            data = layout.read_blob(sidecar)
            sidecar_path = image_cache / (name.removesuffix(".qcow2") + sidecar_suffix)
            sidecar_path.write_bytes(data)
            fetched.append(sidecar_path.name)

        if sidecar_first:
            write_sidecar()
            layout.copy_blob_to(blob, target)
        else:
            layout.copy_blob_to(blob, target)
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
    layout: OciLayout,
    root: Descriptor,
    *,
    image_cache: Path,
    build_cache: Path,
    recipe_cache: Path,
) -> MaterializeResult:
    """Materialize a pull root's closure into the local caches, verified end to end; returns what was fetched versus already present.

    Raises:
        DistError: missing or corrupt blobs, invalid manifests, cache name conflicts, broken backing chains, or recipe bundles whose extracted content does not reproduce the recorded recipe digest. On refusal the build manifest has NOT landed, so nothing consumable dangles.
    """
    if root.media_type != MEDIA_TYPE_INDEX:
        raise DistError(
            "manifest-invalid",
            f"a pull root is an OCI index, not {root.media_type}",
        )
    index = OciIndex.model_validate_json(layout.read_blob(root))
    artifacts: dict[str, list[OciManifest]] = {kind: [] for kind in _KIND_ORDER}
    for member in index.manifests:
        manifest = layout.manifest(member)
        if manifest.artifact_type not in artifacts:
            raise DistError(
                "manifest-invalid",
                f"unknown artifact type {manifest.artifact_type!r} in the closure",
            )
        artifacts[manifest.artifact_type].append(manifest)
    builds = artifacts[ARTIFACT_BUILD_MANIFEST]
    if len(builds) != 1:
        raise DistError(
            "manifest-invalid",
            f"a pull root carries exactly one build manifest; this one carries {len(builds)}",
        )

    fetched: list[str] = []
    present: list[str] = []
    landed_digests: dict[str, str] = {}

    for manifest in artifacts[ARTIFACT_VENDOR_BASE]:
        _land_image(
            layout,
            manifest,
            image_cache,
            sidecar_suffix=None,
            sidecar_first=False,
            fetched=fetched,
            present=present,
        )
        landed_digests[_annotation(manifest, ANN_NAME)] = _layer(
            manifest, LAYER_QCOW2
        ).digest
    for manifest in artifacts[ARTIFACT_GOLDEN]:
        _land_image(
            layout,
            manifest,
            image_cache,
            sidecar_suffix=".json",
            sidecar_first=True,
            fetched=fetched,
            present=present,
        )
        landed_digests[_annotation(manifest, ANN_NAME)] = _layer(
            manifest, LAYER_QCOW2
        ).digest
        _validate_chain(manifest, image_cache, landed_digests)
    for manifest in artifacts[ARTIFACT_REALIZED]:
        _land_image(
            layout,
            manifest,
            image_cache,
            sidecar_suffix=".realized.json",
            sidecar_first=False,
            fetched=fetched,
            present=present,
        )
        landed_digests[_annotation(manifest, ANN_NAME)] = _layer(
            manifest, LAYER_QCOW2
        ).digest
        _validate_chain(manifest, image_cache, landed_digests)

    for manifest in artifacts[ARTIFACT_RECIPE_BUNDLE]:
        _land_recipe(layout, manifest, recipe_cache, fetched=fetched, present=present)

    build = builds[0]
    manifest_bytes = layout.read_blob(_layer(build, LAYER_BUILD_MANIFEST))
    try:
        build_manifest = BuildManifest.model_validate_json(manifest_bytes)
    except ValueError as error:
        raise DistError(
            "manifest-invalid", f"the pulled build manifest does not parse: {error}"
        ) from error
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


def _land_recipe(
    layout: OciLayout,
    manifest: OciManifest,
    recipe_cache: Path,
    *,
    fetched: list[str],
    present: list[str],
) -> None:
    """Extract a recipe bundle into the flat name-keyed recipe cache; the recorded recipe digest must reproduce from the extracted tree."""
    name = _annotation(manifest, ANN_NAME)
    declared = _annotation(manifest, ANN_RECIPE_DIGEST)
    if "/" in name or name.startswith("."):
        raise DistError("manifest-invalid", f"{name!r} is not a recipe name")
    target = recipe_cache / name
    if target.is_dir():
        existing = recipe_digest(target)
        if existing == declared:
            present.append(f"recipes/{name}")
            return
        raise DistError(
            "cache-name-conflict",
            f"recipe cache already holds {name!r} at digest {existing[:12]}, not {declared[:12]}; remove it to pull this bundle",
        )
    data = layout.read_blob(_layer(manifest, LAYER_RECIPE_TAR))
    staging = recipe_cache / f".{name}.pulling"
    if staging.exists():
        _rmtree(staging)
    staging.mkdir(parents=True)
    try:
        with tarfile.open(fileobj=io.BytesIO(data)) as tar:
            for member in tar.getmembers():
                if not member.isfile() or member.name.startswith(("/", "..")):
                    raise DistError(
                        "recipe-bundle-invalid",
                        f"bundle member {member.name!r} is not a safe regular file",
                    )
            tar.extractall(staging, filter="data")
        extracted = recipe_digest(staging)
        if extracted != declared:
            raise DistError(
                "blob-digest-mismatch",
                f"recipe {name!r} extracted to digest {extracted[:12]}, expected {declared[:12]}",
            )
        recipe_cache.mkdir(parents=True, exist_ok=True)
        staging.rename(target)
        fetched.append(f"recipes/{name}")
    finally:
        if staging.exists():
            _rmtree(staging)


def _rmtree(path: Path) -> None:
    shutil.rmtree(path, ignore_errors=True)

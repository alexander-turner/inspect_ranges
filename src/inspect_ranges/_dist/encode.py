"""Encoding built artifacts into OCI form: the push side of distribution-v1 slice 1.

The pull root is an OCI index listing one artifact manifest per closure member, so mirroring the root mirrors the whole range by construction (spine Q3: a manifest always carries its transitive references). Each artifact manifest is an OCI artifact (`artifactType` names the inspect-ranges kind) whose layers are the artifact's canonical bytes exactly as they live in the local caches: qcow2 blobs travel uncompressed so a blob's digest IS its cache-file identity (dedup against the local cache needs no recompression or re-hash), sidecars travel verbatim, recipe bundles travel as a deterministic tar, and the build manifest travels as its exact on-disk bytes (its content digest is the published identity Journey B prints).

Backing relationships are pinned by digest in annotations (image-distribution.md): a golden names its vendor base, a realized image names its golden, and materialization refuses a chain whose annotations and landed bytes disagree. Every blob put verifies against the digest the build manifest or sidecar recorded, so a corrupt cache refuses at push rather than publishing bytes nothing verified.
"""

import io
import json
import subprocess
import tarfile
from pathlib import Path

from .._build.manifest import BuildManifest, manifest_path
from .._build.recipes import ResolvedRecipe, resolve_recipe
from .._compiler.plan import image_file_name
from .._runtime.images import ImageMetadata
from .errors import DistError
from .oci import ContentStore, Descriptor, OciIndex, OciManifest

__all__ = [
    "ANN_BACKING_DIGEST",
    "ANN_BACKING_FILE",
    "ANN_BUILT_AT",
    "ANN_GUEST",
    "ANN_KIND",
    "ANN_NAME",
    "ANN_RANGE",
    "ANN_RECIPE_DIGEST",
    "ANN_RECIPE_VERSION",
    "ANN_SPEC_SHA256",
    "ARTIFACT_BUILD_MANIFEST",
    "ARTIFACT_GOLDEN",
    "ARTIFACT_REALIZED",
    "ARTIFACT_RECIPE_BUNDLE",
    "ARTIFACT_VENDOR_BASE",
    "LAYER_BUILD_MANIFEST",
    "LAYER_QCOW2",
    "LAYER_RECIPE_TAR",
    "LAYER_SIDECAR",
    "push_build",
    "qcow2_backing_name",
    "recipe_bundle_tar",
]


ARTIFACT_VENDOR_BASE = "application/vnd.inspect-ranges.vendor-base.v1"
ARTIFACT_GOLDEN = "application/vnd.inspect-ranges.golden.v1"
ARTIFACT_REALIZED = "application/vnd.inspect-ranges.realized-image.v1"
ARTIFACT_RECIPE_BUNDLE = "application/vnd.inspect-ranges.recipe-bundle.v1"
ARTIFACT_BUILD_MANIFEST = "application/vnd.inspect-ranges.build-manifest.v1"

LAYER_QCOW2 = "application/vnd.inspect-ranges.qcow2.v1"
"""Uncompressed qcow2 bytes: the blob digest equals the cache file's sha256, which is the identity every manifest and sidecar already records."""

LAYER_SIDECAR = "application/vnd.inspect-ranges.sidecar.v1+json"
LAYER_RECIPE_TAR = "application/vnd.inspect-ranges.recipe-bundle.v1.tar"
LAYER_BUILD_MANIFEST = "application/vnd.inspect-ranges.build-manifest.v1+json"

ANN_KIND = "org.inspect-ranges.kind"
ANN_NAME = "org.inspect-ranges.name"
ANN_GUEST = "org.inspect-ranges.guest"
ANN_BACKING_FILE = "org.inspect-ranges.backing.file"
ANN_BACKING_DIGEST = "org.inspect-ranges.backing.digest"
ANN_RECIPE_VERSION = "org.inspect-ranges.recipe.version"
ANN_RECIPE_DIGEST = "org.inspect-ranges.recipe.digest"
"""The recipe-references identity (`recipe-digest-1`, over relative paths, content, and exec bits), distinct from the tar layer's blob digest; materialization recomputes it after extraction and refuses a mismatch."""
ANN_RANGE = "org.inspect-ranges.range"
ANN_SPEC_SHA256 = "org.inspect-ranges.spec-sha256"
ANN_BUILT_AT = "org.inspect-ranges.built-at"


def qcow2_backing_name(path: Path) -> str | None:
    """The qcow2 header's embedded backing reference (a relative file name), via host qemu-img; `None` for raw images and chainless qcow2s.

    Raises:
        DistError: `chain-invalid` when qemu-img cannot read the file.
    """
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
    backing = json.loads(result.stdout).get("backing-filename")
    return str(backing) if backing is not None else None


def _prefixed(digest: str) -> str:
    """Normalize the repo's two digest spellings (raw hex and `sha256:`-prefixed) to the OCI form."""
    return digest if digest.startswith("sha256:") else f"sha256:{digest}"


def _metadata_path(image_cache: Path, file: str) -> Path:
    # the image cache's sidecar rule: full name minus .qcow2 (names may contain dots)
    return image_cache / (file.removesuffix(".qcow2") + ".json")


def _realized_sidecar_path(image_cache: Path, file: str) -> Path:
    return image_cache / (file.removesuffix(".qcow2") + ".realized.json")


def _qcow2_descriptor(
    store: ContentStore, path: Path, *, expected: str | None
) -> Descriptor:
    if not path.is_file():
        raise DistError("artifact-missing", f"{path} is not in the image cache")
    digest = store.put_blob_file(path, expected=expected)
    return Descriptor(media_type=LAYER_QCOW2, digest=digest, size=path.stat().st_size)


def _sidecar_descriptor(store: ContentStore, path: Path) -> Descriptor:
    data = path.read_bytes()
    digest = store.put_blob_bytes(data)
    return Descriptor(media_type=LAYER_SIDECAR, digest=digest, size=len(data))


def recipe_bundle_tar(recipe: ResolvedRecipe) -> bytes:
    """A recipe bundle as a deterministic uncompressed USTAR: sorted members, zeroed times and ownership, modes normalized to the exec bit (the daemon bundle's discipline), so identical bundle content always yields identical bytes."""
    buffer = io.BytesIO()
    files = sorted(path for path in recipe.bundle_dir.rglob("*") if not path.is_dir())
    with tarfile.open(fileobj=buffer, mode="w", format=tarfile.USTAR_FORMAT) as tar:
        for path in files:
            if not path.is_file() or path.is_symlink():
                raise DistError(
                    "recipe-bundle-invalid",
                    f"{path} is not a regular file; recipe bundles carry only regular files",
                )
            info = tarfile.TarInfo(path.relative_to(recipe.bundle_dir).as_posix())
            info.size = path.stat().st_size
            info.mtime = 0
            info.uid = info.gid = 0
            info.uname = info.gname = ""
            info.mode = 0o755 if path.stat().st_mode & 0o111 else 0o644
            with path.open("rb") as handle:
                tar.addfile(info, handle)
    return buffer.getvalue()


def push_build(
    manifest: BuildManifest,
    store: ContentStore,
    *,
    image_cache: Path,
    build_cache: Path,
    range_dir: Path | None = None,
    recipe_cache: Path | None = None,
) -> Descriptor:
    """Encode a built range's transitive closure into `store` and return the root index descriptor (the publishable identity).

    The closure: every base image's golden chain (golden plus its vendor base, read from the golden's provenance sidecar), every content guest's realized image with its sidecar, every referenced recipe bundle (resolved exactly as the build resolves them and required to match the manifest's recorded digest), and the build manifest itself as the pull root's entry point. Blobs the store already holds are not rewritten (dedup by digest). The index is also named in the store under the range name.

    Raises:
        DistError: `artifact-missing` when a closure member is absent from its cache, `blob-digest-mismatch` when cache bytes disagree with the recorded digest, `recipe-closure-broken` when a recorded recipe no longer resolves or resolves at a different digest.
    """
    config = store.ensure_empty_config()
    members: list[Descriptor] = []
    seen: set[str] = set()

    def add(manifest_descriptor: Descriptor) -> None:
        if manifest_descriptor.digest not in seen:
            seen.add(manifest_descriptor.digest)
            members.append(manifest_descriptor)

    def encode_golden_chain(file: str, digest: str | None) -> None:
        """A golden with its vendor base; a file with no provenance sidecar encodes as a bare vendor base."""
        metadata_path = _metadata_path(image_cache, file)
        if not metadata_path.is_file():
            # closed-world check: a sidecar-less image publishes as a bare
            # vendor base, which never joins a validated chain, so an embedded
            # backing here would publish a chain that cannot boot (round-1 N6)
            if file.endswith(".qcow2") and qcow2_backing_name(image_cache / file):
                raise DistError(
                    "chain-invalid",
                    f"{file} embeds a backing file but has no provenance sidecar; it cannot publish as a vendor base",
                )
            blob = _qcow2_descriptor(store, image_cache / file, expected=digest)
            add(
                store.put_manifest(
                    OciManifest(
                        artifact_type=ARTIFACT_VENDOR_BASE,
                        config=config,
                        layers=[blob],
                        annotations={ANN_KIND: "vendor-base", ANN_NAME: file},
                    )
                )
            )
            return
        try:
            metadata = ImageMetadata.model_validate_json(metadata_path.read_text())
        except ValueError as error:
            raise DistError(
                "artifact-missing",
                f"{metadata_path} is not a valid golden sidecar: {error}",
            ) from error
        vendor_path = image_cache / metadata.vendor_file
        vendor_blob = _qcow2_descriptor(
            store, vendor_path, expected=_prefixed(metadata.vendor_sha256)
        )
        add(
            store.put_manifest(
                OciManifest(
                    artifact_type=ARTIFACT_VENDOR_BASE,
                    config=config,
                    layers=[vendor_blob],
                    annotations={
                        ANN_KIND: "vendor-base",
                        ANN_NAME: metadata.vendor_file,
                    },
                )
            )
        )
        golden_blob = _qcow2_descriptor(
            store,
            image_cache / file,
            expected=_prefixed(digest or metadata.golden_sha256),
        )
        add(
            store.put_manifest(
                OciManifest(
                    artifact_type=ARTIFACT_GOLDEN,
                    config=config,
                    layers=[
                        golden_blob,
                        _sidecar_descriptor(store, metadata_path),
                    ],
                    annotations={
                        ANN_KIND: "golden",
                        ANN_NAME: file,
                        ANN_BACKING_FILE: metadata.vendor_file,
                        ANN_BACKING_DIGEST: _prefixed(metadata.vendor_sha256),
                    },
                )
            )
        )

    for base in manifest.base_images:
        encode_golden_chain(base.file, base.digest or None)

    for guest in manifest.guests:
        golden_file = image_file_name(guest.golden_reference)
        encode_golden_chain(golden_file, guest.golden_digest)
        realized_path = image_cache / guest.realized_file
        sidecar_path = _realized_sidecar_path(image_cache, guest.realized_file)
        if not sidecar_path.is_file():
            raise DistError(
                "artifact-missing",
                f"{sidecar_path} is missing; a realized image publishes with its provenance sidecar",
            )
        realized_blob = _qcow2_descriptor(
            store, realized_path, expected=_prefixed(guest.realized_sha256)
        )
        add(
            store.put_manifest(
                OciManifest(
                    artifact_type=ARTIFACT_REALIZED,
                    config=config,
                    layers=[
                        realized_blob,
                        _sidecar_descriptor(store, sidecar_path),
                    ],
                    annotations={
                        ANN_KIND: "realized-image",
                        ANN_NAME: guest.realized_file,
                        ANN_GUEST: guest.name,
                        ANN_BACKING_FILE: golden_file,
                        ANN_BACKING_DIGEST: _prefixed(guest.golden_digest),
                    },
                )
            )
        )

    triples = {
        (record.name, record.version, record.digest)
        for guest in manifest.guests
        for record in guest.recipes
    }
    for name, version, digest in sorted(triples):
        if range_dir is None:
            raise DistError(
                "recipe-closure-broken",
                f"the manifest records recipe {name!r} but no range directory was given to resolve it from",
            )
        try:
            recipe = resolve_recipe(
                name, range_dir=range_dir, cache=recipe_cache, version=version
            )
        except Exception as error:
            raise DistError(
                "recipe-closure-broken",
                f"recipe {name!r} ({version}) no longer resolves: {error}",
            ) from error
        if recipe.digest != digest:
            raise DistError(
                "recipe-closure-broken",
                f"recipe {name!r} resolves at digest {recipe.digest[:12]} but the manifest recorded {digest[:12]}; the bundle changed since the build",
            )
        tar_bytes = recipe_bundle_tar(recipe)
        tar_digest = store.put_blob_bytes(tar_bytes)
        add(
            store.put_manifest(
                OciManifest(
                    artifact_type=ARTIFACT_RECIPE_BUNDLE,
                    config=config,
                    layers=[
                        Descriptor(
                            media_type=LAYER_RECIPE_TAR,
                            digest=tar_digest,
                            size=len(tar_bytes),
                        )
                    ],
                    annotations={
                        ANN_KIND: "recipe-bundle",
                        ANN_NAME: name,
                        ANN_RECIPE_VERSION: version,
                        ANN_RECIPE_DIGEST: digest,
                    },
                )
            )
        )

    manifest_file = manifest_path(build_cache, manifest.range_name)
    if not manifest_file.is_file():
        raise DistError(
            "artifact-missing", f"{manifest_file} is not in the builds cache"
        )
    manifest_bytes = manifest_file.read_bytes()
    on_disk = BuildManifest.model_validate_json(manifest_bytes)
    if (on_disk.spec_sha256, on_disk.built_at) != (
        manifest.spec_sha256,
        manifest.built_at,
    ):
        raise DistError(
            "manifest-changed",
            f"{manifest_file} changed since it was loaded (a concurrent rebuild?); re-run the push",
        )
    manifest_digest = store.put_blob_bytes(manifest_bytes)
    add(
        store.put_manifest(
            OciManifest(
                artifact_type=ARTIFACT_BUILD_MANIFEST,
                config=config,
                layers=[
                    Descriptor(
                        media_type=LAYER_BUILD_MANIFEST,
                        digest=manifest_digest,
                        size=len(manifest_bytes),
                    )
                ],
                annotations={
                    ANN_KIND: "build-manifest",
                    ANN_RANGE: manifest.range_name,
                    ANN_SPEC_SHA256: manifest.spec_sha256,
                    ANN_BUILT_AT: manifest.built_at,
                },
            )
        )
    )

    index = OciIndex(
        manifests=members,
        annotations={
            ANN_RANGE: manifest.range_name,
            ANN_SPEC_SHA256: manifest.spec_sha256,
            ANN_BUILT_AT: manifest.built_at,
        },
    )
    return store.put_index(manifest.range_name, index)

"""OCI primitives: descriptors, manifests, and the image-layout directory with its content-addressed blob store.

This module is deliberately artifact-agnostic: it implements the OCI image-spec structures (descriptor, manifest, index) and the plain image-layout directory form, which is the registry-less shape every location ultimately shares (a registry is the same content model behind an HTTP protocol; the directory is the same content model on disk). The inspect-ranges artifact kinds and their media types live in `encode.py`; nothing here knows what a golden is.

Integrity contract (image-distribution.md): blobs are canonical bytes addressed by sha256 and are never edited after write; writes land under temporary names and move in atomically, so concurrent writers converge by digest and a partial write is never observable under a blob path; every read path verifies the digest before the caller sees the content (small blobs by hashing in memory, large blobs by streaming verification on copy).
"""

import fcntl
import hashlib
import json
import os
import re
import tempfile
from collections.abc import Iterator
from pathlib import Path
from typing import Any, Protocol

from pydantic import BaseModel, ConfigDict, Field

from .errors import DistError

__all__ = [
    "DIGEST_PATTERN",
    "MEDIA_TYPE_EMPTY",
    "MEDIA_TYPE_INDEX",
    "MEDIA_TYPE_MANIFEST",
    "OCI_LAYOUT_VERSION",
    "REF_NAME_ANNOTATION",
    "ContentStore",
    "Descriptor",
    "OciIndex",
    "OciLayout",
    "OciManifest",
    "atomic_write",
    "blob_sha256",
]


MEDIA_TYPE_MANIFEST = "application/vnd.oci.image.manifest.v1+json"
"""The OCI image manifest media type; inspect-ranges artifacts are OCI artifacts (an `artifactType` plus typed layers) carried in this envelope, the shape registries accept uniformly."""

MEDIA_TYPE_INDEX = "application/vnd.oci.image.index.v1+json"
"""The OCI image index media type (the layout's `index.json` and any multi-manifest grouping)."""

MEDIA_TYPE_EMPTY = "application/vnd.oci.empty.v1+json"
"""The OCI empty descriptor media type: the `config` slot of a pure artifact manifest points at the canonical 2-byte `{}` blob, per the image-spec artifact guidance."""

EMPTY_BLOB = b"{}"
"""The canonical empty-config blob the spec pairs with `MEDIA_TYPE_EMPTY`."""

OCI_LAYOUT_VERSION = "1.0.0"
"""The `imageLayoutVersion` this module writes and accepts."""

REF_NAME_ANNOTATION = "org.opencontainers.image.ref.name"
"""The standard annotation naming a manifest inside an index (the layout's tag equivalent)."""

DIGEST_PATTERN = re.compile(r"\Asha256:[0-9a-f]{64}\Z")
"""The one digest algorithm this layer speaks; anything else refuses rather than silently passing unverified."""

_BLOB_CHUNK = 1 << 20


def blob_sha256(path: Path) -> str:
    """The `sha256:<hex>` digest of a file's bytes, streamed."""
    hasher = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(_BLOB_CHUNK), b""):
            hasher.update(chunk)
    return f"sha256:{hasher.hexdigest()}"


class Descriptor(BaseModel):
    """An OCI content descriptor: the typed, sized, digest-pinned reference every edge in the content graph uses."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    media_type: str = Field(
        validation_alias="mediaType", serialization_alias="mediaType"
    )
    digest: str
    size: int = Field(ge=0)
    annotations: dict[str, str] | None = None
    artifact_type: str | None = Field(
        default=None,
        validation_alias="artifactType",
        serialization_alias="artifactType",
    )

    def require_sha256(self) -> str:
        """The digest, validated against the supported grammar.

        Raises:
            DistError: `unsupported-digest` for anything but lowercase `sha256:<64 hex>`.
        """
        if DIGEST_PATTERN.fullmatch(self.digest) is None:
            raise DistError(
                "unsupported-digest",
                f"descriptor digest {self.digest!r} is not a sha256 digest",
            )
        return self.digest


class OciManifest(BaseModel):
    """An OCI image manifest in artifact form: `artifactType` names the inspect-ranges kind, `layers` carry the content, `annotations` carry the kind's metadata."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    schema_version: int = Field(
        default=2, validation_alias="schemaVersion", serialization_alias="schemaVersion"
    )
    media_type: str = Field(
        default=MEDIA_TYPE_MANIFEST,
        validation_alias="mediaType",
        serialization_alias="mediaType",
    )
    artifact_type: str | None = Field(
        default=None,
        validation_alias="artifactType",
        serialization_alias="artifactType",
    )
    config: Descriptor
    layers: list[Descriptor]
    annotations: dict[str, str] | None = None

    def canonical_bytes(self) -> bytes:
        """The manifest's serialized form, which is what its digest addresses.

        Stable by construction rather than by canonicalization: a manifest is serialized exactly once, at creation, and the bytes are content-addressed from then on; re-serialization never has to reproduce them.
        """
        return self.model_dump_json(by_alias=True, exclude_none=True).encode()


class OciIndex(BaseModel):
    """An OCI image index: the layout's entry point, one descriptor per referenced manifest, named by `REF_NAME_ANNOTATION`."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    schema_version: int = Field(
        default=2, validation_alias="schemaVersion", serialization_alias="schemaVersion"
    )
    media_type: str = Field(
        default=MEDIA_TYPE_INDEX,
        validation_alias="mediaType",
        serialization_alias="mediaType",
    )
    manifests: list[Descriptor] = Field(default_factory=list[Descriptor])
    annotations: dict[str, str] | None = None

    def canonical_bytes(self) -> bytes:
        """Serialized form (see `OciManifest.canonical_bytes`)."""
        return self.model_dump_json(by_alias=True, exclude_none=True).encode()


class OciLayout:
    """A plain OCI image-layout directory: `oci-layout`, `index.json`, and `blobs/sha256/<hex>`.

    This is the registry-less location form: tar it, ship it, untar it, and every blob still verifies because identity is content, not transport. The same class serves push targets, pull sources, and mirror endpoints.
    """

    def __init__(self, root: Path) -> None:
        self.root = root

    # -- creation and validation -------------------------------------------------

    def ensure(self) -> "OciLayout":
        """Create the layout skeleton if absent; validate the version marker if present.

        Raises:
            DistError: `layout-invalid` when the directory exists but is not a compatible OCI layout.
        """
        marker = self.root / "oci-layout"
        if marker.exists():
            self._check_marker(marker)
        else:
            (self.root / "blobs" / "sha256").mkdir(parents=True, exist_ok=True)
            atomic_write(
                marker, json.dumps({"imageLayoutVersion": OCI_LAYOUT_VERSION}).encode()
            )
        if not (self.root / "index.json").exists():
            atomic_write(self.root / "index.json", OciIndex().canonical_bytes())
        blobs = self.root / "blobs" / "sha256"
        blobs.mkdir(parents=True, exist_ok=True)
        # a hard-killed writer strands randomly-named temps nothing else would
        # ever reclaim; blobs land atomically, so anything matching the temp
        # prefix is debris by definition
        for stale in blobs.glob(".incoming-*"):
            stale.unlink(missing_ok=True)
        return self

    def open(self) -> "OciLayout":
        """Open an existing layout for reading.

        Raises:
            DistError: `layout-invalid` when the marker or index is missing or malformed.
        """
        marker = self.root / "oci-layout"
        if not marker.is_file():
            raise DistError(
                "layout-invalid",
                f"{self.root} is not an OCI image layout (no oci-layout marker)",
            )
        self._check_marker(marker)
        self.index()
        return self

    def _check_marker(self, marker: Path) -> None:
        try:
            version = json.loads(marker.read_text())["imageLayoutVersion"]
        except (ValueError, KeyError) as error:
            raise DistError(
                "layout-invalid", f"{marker} is not a valid oci-layout marker: {error}"
            ) from error
        if not str(version).startswith("1."):
            raise DistError(
                "layout-invalid",
                f"{marker} declares imageLayoutVersion {version!r}; this client speaks 1.x",
            )

    # -- the index ----------------------------------------------------------------

    def index(self) -> OciIndex:
        """The layout's index.

        Raises:
            DistError: `layout-invalid` when index.json is missing or malformed.
        """
        path = self.root / "index.json"
        try:
            return OciIndex.model_validate_json(path.read_text())
        except (OSError, ValueError) as error:
            raise DistError(
                "layout-invalid", f"{path} is not a valid OCI index: {error}"
            ) from error

    def set_ref(self, name: str, descriptor: Descriptor) -> None:
        """Point `name` at `descriptor` in the index (replacing an existing entry of the same name).

        The read-modify-write runs under the layout's `.index.lock`, so concurrent pushes into one layout never drop each other's refs (slice-5 mirror relies on this).
        """
        with open(self.root / ".index.lock", "w") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            try:
                self._set_ref_locked(name, descriptor)
            finally:
                fcntl.flock(lock, fcntl.LOCK_UN)

    def _set_ref_locked(self, name: str, descriptor: Descriptor) -> None:
        index = self.index()
        annotations = dict(descriptor.annotations or {})
        annotations[REF_NAME_ANNOTATION] = name
        entry = descriptor.model_copy(update={"annotations": annotations})
        kept = [
            manifest
            for manifest in index.manifests
            if (manifest.annotations or {}).get(REF_NAME_ANNOTATION) != name
        ]
        index.manifests = [*kept, entry]
        atomic_write(self.root / "index.json", index.canonical_bytes())

    def ref(self, name: str) -> Descriptor:
        """The index entry named `name`.

        Raises:
            DistError: `ref-not-found` when no entry carries the name.
        """
        for manifest in self.index().manifests:
            if (manifest.annotations or {}).get(REF_NAME_ANNOTATION) == name:
                return manifest
        raise DistError("ref-not-found", f"{self.root} has no reference named {name!r}")

    # -- blobs --------------------------------------------------------------------

    def blob_path(self, digest: str) -> Path:
        """The path a digest's blob lives at (whether or not it exists)."""
        if DIGEST_PATTERN.fullmatch(digest) is None:
            raise DistError("unsupported-digest", f"{digest!r} is not a sha256 digest")
        return self.root / "blobs" / "sha256" / digest.removeprefix("sha256:")

    def has_blob(self, digest: str) -> bool:
        """Whether the blob is present (presence only; reads verify)."""
        return self.blob_path(digest).is_file()

    def put_blob_bytes(self, data: bytes) -> str:
        """Store small content (manifests, metadata) as a blob; returns its digest."""
        digest = f"sha256:{hashlib.sha256(data).hexdigest()}"
        target = self.blob_path(digest)
        if not target.exists():
            atomic_write(target, data)
        return digest

    def put_blob_file(self, source: Path, *, expected: str | None = None) -> str:
        """Store a file as a blob, streaming and hashing in one pass; returns its digest.

        With `expected`, the copy refuses on mismatch and nothing lands under the blob path (verify-while-copy: a corrupt source is caught before it is ever addressable). Without it, the digest is computed and trusted as the content's identity, which is only correct for content this process produced or already verified.

        Raises:
            DistError: `blob-digest-mismatch` when `expected` is given and the bytes disagree.
        """
        if expected is not None and DIGEST_PATTERN.fullmatch(expected) is None:
            raise DistError(
                "unsupported-digest", f"{expected!r} is not a sha256 digest"
            )
        if expected is not None and self.has_blob(expected):
            return expected
        blobs = self.root / "blobs" / "sha256"
        blobs.mkdir(parents=True, exist_ok=True)
        hasher = hashlib.sha256()
        fd, temp_name = tempfile.mkstemp(dir=blobs, prefix=".incoming-")
        temp = Path(temp_name)
        try:
            with os.fdopen(fd, "wb") as out, source.open("rb") as handle:
                for chunk in iter(lambda: handle.read(_BLOB_CHUNK), b""):
                    hasher.update(chunk)
                    out.write(chunk)
            digest = f"sha256:{hasher.hexdigest()}"
            if expected is not None and digest != expected:
                raise DistError(
                    "blob-digest-mismatch",
                    f"{source} hashed to {digest}, expected {expected}",
                )
            target = self.blob_path(digest)
            if target.exists():
                temp.unlink()
            else:
                temp.chmod(0o644)
                os.replace(temp, target)
            return digest
        finally:
            temp.unlink(missing_ok=True)

    def read_blob(
        self, descriptor: Descriptor, *, cap: int = 64 * 1024 * 1024
    ) -> bytes:
        """A blob's verified bytes (for manifests and metadata, never multi-GB content).

        Raises:
            DistError: `missing-blob`, `blob-digest-mismatch`, or `blob-too-large` past `cap`.
        """
        digest = descriptor.require_sha256()
        path = self.blob_path(digest)
        if not path.is_file():
            raise DistError("missing-blob", f"{self.root} has no blob {digest}")
        if path.stat().st_size > cap:
            raise DistError(
                "blob-too-large",
                f"blob {digest} is {path.stat().st_size} bytes; in-memory reads cap at {cap}",
            )
        data = path.read_bytes()
        actual = f"sha256:{hashlib.sha256(data).hexdigest()}"
        if actual != digest:
            raise DistError(
                "blob-digest-mismatch", f"blob {digest} reads back as {actual}"
            )
        return data

    def copy_blob_to(
        self,
        descriptor: Descriptor,
        destination: Path,
        *,
        temp_prefix: str | None = None,
    ) -> None:
        """Stream a blob to `destination` with verify-while-copy; the file appears atomically.

        `temp_prefix` names the in-flight temp (default `.incoming-`); callers landing into a shared cache pass a per-name prefix so a crash's debris is attributable and reclaimable by the next attempt on that name.

        Raises:
            DistError: `missing-blob` or `blob-digest-mismatch` (nothing lands at `destination` on failure).
        """
        digest = descriptor.require_sha256()
        source = self.blob_path(digest)
        if not source.is_file():
            raise DistError("missing-blob", f"{self.root} has no blob {digest}")
        destination.parent.mkdir(parents=True, exist_ok=True)
        hasher = hashlib.sha256()
        fd, temp_name = tempfile.mkstemp(
            dir=destination.parent, prefix=temp_prefix or ".incoming-"
        )
        temp = Path(temp_name)
        try:
            with os.fdopen(fd, "wb") as out, source.open("rb") as handle:
                for chunk in iter(lambda: handle.read(_BLOB_CHUNK), b""):
                    hasher.update(chunk)
                    out.write(chunk)
            actual = f"sha256:{hasher.hexdigest()}"
            if actual != digest:
                raise DistError(
                    "blob-digest-mismatch", f"blob {digest} reads back as {actual}"
                )
            temp.chmod(0o644)
            os.replace(temp, destination)
        finally:
            temp.unlink(missing_ok=True)

    # -- manifests ----------------------------------------------------------------

    def put_manifest(self, manifest: OciManifest) -> Descriptor:
        """Store a manifest as a blob and return its descriptor (not yet named in the index)."""
        data = manifest.canonical_bytes()
        digest = self.put_blob_bytes(data)
        return Descriptor(
            media_type=manifest.media_type,
            digest=digest,
            size=len(data),
            artifact_type=manifest.artifact_type,
        )

    def put_manifest_bytes(self, data: bytes, media_type: str) -> Descriptor:
        """Store manifest bytes VERBATIM (the transfer path: foreign manifests must keep their digests)."""
        digest = self.put_blob_bytes(data)
        return Descriptor(media_type=media_type, digest=digest, size=len(data))

    def manifest_bytes(self, descriptor: Descriptor) -> bytes:
        """A manifest's verified RAW bytes (the transfer path reads these, never a re-serialization)."""
        return self.read_blob(descriptor)

    def manifest(self, descriptor: Descriptor) -> OciManifest:
        """A manifest's verified, parsed content.

        Raises:
            DistError: blob errors, or `manifest-invalid` when the bytes do not parse as an OCI manifest.
        """
        data = self.read_blob(descriptor)
        try:
            return OciManifest.model_validate_json(data)
        except ValueError as error:
            raise DistError(
                "manifest-invalid",
                f"blob {descriptor.digest} is not a valid OCI manifest: {error}",
            ) from error

    def ensure_empty_config(self) -> Descriptor:
        """The canonical empty-config descriptor, with its blob present."""
        digest = self.put_blob_bytes(EMPTY_BLOB)
        return Descriptor(
            media_type=MEDIA_TYPE_EMPTY, digest=digest, size=len(EMPTY_BLOB)
        )

    # -- the index as a store surface (shared with registries) ---------------------

    def put_index_bytes(self, name: str, data: bytes) -> Descriptor:
        """Store index bytes VERBATIM and name them `name` (a layout stores a blob plus an index.json ref; a registry tags)."""
        digest = self.put_blob_bytes(data)
        descriptor = Descriptor(
            media_type=MEDIA_TYPE_INDEX, digest=digest, size=len(data)
        )
        self.set_ref(name, descriptor)
        return descriptor

    def put_index(self, name: str, index: OciIndex) -> Descriptor:
        """Store an index and name it `name`; returns its descriptor."""
        descriptor = self.put_index_bytes(name, index.canonical_bytes())
        annotated = descriptor.model_copy(
            update={"annotations": dict(index.annotations or {}) or None}
        )
        self.set_ref(name, annotated)
        return annotated

    def read_index(self, descriptor: Descriptor) -> OciIndex:
        """A named or digest-addressed index's verified, parsed content.

        Raises:
            DistError: blob errors, or `manifest-invalid` when the bytes do not parse as an OCI index.
        """
        data = self.read_blob(descriptor)
        try:
            return OciIndex.model_validate_json(data)
        except ValueError as error:
            raise DistError(
                "manifest-invalid",
                f"blob {descriptor.digest} is not a valid OCI index: {error}",
            ) from error

    # -- streaming (store-to-store transfer) ----------------------------------------

    def blob_chunks(self, descriptor: Descriptor) -> Iterator[bytes]:
        """A blob's bytes as a chunk stream (UNVERIFIED: the consumer verifies while writing; see `put_blob_stream`).

        Raises:
            DistError: `missing-blob`.
        """
        digest = descriptor.require_sha256()
        source = self.blob_path(digest)
        if not source.is_file():
            raise DistError("missing-blob", f"{self.root} has no blob {digest}")
        with source.open("rb") as handle:
            yield from iter(lambda: handle.read(_BLOB_CHUNK), b"")

    def put_blob_stream(
        self, chunks: Iterator[bytes], *, expected: str, size: int
    ) -> str:
        """Store a chunk stream as a blob with verify-while-write; nothing is addressable on mismatch.

        Raises:
            DistError: `blob-digest-mismatch` when the stream's bytes disagree with `expected`.
        """
        if DIGEST_PATTERN.fullmatch(expected) is None:
            raise DistError(
                "unsupported-digest", f"{expected!r} is not a sha256 digest"
            )
        if self.has_blob(expected):
            for _ in chunks:  # drain so the source can close cleanly
                pass
            return expected
        blobs = self.root / "blobs" / "sha256"
        blobs.mkdir(parents=True, exist_ok=True)
        hasher = hashlib.sha256()
        written = 0
        fd, temp_name = tempfile.mkstemp(dir=blobs, prefix=".incoming-")
        temp = Path(temp_name)
        try:
            with os.fdopen(fd, "wb") as out:
                for chunk in chunks:
                    hasher.update(chunk)
                    written += len(chunk)
                    out.write(chunk)
            digest = f"sha256:{hasher.hexdigest()}"
            if digest != expected or written != size:
                raise DistError(
                    "blob-digest-mismatch",
                    f"stream hashed to {digest} ({written} bytes), expected {expected} ({size} bytes)",
                )
            target = self.blob_path(digest)
            if target.exists():
                temp.unlink()
            else:
                temp.chmod(0o644)
                os.replace(temp, target)
            return digest
        finally:
            temp.unlink(missing_ok=True)


class ContentStore(Protocol):
    """The store surface push, materialize, and mirror run against: a location's three forms (layout directory, OCI registry, and later the hub) all implement it, so the transfer logic is written once.

    Semantics every implementation holds: blobs are content-addressed and immutable, writes are atomic and converge by digest, reads verify bytes against the descriptor before the caller sees them, and `put_index`/`ref` give a root a name without weakening digest addressing.
    """

    def has_blob(self, digest: str) -> bool: ...

    def put_blob_bytes(self, data: bytes) -> str: ...

    def put_blob_file(self, source: Path, *, expected: str | None = None) -> str: ...

    def read_blob(
        self, descriptor: Descriptor, *, cap: int = 64 * 1024 * 1024
    ) -> bytes: ...

    def copy_blob_to(
        self,
        descriptor: Descriptor,
        destination: Path,
        *,
        temp_prefix: str | None = None,
    ) -> None: ...

    def blob_chunks(self, descriptor: Descriptor) -> Iterator[bytes]: ...

    def put_blob_stream(
        self, chunks: Iterator[bytes], *, expected: str, size: int
    ) -> str: ...

    def put_manifest(self, manifest: OciManifest) -> Descriptor: ...

    def put_manifest_bytes(self, data: bytes, media_type: str) -> Descriptor: ...

    def manifest(self, descriptor: Descriptor) -> OciManifest: ...

    def manifest_bytes(self, descriptor: Descriptor) -> bytes: ...

    def ensure_empty_config(self) -> Descriptor: ...

    def put_index(self, name: str, index: OciIndex) -> Descriptor: ...

    def put_index_bytes(self, name: str, data: bytes) -> Descriptor: ...

    def read_index(self, descriptor: Descriptor) -> OciIndex: ...

    def ref(self, name: str) -> Descriptor: ...


def atomic_write(path: Path, data: bytes) -> None:
    """Write bytes with the cache discipline: temp in the same directory, atomic replace."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(dir=path.parent, prefix=".incoming-")
    temp = Path(temp_name)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
        temp.chmod(0o644)
        os.replace(temp, path)
    finally:
        temp.unlink(missing_ok=True)


def descriptor_for_bytes(
    data: bytes, media_type: str, *, annotations: dict[str, str] | None = None
) -> Descriptor:
    """A descriptor addressing `data` (helper for callers composing manifests)."""
    return Descriptor(
        media_type=media_type,
        digest=f"sha256:{hashlib.sha256(data).hexdigest()}",
        size=len(data),
        annotations=annotations,
    )


def validate_annotations(annotations: Any) -> dict[str, str]:
    """Narrow untrusted annotation content to `dict[str, str]` (registries and layouts are inputs)."""
    if not isinstance(annotations, dict):
        raise DistError("manifest-invalid", "annotations must be a string mapping")
    out: dict[str, str] = {}
    for key, value in annotations.items():  # pyright: ignore[reportUnknownVariableType]
        if not isinstance(key, str) or not isinstance(value, str):
            raise DistError("manifest-invalid", "annotations must be a string mapping")
        out[key] = value
    return out

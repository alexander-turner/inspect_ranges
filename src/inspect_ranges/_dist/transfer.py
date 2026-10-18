"""Store-to-store closure transfer: the engine under push-to-registry and mirror.

A closure copies by walking the root index: every member manifest, every layer and config blob, then the index itself, named at the destination. Blobs the destination already holds are skipped by digest (the structural dedup of content addressing), and every byte streams source to destination under verify-while-write, so a corrupt source refuses before anything lands addressable. The destination index lands LAST, so a named root at the destination always references a complete closure (the same manifest-lands-last invariant materialization holds for caches).
"""

from pydantic import BaseModel, ConfigDict

from .errors import DistError
from .oci import MEDIA_TYPE_INDEX, ContentStore, Descriptor

__all__ = ["TransferResult", "copy_closure"]


class TransferResult(BaseModel):
    """What a closure transfer did, for the caller's report."""

    model_config = ConfigDict(frozen=True)

    root: str
    """The root index digest at the destination (equal to the source's)."""

    copied: tuple[str, ...]
    """Blob digests this transfer moved."""

    present: tuple[str, ...]
    """Blob digests the destination already held (the `Already exists` lines)."""


def copy_closure(
    source: ContentStore,
    destination: ContentStore,
    root: Descriptor,
    *,
    name: str,
) -> TransferResult:
    """Copy a pull root's whole closure from `source` to `destination` and name it `name` there.

    Raises:
        DistError: unreadable or corrupt source content, or destination write failures; on refusal the destination has no `name` ref pointing at this root, so a partial transfer is never consumable by name.
    """
    if root.media_type != MEDIA_TYPE_INDEX:
        raise DistError(
            "manifest-invalid",
            f"a transfer root is an OCI index, not {root.media_type}",
        )
    index = source.read_index(root)
    copied: list[str] = []
    present: list[str] = []

    def move_blob(descriptor: Descriptor) -> None:
        digest = descriptor.require_sha256()
        if digest in copied or digest in present:
            return
        if destination.has_blob(digest):
            present.append(digest)
            return
        destination.put_blob_stream(
            source.blob_chunks(descriptor), expected=digest, size=descriptor.size
        )
        copied.append(digest)

    for member in index.manifests:
        manifest = source.manifest(member)
        move_blob(manifest.config)
        for layer in manifest.layers:
            move_blob(layer)
        destination.put_manifest(manifest)
    destination.put_index(name, index)
    return TransferResult(
        root=root.require_sha256(), copied=tuple(copied), present=tuple(present)
    )

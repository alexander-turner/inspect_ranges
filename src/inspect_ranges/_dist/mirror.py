"""The mirror verb's engine: seed or sync a whole location, or copy one range's closure, between any two location forms (Journey B's operator sessions).

Mirroring rides `copy_closure` (raw verified bytes, destination index named LAST), so a mirrored root is complete by construction and byte-identical to its source. A whole-location mirror copies EVERYTHING the source serves: every name, and for each name every published build's spec ref with its closure, not just the latest root (round-5 B3: a disconnected consumer holding an older spec must pull from the archive exactly what the source would have served). Enumeration: a layout lists its index refs; a registry lists `/v2/_catalog` under the location's prefix through the same bearer-auth flow as every other request, paginated. Docker Hub does not expose org enumeration through the OCI API, so whole-org mirroring FROM the hub refuses with a named cause and the per-name form remains (the catalog phase's published name list is the recorded follow-up; spine Q12).

An explicit root (the `name@sha256:` pin and spec-driven forms) never overwrites a newer `latest` at the destination (round-5 N6): when the destination already serves the name, the pinned root lands under its spec ref (or a digest alias) and `latest` stays.
"""

from pydantic import BaseModel, ConfigDict

from .encode import ANN_SPEC_SHA256
from .errors import DistError
from .location import Location
from .oci import (
    MEDIA_TYPE_INDEX,
    REF_NAME_ANNOTATION,
    ContentStore,
    Descriptor,
    OciLayout,
)
from .progress import BlobProgress
from .transfer import TransferResult, copy_closure

__all__ = ["MirrorReport", "mirror_names", "mirror_one", "source_names"]


class MirrorReport(BaseModel):
    """What a mirror did, per name."""

    model_config = ConfigDict(frozen=True)

    results: dict[str, TransferResult]

    @property
    def copied(self) -> int:
        return sum(len(result.copied) for result in self.results.values())

    @property
    def present(self) -> int:
        return sum(len(result.present) for result in self.results.values())


def source_names(location: Location) -> list[str]:
    """Every artifact name a location can enumerate.

    Raises:
        DistError: `location-unenumerable` for sources with no listing surface (the public hub), with the per-name form as the remedy.
    """
    from .catalog import CATALOG_REF, catalog_names

    try:
        # the published name list is the first-class enumeration (it is what
        # the hub-shaped locations have), with the structural listings below
        # as the fallback for locations that never published one
        return [name for name in catalog_names(location) if name != CATALOG_REF]
    except DistError as error:
        if error.code not in ("ref-not-found",):
            raise
    if location.directory is not None:
        layout = OciLayout(location.directory).open()
        names: list[str] = []
        for entry in layout.index().manifests:
            name = (entry.annotations or {}).get(REF_NAME_ANNOTATION)
            if (
                name
                and ":spec-" not in name
                and name != CATALOG_REF
                and name not in names
            ):
                names.append(name)
        return names
    base, prefix = location.registry_base_and_prefix()
    if base == "https://registry-1.docker.io":
        raise DistError(
            "location-unenumerable",
            "the public hub does not enumerate an org through the OCI API; "
            "mirror explicit names (the published catalog list is the "
            "catalog phase's follow-up)",
        )
    from .registry import registry_catalog

    return registry_catalog(base, prefix)


def _spec_refs_at_source(source: Location, name: str) -> list[tuple[str, str]]:
    """Every `(spec_hash, source_ref)` published for `name` at `source` (layouts list index refs; registries list tags)."""
    refs: list[tuple[str, str]] = []
    if source.directory is not None:
        layout = OciLayout(source.directory).open()
        marker = f"{name}:spec-"
        for entry in layout.index().manifests:
            ref_name = (entry.annotations or {}).get(REF_NAME_ANNOTATION) or ""
            if ref_name.startswith(marker):
                refs.append((ref_name.removeprefix(marker), ref_name))
        return refs
    from .registry import RegistryRepo

    store = source.store_for(name)
    assert isinstance(store, RegistryRepo)
    return [
        (tag.removeprefix("spec-"), tag)
        for tag in store.tags()
        if tag.startswith("spec-")
    ]


def _root_spec_hash(store: ContentStore, root: Descriptor) -> str | None:
    return (store.read_index(root).annotations or {}).get(ANN_SPEC_SHA256)


def _ref_exists(store: ContentStore, name: str) -> bool:
    try:
        store.ref(name)
        return True
    except DistError as error:
        if error.code == "ref-not-found":
            return False
        raise


def mirror_one(
    name: str,
    source: Location,
    destination: Location,
    *,
    root: Descriptor | None = None,
    progress: BlobProgress | None = None,
    all_builds: bool = False,
) -> TransferResult:
    """Mirror one name from `source` to `destination`: its current root (or an explicit `root`), with `all_builds` extending to every published build's spec ref and closure.

    Raises:
        DistError: unreadable sources, destination write failures, or a target that is not a pull root; a partial transfer is never consumable by name (`copy_closure`'s invariant).
    """
    source_store = source.store_for(name)
    explicit = root is not None
    if root is None:
        root = source_store.ref(source.latest_ref(name))
    if root.media_type != MEDIA_TYPE_INDEX:
        raise DistError(
            "manifest-invalid",
            f"{name!r} at {source.describe()} is not a pull root (an OCI index)",
        )
    destination_store = destination.store_for(name, create=True)
    latest_name = destination.latest_ref(name)
    spec_hash = _root_spec_hash(source_store, root)
    primary_name = latest_name
    if explicit and _ref_exists(destination_store, latest_name):
        # never regress a newer latest under an explicit older root
        primary_name = destination.spec_ref(
            name, spec_hash or root.require_sha256().removeprefix("sha256:")
        )
    result = copy_closure(
        source_store, destination_store, root, name=primary_name, progress=progress
    )
    if spec_hash and primary_name != destination.spec_ref(name, spec_hash):
        # the exact-spec ref travels, so spec-driven pull works FROM the mirror
        destination_store.put_index_bytes(
            destination.spec_ref(name, spec_hash), source_store.manifest_bytes(root)
        )
    if not all_builds:
        return result
    copied = list(result.copied)
    present = list(result.present)
    for build_hash, source_ref in _spec_refs_at_source(source, name):
        older = source_store.ref(source_ref)
        if older.digest == root.digest:
            continue
        extra = copy_closure(
            source_store,
            destination_store,
            older,
            name=destination.spec_ref(name, build_hash),
            progress=progress,
        )
        copied.extend(extra.copied)
        present.extend(extra.present)
    return TransferResult(
        root=result.root, copied=tuple(copied), present=tuple(present)
    )


def mirror_names(
    names: list[str],
    source: Location,
    destination: Location,
    *,
    progress: BlobProgress | None = None,
) -> MirrorReport:
    """Mirror a set of names completely (the whole-location form passes `source_names`): every build each name serves."""
    results: dict[str, TransferResult] = {}
    for name in names:
        results[name] = mirror_one(
            name, source, destination, progress=progress, all_builds=True
        )
    return MirrorReport(results=results)

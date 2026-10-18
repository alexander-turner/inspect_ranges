"""The mirror verb's engine: seed or sync a whole location, or copy one range's closure, between any two location forms (Journey B's operator sessions).

Mirroring rides `copy_closure` (raw verified bytes, destination index named LAST), so a mirrored root is complete by construction and byte-identical to its source. Whole-location mirroring enumerates the source: a layout lists its index refs; a registry lists `/v2/_catalog` under the location's prefix (what `registry:2` and private registries serve). Docker Hub does not expose org enumeration through the OCI API, so whole-org mirroring FROM the hub refuses with a named cause and the per-name form remains (the catalog phase's published name list is the recorded follow-up that will close this; spine Q12).

Spec-driven single mirroring matches `pull`: from a range directory, the normalized-spec hash selects the source build exactly, and the same `name@sha256:` pin form works with no spec in hand.
"""

import json
import urllib.error
import urllib.request
from typing import cast

from pydantic import BaseModel, ConfigDict

from .errors import DistError
from .location import Location
from .oci import MEDIA_TYPE_INDEX, REF_NAME_ANNOTATION, Descriptor, OciLayout
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
    if location.directory is not None:
        layout = OciLayout(location.directory).open()
        names: list[str] = []
        for entry in layout.index().manifests:
            name = (entry.annotations or {}).get(REF_NAME_ANNOTATION)
            if name and ":spec-" not in name and name not in names:
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
    try:
        with urllib.request.urlopen(f"{base}/v2/_catalog?n=1000", timeout=60) as resp:
            payload = json.loads(resp.read(1 << 20))
    except (urllib.error.URLError, OSError, ValueError) as error:
        raise DistError(
            "location-unenumerable",
            f"{location.describe()} did not answer the catalog listing: {error}; "
            "mirror explicit names instead",
        ) from error
    raw_repositories = payload.get("repositories")
    if not isinstance(raw_repositories, list):
        raise DistError(
            "location-unenumerable",
            f"{location.describe()} returned no repository list",
        )
    repositories = cast("list[object]", raw_repositories)
    wanted = f"{prefix}/" if prefix else ""
    return [
        repo.removeprefix(wanted)
        for repo in repositories
        if isinstance(repo, str) and (not wanted or repo.startswith(wanted))
    ]


def mirror_one(
    name: str,
    source: Location,
    destination: Location,
    *,
    root: Descriptor | None = None,
    progress: BlobProgress | None = None,
) -> TransferResult:
    """Mirror one name's current root (or an explicit `root`) from `source` to `destination`."""
    source_store = source.store_for(name)
    if root is None:
        root = source_store.ref(source.latest_ref(name))
    if root.media_type != MEDIA_TYPE_INDEX:
        raise DistError(
            "manifest-invalid",
            f"{name!r} at {source.describe()} is not a pull root (an OCI index)",
        )
    destination_store = destination.store_for(name, create=True)
    result = copy_closure(
        source_store,
        destination_store,
        root,
        name=destination.latest_ref(name),
        progress=progress,
    )
    # the exact-spec ref travels too, so spec-driven pull works FROM the mirror
    index = source_store.read_index(root)
    spec_hash = (index.annotations or {}).get("org.inspect-ranges.spec-sha256")
    if spec_hash:
        destination_store.put_index_bytes(
            destination.spec_ref(name, spec_hash), source_store.manifest_bytes(root)
        )
    return result


def mirror_names(
    names: list[str],
    source: Location,
    destination: Location,
    *,
    progress: BlobProgress | None = None,
) -> MirrorReport:
    """Mirror a set of names (the whole-location form passes `source_names`)."""
    results: dict[str, TransferResult] = {}
    for name in names:
        results[name] = mirror_one(name, source, destination, progress=progress)
    return MirrorReport(results=results)

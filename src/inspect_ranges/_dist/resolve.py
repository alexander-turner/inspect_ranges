"""Resolution and the spec-driven verbs: push a built range, pull by exact normalized-spec hash, publish and fetch catalog images, and the explicit move-forward refresh.

The spec hash is the join (spine Q3): specs travel by git, artifacts by registry, and `pull` connects them by exact match of the local `range.yaml`'s normalized-form hash against the published build's recorded hash. Push therefore names every root twice at its location: the form's latest ref and a `spec-<sha256>` ref, so a consumer resolves the exact build in one request. A mismatch refuses with `no-build-for-spec`, naming the nearest published build (the transcript's refusal), never guessing.

Resolution order is the spine's Q1 made operational: an explicit `name@sha256:` pin short-circuits everything; otherwise the local cache answers first (bare names are sticky; freezing is automatic), then the ordered search path, first match wins. Moving a cached bare name forward is the explicit `refresh` act, which lands the chain's staged bytes and renames them together under every member's lock; an interrupted refresh is re-run, and a mixed chain can never boot silently because `up` verifies the full backing chain including the golden-to-vendor edge (round-3 B4). The next build's keys change accordingly.
"""

from pathlib import Path

from pydantic import BaseModel, ConfigDict

from .._build.manifest import BuildManifest
from .._compiler.plan import image_file_name, resolve_image_reference, spec_sha256
from ..types import RangeSpec
from .encode import (
    ANN_BUILT_AT,
    ANN_SPEC_SHA256,
    encode_image_chain,
    push_build,
)
from .errors import DistError
from .location import Location
from .materialize import MaterializeResult, materialize_closure
from .oci import MEDIA_TYPE_INDEX, ContentStore, Descriptor, OciIndex

__all__ = [
    "PullReport",
    "pull_image",
    "pull_pinned",
    "pull_range",
    "push_image_artifact",
    "push_range",
    "refresh_image",
]


class PullReport(BaseModel):
    """Where a pull resolved and what it did."""

    model_config = ConfigDict(frozen=True)

    location: str
    root: str
    result: MaterializeResult


def push_range(
    manifest: BuildManifest,
    location: Location,
    *,
    image_cache: Path,
    build_cache: Path,
    range_dir: Path | None = None,
    recipe_cache: Path | None = None,
) -> Descriptor:
    """Push a built range's closure to `location`, named under both the latest ref and the exact-spec ref."""
    store = location.store_for(manifest.range_name, create=True)
    # the exact-spec ref lands FIRST and the latest ref LAST (round-3 N1): a
    # crash between the two must never leave a build visible as latest but
    # unresolvable by the spec hash that selects it
    root = push_build(
        manifest,
        store,
        image_cache=image_cache,
        build_cache=build_cache,
        range_dir=range_dir,
        recipe_cache=recipe_cache,
        ref=location.spec_ref(manifest.range_name, manifest.spec_sha256),
    )
    index_bytes = store.manifest_bytes(root)
    store.put_index_bytes(location.latest_ref(manifest.range_name), index_bytes)
    return root


def _try_ref(store: ContentStore, name: str) -> Descriptor | None:
    """`None` only for a clean miss; every other failure aborts the search, because silently falling through to a later location de-shadows the one the operator configured first (round-3 B2)."""
    try:
        return store.ref(name)
    except DistError as error:
        if error.code == "ref-not-found":
            return None
        raise


def _nearest_hint(store: ContentStore, location: Location, name: str) -> str | None:
    latest = _try_ref(store, location.latest_ref(name))
    if latest is None:
        return None
    try:
        annotations = store.read_index(latest).annotations or {}
    except DistError:
        return None
    built = annotations.get(ANN_BUILT_AT, "unknown time")
    spec = annotations.get(ANN_SPEC_SHA256, "unknown")
    return (
        f"{location.describe()} holds {name}@{latest.digest[:19]}... "
        f"(built {built} from spec {spec[:12]}...)"
    )


def pull_range(
    spec: RangeSpec,
    locations: list[Location],
    *,
    image_cache: Path,
    build_cache: Path,
    recipe_cache: Path,
    pin: str | None = None,
) -> PullReport:
    """Resolve and materialize the published build matching this spec exactly (or an explicit `sha256:` root pin), first location wins.

    Raises:
        DistError: `no-build-for-spec` when no location holds a build of this exact normalized spec (the message names the nearest published build per location), or any materialization refusal.
    """
    if pin is not None:
        return pull_pinned(
            spec.meta.name,
            pin,
            locations,
            image_cache=image_cache,
            build_cache=build_cache,
            recipe_cache=recipe_cache,
        )
    name = spec.meta.name
    want = spec_sha256(spec)
    nearest: list[str] = []
    for location in locations:
        store = location.store_for(name)
        found = _try_ref(store, location.spec_ref(name, want))
        if found is None:
            hint = _nearest_hint(store, location, name)
            if hint:
                nearest.append(hint)
            continue
        # tags are mutable: materialization re-imposes the identity the ref
        # CLAIMED (recorded spec hash and range name) before anything lands
        # (round-3 B1)
        result = materialize_closure(
            store,
            found,
            image_cache=image_cache,
            build_cache=build_cache,
            recipe_cache=recipe_cache,
            require_manifest=True,
            expect_range=name,
            expect_spec=want,
        )
        return PullReport(
            location=location.describe(), root=found.digest, result=result
        )
    searched = ", ".join(location.describe() for location in locations)
    detail = ("; nearest: " + "; ".join(nearest)) if nearest else ""
    raise DistError(
        "no-build-for-spec",
        f"no build of {name!r} matching this range.yaml (spec {want[:12]}...) "
        f"in [{searched}]{detail}; run 'inspect-ranges build' for the edited "
        f"spec, or check out the spec revision matching a published build",
    )


def pull_pinned(
    name: str,
    pin: str,
    locations: list[Location],
    *,
    image_cache: Path,
    build_cache: Path,
    recipe_cache: Path,
) -> PullReport:
    """The `name@sha256:` form: pull an exact published root with no spec in hand (Journey B); the landed manifest must still be a build of `name`.

    Raises:
        DistError: `no-build-for-spec` when no location holds the pinned root, or any materialization refusal (a pinned image-only closure refuses `manifest-invalid` rather than reporting vacuous success).
    """
    for location in locations:
        store = location.store_for(name)
        root = Descriptor(media_type=MEDIA_TYPE_INDEX, digest=pin, size=0)
        try:
            store.manifest_bytes(root)
        except DistError as error:
            if error.code in ("ref-not-found", "missing-blob"):
                continue
            raise
        result = materialize_closure(
            store,
            root,
            image_cache=image_cache,
            build_cache=build_cache,
            recipe_cache=recipe_cache,
            require_manifest=True,
            expect_range=name,
        )
        return PullReport(location=location.describe(), root=root.digest, result=result)
    raise DistError(
        "no-build-for-spec",
        f"no configured location holds a root {pin} for {name!r} "
        f"(searched: {', '.join(location.describe() for location in locations)})",
    )


def push_image_artifact(
    name: str, location: Location, *, image_cache: Path
) -> Descriptor:
    """Publish one cache image's chain (golden plus vendor base, or a bare vendor base) as a standalone catalog artifact named at `location`."""
    reference = resolve_image_reference(name, image_cache)
    if reference.digest is None:
        raise DistError("artifact-missing", f"image {name!r} is not in the image cache")
    store = location.store_for(name, create=True)
    config = store.ensure_empty_config()
    members = encode_image_chain(
        store, image_cache, reference.file, reference.digest, config=config
    )
    index = OciIndex(manifests=members, annotations={"org.inspect-ranges.name": name})
    return store.put_index(location.latest_ref(name), index)


def pull_image(
    name: str,
    locations: list[Location],
    *,
    image_cache: Path,
    replace: bool = False,
) -> tuple[str, MaterializeResult] | None:
    """Fetch a catalog image's chain from the first location holding it; `None` when no location does.

    With `replace` (the refresh act), a cache name holding different content moves forward to the published chain; without it, divergence refuses `cache-name-conflict` (shadow deliberately or prune first).
    """
    for location in locations:
        store = location.store_for(name)
        root = _try_ref(store, location.latest_ref(name))
        if root is None:
            continue
        result = materialize_closure(
            store, root, image_cache=image_cache, replace_images=replace
        )
        return location.describe(), result
    return None


def refresh_image(
    name: str, locations: list[Location], *, image_cache: Path
) -> tuple[str, MaterializeResult] | None:
    """The explicit move-forward act: re-resolve `name` against the search path and replace the cached chain when the registry moved on; the next build's keys change accordingly (freezing is automatic, moving forward is explicit)."""
    pulled = pull_image(name, locations, image_cache=image_cache, replace=True)
    if pulled is None:
        raise DistError(
            "image-not-published",
            f"no configured location publishes {name!r} "
            f"(searched: {', '.join(location.describe() for location in locations)})",
        )
    return pulled


def cached_image_digest(name: str, image_cache: Path) -> str | None:
    """The cache's current digest for a bare name (`None` when absent); what sticky resolution answers before the registry tier is consulted."""
    reference = resolve_image_reference(name, image_cache)
    return reference.digest


def image_cache_file(name: str) -> str:
    """The cache file a bare name maps to (the shared naming rule)."""
    return image_file_name(name)

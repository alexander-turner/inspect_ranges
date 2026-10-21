"""Resolution and the spec-driven verbs: push a built range, pull by exact normalized-spec hash, publish and fetch catalog images, and the explicit move-forward refresh.

The spec hash is the join (spine Q3): specs travel by git, artifacts by registry, and `pull` connects them by exact match of the local `range.yaml`'s normalized-form hash against the published build's recorded hash. Push therefore names every root twice at its location: the form's latest ref and a `spec-<sha256>` ref, so a consumer resolves the exact build in one request. A mismatch refuses with `no-build-for-spec`, naming the nearest published build (the transcript's refusal), never guessing.

Resolution order is the spine's Q1 made operational: an explicit `name@sha256:` pin short-circuits everything; otherwise the local cache answers first (bare names are sticky; freezing is automatic), then the ordered search path, first match wins. Moving a cached bare name forward is the explicit `refresh` act, which lands the chain's staged bytes and renames them together under every member's lock; an interrupted refresh is re-run, and a mixed chain can never boot silently because `up` verifies the full backing chain including the golden-to-vendor edge (round-3 B4). The next build's keys change accordingly.
"""

import os
from pathlib import Path

from pydantic import BaseModel, ConfigDict

from .._build.manifest import BuildManifest, load_manifest
from .._compiler.plan import image_file_name, resolve_image_reference, spec_sha256
from ..types import RangeSpec, has_guest_content, has_router_content
from .encode import (
    ANN_BUILT_AT,
    ANN_NAME,
    ANN_SPEC_SHA256,
    encode_image_chain,
    push_build,
)
from .errors import DistError
from .location import Location, registry_locations
from .materialize import MaterializeResult, materialize_closure
from .oci import MEDIA_TYPE_INDEX, ContentStore, Descriptor, OciIndex, ProgressFn

__all__ = [
    "NEVER_PULL_ENV",
    "PIN_FILE_ENV",
    "PullReport",
    "ensure_build_available",
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
    progress: "ProgressFn | None" = None,
) -> Descriptor:
    """Push a built range's closure to `location`, named under both the latest ref and the exact-spec ref."""
    from .catalog import refuse_reserved

    refuse_reserved(manifest.range_name, "rename the range")
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
        progress=progress,
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
    progress: "ProgressFn | None" = None,
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
            progress=progress,
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
            progress=progress,
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
    progress: "ProgressFn | None" = None,
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
            progress=progress,
        )
        return PullReport(location=location.describe(), root=root.digest, result=result)
    raise DistError(
        "no-build-for-spec",
        f"no configured location holds a root {pin} for {name!r} "
        f"(searched: {', '.join(location.describe() for location in locations)})",
    )


PIN_FILE_ENV = "INSPECT_RANGES_PIN_FILE"
"""Path to a fleet pin file ({"pins": {name: root digest}}): a catalog name resolving to a different root than its pin refuses `pin-mismatch` (Q11)."""


def _pins() -> dict[str, str]:
    path = os.environ.get(PIN_FILE_ENV)
    if not path:
        return {}
    import json as json_module

    try:
        data = json_module.loads(Path(path).read_text())
    except (OSError, ValueError) as error:
        raise DistError(
            "pin-file-invalid", f"{path} did not parse as a pin file: {error}"
        ) from error
    pins = data.get("pins")
    if not isinstance(pins, dict):
        raise DistError("pin-file-invalid", f"{path} carries no pins mapping")
    return {
        key: value
        for key, value in pins.items()  # pyright: ignore[reportUnknownVariableType]
        if isinstance(key, str) and isinstance(value, str)
    }


NEVER_PULL_ENV = "INSPECT_RANGES_NEVER_PULL"
"""Set to pin a host against IMPLICIT transfers: the provider's auto-pull and the build path's registry tier refuse/skip instead of touching the network. Scope recorded (round-4 N4): explicit verbs (`pull`, `images pull`, `images refresh`) still work on a pinned host, because typing them IS the operator's explicit intent; a fully offline host simply configures no reachable locations."""


def ensure_build_available(
    spec: RangeSpec,
    *,
    image_cache: Path,
    build_cache: Path,
    recipe_cache: Path,
    progress: "ProgressFn | None" = None,
) -> PullReport | None:
    """The provider's implicit resolve-verify-fetch (Journey B): `None` when nothing needed pulling (a content-free range, or the warm path: a local build manifest matching this exact spec, which costs one hash and zero network), else the pull report.

    Raises:
        DistError: `never-pull` when a pull is needed but the host is pinned offline; otherwise whatever `pull_range` refuses with (`no-build-for-spec` with the nearest builds, a named broken location, an unreachable registry).
    """
    content = any(has_guest_content(host) for host in spec.hosts) or any(
        has_router_content(router) for router in spec.routers
    )
    if not content:
        return None
    manifest = load_manifest(build_cache, spec.meta.name)
    if (
        manifest is not None
        and manifest.spec_sha256 == spec_sha256(spec)
        and _artifacts_present(manifest, image_cache)
    ):
        # warm: one hash plus presence checks, zero network; a pruned artifact
        # falls through to the pull, which heals it (round-4 N2)
        return None
    if os.environ.get(NEVER_PULL_ENV):
        raise DistError(
            "never-pull",
            f"no local build matches this range.yaml and {NEVER_PULL_ENV} is set; "
            "build locally, or pull on a host that allows it",
        )
    return pull_range(
        spec,
        registry_locations(),
        image_cache=image_cache,
        build_cache=build_cache,
        recipe_cache=recipe_cache,
        progress=progress,
    )


def catalog_image_references(spec: RangeSpec) -> list[str]:
    """Every image reference a render resolves OUTSIDE the build closure: content-free hosts' declared images, content-free routers with the default applied, and a dedicated attack box with the standard attack image applied. Built guests' artifacts (provisioned hosts AND routers) land via the build pull, never here; a foothold attacker (`host:` set) boots nothing of its own."""
    from .._compiler.plan import DEFAULT_ATTACKER_IMAGE, DEFAULT_ROUTER_IMAGE

    names: list[str] = []
    for host in spec.hosts:
        if not has_guest_content(host):
            names.append(host.image)
    for router in spec.routers:
        if not has_router_content(router):
            names.append(router.image or DEFAULT_ROUTER_IMAGE)
    if spec.attacker.host is None:
        names.append(spec.attacker.image or DEFAULT_ATTACKER_IMAGE)
    seen: set[str] = set()
    return [name for name in names if not (name in seen or seen.add(name))]


def ensure_images_available(
    spec: RangeSpec,
    *,
    image_cache: Path,
    progress: "ProgressFn | None" = None,
) -> list[str]:
    """The catalog tier of the provider's implicit fetch: every image this spec renders with that is absent from the cache pulls through the search path (the clean-machine `inspect eval` path: the attacker's default `attack`, goldens by bare name); returns what was pulled, `[]` on the warm path (zero network).

    Raises:
        DistError: `never-pull` when an image is missing and the host is pinned offline, `image-not-published` when no configured location serves a missing name, plus transport refusals.
    """
    missing = [
        name
        for name in catalog_image_references(spec)
        if not (image_cache / image_cache_file(name)).is_file()
    ]
    if not missing:
        return []
    if os.environ.get(NEVER_PULL_ENV):
        raise DistError(
            "never-pull",
            f"image(s) {', '.join(repr(name) for name in missing)} are not in the "
            f"cache and {NEVER_PULL_ENV} is set; pull explicitly, or run on a host "
            "that allows implicit transfers",
        )
    locations = registry_locations()
    for name in missing:
        pulled = pull_image(name, locations, image_cache=image_cache, progress=progress)
        if pulled is None:
            raise DistError(
                "image-not-published",
                f"image {name!r} is neither cached nor published at any configured "
                f"location (searched: "
                f"{', '.join(location.describe() for location in locations)})",
            )
        if not (image_cache / image_cache_file(name)).is_file():
            raise DistError(
                "published-mismatch",
                f"pulling {name!r} from {pulled[0]} landed a closure that does "
                f"not contain {image_cache_file(name)}; the published artifact "
                "is not the named image",
            )
    return missing


def _artifacts_present(manifest: BuildManifest, image_cache: Path) -> bool:
    """Whether every image the manifest references exists in the cache (presence only; the gate's sidecar discipline and boot's verify-images own the digests)."""
    from .._compiler.plan import image_file_name

    files = {base.file for base in manifest.base_images}
    for guest in manifest.guests:
        files.add(guest.realized_file)
        files.add(image_file_name(guest.golden_reference))
    return all((image_cache / file).is_file() for file in files)


def push_image_artifact(
    name: str, location: Location, *, image_cache: Path
) -> Descriptor:
    """Publish one cache image's chain (golden plus vendor base, or a bare vendor base) as a standalone catalog artifact named at `location`.

    Raises:
        DistError: `name-reserved` for the reserved refs, `artifact-missing` when the image is not cached.
    """
    from .catalog import refuse_reserved

    refuse_reserved(name, "images never publish under it")
    reference = resolve_image_reference(name, image_cache)
    if reference.digest is None:
        raise DistError("artifact-missing", f"image {name!r} is not in the image cache")
    store = location.store_for(name, create=True)
    config = store.ensure_empty_config()
    members = encode_image_chain(
        store, image_cache, reference.file, reference.digest, config=config
    )
    index = OciIndex(manifests=members, annotations={ANN_NAME: name})
    return store.put_index(location.latest_ref(name), index)


def pull_image(
    name: str,
    locations: list[Location],
    *,
    image_cache: Path,
    replace: bool = False,
    progress: "ProgressFn | None" = None,
) -> tuple[str, MaterializeResult] | None:
    """Fetch a catalog image's chain from the first location holding it; `None` when no location does.

    With `replace` (the refresh act), a cache name holding different content moves forward to the published chain; without it, divergence refuses `cache-name-conflict` (shadow deliberately or prune first).
    """
    pins = _pins()
    for location in locations:
        store = location.store_for(name)
        root = _try_ref(store, location.latest_ref(name))
        if root is None:
            continue
        if name in pins and root.digest != pins[name]:
            # the pin consumes as an @sha256 pin (spine Q1): the pinned root
            # stays fetchable by digest even after the tag moved, so the fleet
            # lands its pinned state from origin; only a GONE pinned root
            # refuses (round-2 slice-2 review N2)
            pinned_root = Descriptor(
                media_type=MEDIA_TYPE_INDEX, digest=pins[name], size=0
            )
            try:
                store.manifest_bytes(pinned_root)
                root = pinned_root
            except DistError as error:
                if error.code not in ("ref-not-found", "missing-blob"):
                    raise
                raise DistError(
                    "pin-mismatch",
                    f"{name!r} at {location.describe()} resolves to "
                    f"{root.digest[:19]}..., the fleet pin names "
                    f"{pins[name][:19]}..., and the pinned root is no longer "
                    "served there; mirror the pinned artifacts or update the "
                    "pin file deliberately",
                ) from None
        # the identity check the range path gets from expect_range (round-3
        # B1), for the catalog tier: registry tags are mutable, so the root a
        # name RESOLVED TO is untrusted until its recorded published name
        # matches what was asked for; a re-pointed reference never lands
        recorded = (store.read_index(root).annotations or {}).get(ANN_NAME)
        if recorded != name:
            raise DistError(
                "published-mismatch",
                f"the root {root.digest[:19]}... served for {name!r} at "
                f"{location.describe()} records the published name "
                f"{recorded!r}; a re-pointed reference never lands",
            )
        result = materialize_closure(
            store,
            root,
            image_cache=image_cache,
            replace_images=replace,
            progress=progress,
        )
        return location.describe(), result
    return None


def refresh_image(
    name: str,
    locations: list[Location],
    *,
    image_cache: Path,
    progress: "ProgressFn | None" = None,
) -> tuple[str, MaterializeResult] | None:
    """The explicit move-forward act: re-resolve `name` against the search path and replace the cached chain when the registry moved on; the next build's keys change accordingly (freezing is automatic, moving forward is explicit)."""
    pulled = pull_image(
        name, locations, image_cache=image_cache, replace=True, progress=progress
    )
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

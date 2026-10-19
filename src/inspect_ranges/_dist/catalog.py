"""The catalog: publishing bare names (standard-images-v1 slice 2).

`publish` is the deliberate promotion act distribution v1 deferred (Journey B: "push mints no image names"): a built guest's realized image, or a cache golden, becomes consumable by other ranges' `image:` lines under a bare catalog name. A promoted realized image travels with its whole chain (golden, vendor base, provenance sidecars) and lands in consumer caches under the catalog name's file (`attack.qcow2`), so bare-name resolution, stickiness, and `images refresh` all apply to it exactly like any catalog image.

The catalog also publishes its own name list as a well-known artifact (the reserved ref `catalog`): a JSON layer enumerating the published names. That list is what closes the hub-enumeration gap mirror recorded (the hub exposes no org listing through the OCI API), and the Q11 fleet pin file is generated from the same resolution (name to root digest, consumed as refusals on divergence).
"""

import json
import time
from pathlib import Path
from typing import TYPE_CHECKING, cast

from .._build.manifest import BuildManifest

if TYPE_CHECKING:
    from .._channel.bundle import DaemonBundleInfo as DaemonInfo
from .encode import (
    ANN_BACKING_DIGEST,
    ANN_BACKING_FILE,
    ANN_KIND,
    ANN_NAME,
    ARTIFACT_DAEMON_BUNDLE,
    ARTIFACT_REALIZED,
    LAYER_DAEMON_TAR,
    LAYER_SIDECAR,
    encode_image_chain,
    prefixed_digest,
    qcow2_descriptor,
    realized_sidecar_path,
    validated_cache_name,
)
from .errors import DistError
from .location import Location
from .oci import Descriptor, OciIndex, OciManifest
from .resolve import push_image_artifact

__all__ = [
    "CATALOG_REF",
    "DAEMON_REF",
    "catalog_names",
    "fetch_daemon_bundle",
    "generate_pin_file",
    "publish_daemon_bundle",
    "publish_golden",
    "publish_realized",
]

CATALOG_REF = "catalog"
"""The reserved ref carrying the catalog's name list at a location."""

DAEMON_REF = "daemon-bundle"
"""The reserved ref carrying the published daemon bundle at a location: the bundle tar plus its `daemon.json` sidecar, landing in the artifact directory (never the image cache), so fleets derive goldens without a Go toolchain."""

CATALOG_ARTIFACT = "application/vnd.inspect-ranges.catalog.v1"
CATALOG_LAYER = "application/vnd.inspect-ranges.catalog.v1+json"


def _update_catalog_index(location: Location, name: str) -> None:
    """Add `name` to the location's published-name list (read-modify-write; the layout's index lock or the registry's last-write serialize publishers, who are one deliberate actor by posture)."""
    store = location.store_for(CATALOG_REF, create=True)
    names: list[str] = []
    try:
        root = store.ref(location.latest_ref(CATALOG_REF))
        index = store.read_index(root)
        if index.manifests:
            manifest = store.manifest(index.manifests[0])
            if manifest.artifact_type != CATALOG_ARTIFACT:
                raise DistError(
                    "catalog-invalid",
                    f"{location.describe()}'s {CATALOG_REF!r} ref holds a "
                    f"{manifest.artifact_type!r} artifact, not the catalog list",
                )
            try:
                data = json.loads(store.read_blob(manifest.layers[0]))
            except ValueError as error:
                raise DistError(
                    "catalog-invalid",
                    f"{location.describe()}'s catalog list does not parse: {error}",
                ) from error
            existing = data.get("names")
            if isinstance(existing, list):
                names = [
                    entry
                    for entry in cast("list[object]", existing)
                    if isinstance(entry, str)
                ]
    except DistError as error:
        if error.code != "ref-not-found":
            raise
    if name not in names:
        names.append(name)
    payload = json.dumps(
        {
            "names": sorted(names),
            "updated": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }
    ).encode()
    digest = store.put_blob_bytes(payload)
    manifest = OciManifest(
        artifact_type=CATALOG_ARTIFACT,
        config=store.ensure_empty_config(),
        layers=[Descriptor(media_type=CATALOG_LAYER, digest=digest, size=len(payload))],
        annotations={ANN_KIND: "catalog"},
    )
    member = store.put_manifest(manifest)
    index = OciIndex(manifests=[member], annotations={ANN_KIND: "catalog"})
    store.put_index(location.latest_ref(CATALOG_REF), index)


def catalog_names(location: Location) -> list[str]:
    """The names a location's catalog artifact lists (the hub-safe enumeration).

    Raises:
        DistError: `ref-not-found` when the location publishes no catalog.
    """
    store = location.store_for(CATALOG_REF)
    root = store.ref(location.latest_ref(CATALOG_REF))
    index = store.read_index(root)
    if not index.manifests:
        return []
    manifest = store.manifest(index.manifests[0])
    if manifest.artifact_type != CATALOG_ARTIFACT:
        raise DistError(
            "catalog-invalid",
            f"{location.describe()}'s {CATALOG_REF!r} ref holds a "
            f"{manifest.artifact_type!r} artifact, not the catalog list",
        )
    try:
        data = json.loads(store.read_blob(manifest.layers[0]))
    except ValueError as error:
        raise DistError(
            "catalog-invalid",
            f"{location.describe()}'s catalog list does not parse: {error}",
        ) from error
    names = data.get("names")
    if not isinstance(names, list):
        return []
    return [entry for entry in cast("list[object]", names) if isinstance(entry, str)]


def _refuse_reserved(name: str) -> None:
    if name == CATALOG_REF:
        raise DistError(
            "name-reserved",
            f"{CATALOG_REF!r} is the catalog's own ref; nothing publishes under it",
        )
    if name == DAEMON_REF:
        raise DistError(
            "name-reserved",
            f"{DAEMON_REF!r} is the published daemon bundle's ref; images never publish under it",
        )


def publish_golden(name: str, location: Location, *, image_cache: Path) -> Descriptor:
    """Promote a cache golden (its whole chain) to the catalog under its own name."""
    _refuse_reserved(name)
    root = push_image_artifact(name, location, image_cache=image_cache)
    _update_catalog_index(location, name)
    return root


def publish_realized(
    manifest: BuildManifest,
    guest: str,
    catalog_name: str,
    location: Location,
    *,
    image_cache: Path,
) -> Descriptor:
    """Promote a built guest's realized image to the bare catalog name: the realized blob republishes under `<catalog_name>.qcow2` (bare-name resolution lands it there in consumer caches), its chain travels, and the provenance sidecar rides verbatim (the factory range and guest stay recorded as provenance).

    Raises:
        DistError: `artifact-missing` when the guest or its files are absent, plus every encode-time digest refusal.
    """
    _refuse_reserved(catalog_name)
    validated_cache_name(f"{catalog_name}.qcow2")
    if any(check.status != "pass" for check in manifest.verification.behavioral_checks):
        raise DistError(
            "range-unproven",
            f"the manifest for {manifest.range_name!r} records failing behavioral "
            "checks (a refused build); an unproven image never publishes",
        )
    record = manifest.guest(guest)
    if record is None:
        raise DistError(
            "artifact-missing",
            f"the manifest for {manifest.range_name!r} has no guest {guest!r}",
        )
    from .._compiler.plan import image_file_name

    store = location.store_for(catalog_name, create=True)
    config = store.ensure_empty_config()
    golden_file = image_file_name(record.golden_reference)
    members = encode_image_chain(
        store, image_cache, golden_file, record.golden_digest, config=config
    )
    realized_blob = qcow2_descriptor(
        store,
        image_cache / record.realized_file,
        expected=prefixed_digest(record.realized_sha256),
    )
    sidecar_path = realized_sidecar_path(image_cache, record.realized_file)
    if not sidecar_path.is_file():
        raise DistError(
            "artifact-missing",
            f"{sidecar_path} is missing; a realized image publishes with its provenance sidecar",
        )
    sidecar_bytes = sidecar_path.read_bytes()
    sidecar_digest = store.put_blob_bytes(sidecar_bytes)
    members.append(
        store.put_manifest(
            OciManifest(
                artifact_type=ARTIFACT_REALIZED,
                config=config,
                layers=[
                    realized_blob,
                    Descriptor(
                        media_type=LAYER_SIDECAR,
                        digest=sidecar_digest,
                        size=len(sidecar_bytes),
                    ),
                ],
                annotations={
                    ANN_KIND: "realized-image",
                    ANN_NAME: f"{catalog_name}.qcow2",
                    ANN_BACKING_FILE: golden_file,
                    ANN_BACKING_DIGEST: prefixed_digest(record.golden_digest),
                },
            )
        )
    )
    index = OciIndex(
        manifests=members, annotations={"org.inspect-ranges.name": catalog_name}
    )
    root = store.put_index(location.latest_ref(catalog_name), index)
    _update_catalog_index(location, catalog_name)
    return root


def publish_daemon_bundle(artifact_dir: Path, location: Location) -> Descriptor:
    """Publish the daemon artifact (the bundle tar and its `daemon.json` sidecar) under the reserved `daemon-bundle` ref, verified against the sidecar's recorded digest before anything uploads.

    Raises:
        DistError: `artifact-missing` when the directory lacks the sidecar or the tar it names, `digest-mismatch` when the tar does not match the sidecar's recorded digest.
    """
    import hashlib

    from .._channel.bundle import DaemonBundleInfo, bundle_file_name

    sidecar_path = artifact_dir / "daemon.json"
    if not sidecar_path.is_file():
        raise DistError(
            "artifact-missing",
            f"{sidecar_path} is missing; build the bundle with 'inspect-ranges daemon-bundle' first",
        )
    try:
        info = DaemonBundleInfo.model_validate_json(sidecar_path.read_text())
    except ValueError as error:
        raise DistError(
            "artifact-missing", f"{sidecar_path} does not parse: {error}"
        ) from error
    tar_path = artifact_dir / bundle_file_name(info.version)
    if not tar_path.is_file():
        raise DistError(
            "artifact-missing",
            f"{tar_path} is missing beside its sidecar; rebuild the bundle",
        )
    tar_bytes = tar_path.read_bytes()
    digest = hashlib.sha256(tar_bytes).hexdigest()
    if digest != info.bundle_sha256:
        raise DistError(
            "digest-mismatch",
            f"{tar_path} is sha256:{digest[:16]}..., its sidecar records "
            f"sha256:{info.bundle_sha256[:16]}...; rebuild the bundle",
        )
    sidecar_bytes = sidecar_path.read_bytes()
    store = location.store_for(DAEMON_REF, create=True)
    tar_digest = store.put_blob_bytes(tar_bytes)
    sidecar_digest = store.put_blob_bytes(sidecar_bytes)
    manifest = OciManifest(
        artifact_type=ARTIFACT_DAEMON_BUNDLE,
        config=store.ensure_empty_config(),
        layers=[
            Descriptor(
                media_type=LAYER_DAEMON_TAR, digest=tar_digest, size=len(tar_bytes)
            ),
            Descriptor(
                media_type=LAYER_SIDECAR, digest=sidecar_digest, size=len(sidecar_bytes)
            ),
        ],
        annotations={
            ANN_KIND: "daemon-bundle",
            "org.inspect-ranges.daemon-version": info.version,
        },
    )
    member = store.put_manifest(manifest)
    index = OciIndex(manifests=[member], annotations={ANN_KIND: "daemon-bundle"})
    return store.put_index(location.latest_ref(DAEMON_REF), index)


def fetch_daemon_bundle(locations: "list[Location]", out_dir: Path) -> "DaemonInfo":
    """Fetch the published daemon bundle from the first location serving one, landing the tar and sidecar in `out_dir` (the no-Go-toolchain path to the artifact `images derive` consumes).

    The tar lands before the sidecar: a torn landing reads as rebuildable (`tar-missing`), never as a consumable bundle.

    Raises:
        DistError: `artifact-missing` when no configured location publishes a bundle, `daemon-bundle-invalid` for a ref holding something else, `digest-mismatch` when the served tar does not match its sidecar; a broken location aborts rather than silently falling through.
    """
    import hashlib

    from .._channel.bundle import DaemonBundleInfo, bundle_file_name
    from .oci import atomic_write

    for location in locations:
        store = location.store_for(DAEMON_REF)
        try:
            root = store.ref(location.latest_ref(DAEMON_REF))
        except DistError as error:
            if error.code == "ref-not-found":
                continue
            raise
        index = store.read_index(root)
        if not index.manifests:
            raise DistError(
                "daemon-bundle-invalid",
                f"{location.describe()}'s {DAEMON_REF!r} ref is an empty index",
            )
        manifest = store.manifest(index.manifests[0])
        if manifest.artifact_type != ARTIFACT_DAEMON_BUNDLE:
            raise DistError(
                "daemon-bundle-invalid",
                f"{location.describe()}'s {DAEMON_REF!r} ref holds a "
                f"{manifest.artifact_type!r} artifact, not a daemon bundle",
            )
        tar_layer = next(
            (
                layer
                for layer in manifest.layers
                if layer.media_type == LAYER_DAEMON_TAR
            ),
            None,
        )
        sidecar_layer = next(
            (layer for layer in manifest.layers if layer.media_type == LAYER_SIDECAR),
            None,
        )
        if tar_layer is None or sidecar_layer is None:
            raise DistError(
                "daemon-bundle-invalid",
                f"{location.describe()}'s daemon bundle lacks its tar or sidecar layer",
            )
        sidecar_bytes = store.read_blob(sidecar_layer)
        try:
            info = DaemonBundleInfo.model_validate_json(sidecar_bytes)
        except ValueError as error:
            raise DistError(
                "daemon-bundle-invalid",
                f"{location.describe()}'s daemon sidecar does not parse: {error}",
            ) from error
        tar_bytes = store.read_blob(tar_layer)
        digest = hashlib.sha256(tar_bytes).hexdigest()
        if digest != info.bundle_sha256:
            raise DistError(
                "digest-mismatch",
                f"the daemon tar served by {location.describe()} is "
                f"sha256:{digest[:16]}..., its sidecar records "
                f"sha256:{info.bundle_sha256[:16]}...",
            )
        atomic_write(out_dir / bundle_file_name(info.version), tar_bytes)
        atomic_write(out_dir / "daemon.json", sidecar_bytes)
        return info
    raise DistError(
        "artifact-missing",
        "no configured location publishes a daemon bundle (searched: "
        + ", ".join(location.describe() for location in locations)
        + ")",
    )


def generate_pin_file(location: Location, out: Path) -> dict[str, str]:
    """The Q11 fleet pin file: every catalog name's current root digest at `location`, written as JSON; consumers refuse a resolved root diverging from its pin."""
    pins: dict[str, str] = {}
    for name in catalog_names(location):
        store = location.store_for(name)
        pins[name] = store.ref(location.latest_ref(name)).digest
    out.write_text(json.dumps({"pins": pins}, indent=2, sort_keys=True) + "\n")
    return pins

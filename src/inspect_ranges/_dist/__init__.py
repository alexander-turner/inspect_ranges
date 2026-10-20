"""Distribution: push, mirror, and spec-driven pull of built artifacts over OCI locations (distribution-v1.md).

A location has three interchangeable forms (public hub, private OCI registry, plain image-layout directory); identity is content digests end to end, and every byte verifies against its descriptor before use on every path.
"""

from .encode import push_build
from .errors import DistError
from .location import Location, parse_location, registry_locations
from .materialize import MaterializeResult, materialize_closure
from .oci import (
    ContentStore,
    Descriptor,
    OciIndex,
    OciLayout,
    OciManifest,
    blob_sha256,
)
from .registry import RegistryRepo
from .resolve import (
    PullReport,
    pull_image,
    pull_pinned,
    pull_range,
    push_image_artifact,
    push_range,
    refresh_image,
)
from .transfer import TransferResult, copy_closure

__all__ = [
    "ContentStore",
    "Descriptor",
    "DistError",
    "Location",
    "MaterializeResult",
    "OciIndex",
    "OciLayout",
    "OciManifest",
    "PullReport",
    "RegistryRepo",
    "TransferResult",
    "blob_sha256",
    "copy_closure",
    "materialize_closure",
    "parse_location",
    "pull_image",
    "pull_pinned",
    "pull_range",
    "push_build",
    "push_image_artifact",
    "push_range",
    "refresh_image",
    "registry_locations",
]

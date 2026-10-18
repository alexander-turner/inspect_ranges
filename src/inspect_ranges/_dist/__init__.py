"""Distribution: push, mirror, and spec-driven pull of built artifacts over OCI locations (distribution-v1.md).

A location has three interchangeable forms (public hub, private OCI registry, plain image-layout directory); identity is content digests end to end, and every byte verifies against its descriptor before use on every path.
"""

from .encode import push_build
from .errors import DistError
from .materialize import MaterializeResult, materialize_closure
from .oci import Descriptor, OciIndex, OciLayout, OciManifest, blob_sha256

__all__ = [
    "Descriptor",
    "DistError",
    "MaterializeResult",
    "OciIndex",
    "OciLayout",
    "OciManifest",
    "blob_sha256",
    "materialize_closure",
    "push_build",
]

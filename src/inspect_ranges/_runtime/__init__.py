"""Runtime realization: image derivation now; the bundle applier (`up`/`down`) in later slices.

The realizer consumes `inspect_ranges.types` and the compiler's plan/bundle and nothing from the channel track; the guest control daemon crosses the tracks only as a digest-pinned artifact (see `realizer-v1.md`).
"""

from .down import DownResult, down, down_all
from .images import (
    DaemonPin,
    DeriveError,
    ImageMetadata,
    derive_golden,
    list_images,
)
from .up import UpError, UpOptions, UpResult, up, verify_bundle

__all__ = [
    "DaemonPin",
    "DeriveError",
    "DownResult",
    "ImageMetadata",
    "UpError",
    "UpOptions",
    "UpResult",
    "derive_golden",
    "down",
    "down_all",
    "list_images",
    "up",
    "verify_bundle",
]

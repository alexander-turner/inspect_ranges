"""Runtime realization: image derivation now; the bundle applier (`up`/`down`) in later slices.

The realizer consumes `inspect_ranges.types` and the compiler's plan/bundle and nothing from the channel track; the guest control daemon crosses the tracks only as a digest-pinned artifact (see `realizer-v1.md`).
"""

from .images import (
    DaemonPin,
    DeriveError,
    ImageMetadata,
    derive_golden,
    list_images,
)

__all__ = [
    "DaemonPin",
    "DeriveError",
    "ImageMetadata",
    "derive_golden",
    "list_images",
]

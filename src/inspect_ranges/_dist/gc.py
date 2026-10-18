"""The distribution GC tier: whole-chain liveness over the flat image cache.

Eviction is by whole chain, never a backing out from under a dependent (image-distribution.md): a golden is live while any realized sidecar names it as `golden_file`, any build manifest records it (as a guest's golden or a base image), or a live project boots it; a vendor base is live while ANY golden that still exists names it, surviving or frozen (round-5 B1: a golden whose provenance cannot be read freezes its whole chain, vendor included). Vendors are identified by the sidecars that name them, never by file extension (round-5 N1: `.qcow2` vendors are first-class), so an orphan chain leaves together and only together.

Freezing is loud (round-5 N2): unreadable provenance returns the reasons alongside the victims, and the caller reports what froze the tier and why instead of silently finding nothing.

Concurrency (round-5 B2): the scan itself is pure, but scan-and-delete must not interleave with a chain landing mid-flight (a pull that has landed the vendor but not the golden looks exactly like an orphan vendor). The cache-wide chains lock (`chains_lock`) closes it: every chain writer (pull materialization, derive, capture) holds it SHARED for the landing, and `images prune --chains` holds it EXCLUSIVE across scan and unlink, so the scan only ever sees complete chains.
"""

import fcntl
import json
from contextlib import contextmanager
from pathlib import Path
from typing import TYPE_CHECKING

from .._build.manifest import load_manifest

if TYPE_CHECKING:
    from collections.abc import Generator

__all__ = ["chains_lock", "unreferenced_chain_files"]

CHAINS_LOCK_NAME = ".chains.lock"


@contextmanager
def chains_lock(image_cache: Path, *, exclusive: bool) -> "Generator[None]":
    """The cache-wide chain lock: shared for landings (pull, derive, capture), exclusive for scan-and-evict, so the GC never observes a half-landed chain."""
    image_cache.mkdir(parents=True, exist_ok=True)
    with open(image_cache / CHAINS_LOCK_NAME, "w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH)
        try:
            yield
        finally:
            fcntl.flock(lock, fcntl.LOCK_UN)


def _sidecar_field(path: Path, field: str) -> str | None:
    try:
        value = json.loads(path.read_text()).get(field)
    except (OSError, ValueError):
        return None
    return value if isinstance(value, str) else None


def unreferenced_chain_files(
    image_cache: Path, build_cache: Path, live_files: set[str]
) -> tuple[list[tuple[Path, str]], list[str]]:
    """Goldens and vendor bases nothing references, with their sidecars, plus the freeze reasons (unreadable provenance that pinned part of the tier in place).

    The caller must hold the chains lock exclusively around this scan and any deletion of its victims.
    """
    frozen: list[str] = []
    referenced_goldens: set[str] = set(live_files)

    for sidecar in sorted(image_cache.glob("*.realized.json")):
        image = image_cache / (sidecar.name.removesuffix(".realized.json") + ".qcow2")
        if not image.is_file():
            continue  # the base tier reports orphan sidecars
        golden = _sidecar_field(sidecar, "golden_file")
        if golden:
            referenced_goldens.add(golden)
        else:
            # unreadable realized provenance: its golden (and that golden's
            # vendor) cannot be attributed, so the whole tier freezes loudly
            frozen.append(f"{sidecar.name}: unreadable realized provenance")

    for manifest_path in list(build_cache.glob("*/manifest.json")) + list(
        build_cache.glob("*/*/manifest.json")
    ):
        manifest = load_manifest(manifest_path.parent.parent, manifest_path.parent.name)
        if manifest is None:
            continue
        from .._compiler.plan import image_file_name

        for base in manifest.base_images:
            referenced_goldens.add(base.file)
        for guest in manifest.guests:
            referenced_goldens.add(image_file_name(guest.golden_reference))

    if frozen:
        return [], frozen

    # golden attribution: every golden-shaped sidecar maps file -> vendor; the
    # vendor tier derives entirely from these maps (never from extensions)
    victims: list[tuple[Path, str]] = []
    vendors_of_survivors: set[str] = set(live_files)
    vendors_of_victims: dict[str, list[str]] = {}
    attributed_images: set[str] = set()
    named_vendors: set[str] = set()
    for sidecar in sorted(image_cache.glob("*.json")):
        if sidecar.name.endswith(".realized.json"):
            continue
        file = _sidecar_field(sidecar, "file")
        vendor = _sidecar_field(sidecar, "vendor_file")
        if file is None or vendor is None:
            continue  # not a golden provenance sidecar
        attributed_images.add(file)
        named_vendors.add(vendor)
        if file in referenced_goldens or not (image_cache / file).is_file():
            # surviving (or mid-landing: sidecar before image) goldens pin
            # their vendors; a sidecar whose image never lands is base-tier
            # debris, not a chain victim (round-5 B2 half b)
            vendors_of_survivors.add(vendor)
            continue
        victims.append((image_cache / file, "unreferenced golden"))
        victims.append((sidecar, "its provenance sidecar"))
        vendors_of_victims.setdefault(vendor, []).append(file)

    # a golden-shaped qcow2 with NO readable provenance freezes the vendor
    # tier: its vendor cannot be attributed, so nothing vendor-shaped leaves
    for image in sorted(image_cache.glob("*.qcow2")):
        if image.name in attributed_images or image.name in named_vendors:
            continue  # a vendor named by a sidecar IS attributed (qcow2 vendors)
        if (
            image_cache / (image.name.removesuffix(".qcow2") + ".realized.json")
        ).is_file():
            continue  # realized images are the realized tier's concern
        if image.name in referenced_goldens or image.name in live_files:
            continue  # a referenced file without provenance is frozen in place anyway
        sidecar = image_cache / (image.name.removesuffix(".qcow2") + ".json")
        frozen.append(f"{image.name}: no readable provenance sidecar ({sidecar.name})")
    if frozen:
        # the freeze protects vendors; fully-attributed orphan goldens still
        # leave (their chains are known), but no vendor does
        return victims, frozen

    for vendor, naming_goldens in sorted(vendors_of_victims.items()):
        if vendor in vendors_of_survivors:
            continue
        if not (image_cache / vendor).is_file():
            continue
        victims.append(
            (
                image_cache / vendor,
                f"unreferenced vendor base (named only by {', '.join(naming_goldens)})",
            )
        )
    return victims, frozen

"""The distribution GC tier: whole-chain liveness over the flat image cache.

Eviction is by whole chain, never a backing out from under a dependent (image-distribution.md): a golden is live while any realized sidecar names it as `golden_file`, any build manifest records it (as a guest's golden or a base image), or a live project boots it; a vendor base is live while any surviving golden's provenance sidecar names it as `vendor_file`. Pulled chains are accounted exactly like built ones, because both land under the same sidecar discipline. The scan is conservative on unreadable metadata: a file whose provenance cannot be read is never offered for eviction.
"""

import json
from pathlib import Path

from .._build.manifest import load_manifest

__all__ = ["unreferenced_chain_files"]


def _sidecar_field(path: Path, field: str) -> str | None:
    try:
        value = json.loads(path.read_text()).get(field)
    except (OSError, ValueError):
        return None
    return value if isinstance(value, str) else None


def unreferenced_chain_files(
    image_cache: Path, build_cache: Path, live_files: set[str]
) -> list[tuple[Path, str]]:
    """Goldens and vendor bases nothing references, with their sidecars, in a safe eviction order (dependents never outlive backings because only fully unreferenced members are offered)."""
    referenced_goldens: set[str] = set(live_files)
    referenced_vendors: set[str] = set(live_files)

    for sidecar in image_cache.glob("*.realized.json"):
        image = image_cache / (sidecar.name.removesuffix(".realized.json") + ".qcow2")
        if not image.is_file():
            continue
        golden = _sidecar_field(sidecar, "golden_file")
        if golden:
            referenced_goldens.add(golden)
        else:
            # unreadable provenance: freeze every golden rather than guess
            return []

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

    victims: list[tuple[Path, str]] = []
    surviving_goldens: list[Path] = []
    for sidecar in sorted(image_cache.glob("*.json")):
        if sidecar.name.endswith(".realized.json"):
            continue
        file = _sidecar_field(sidecar, "file")
        vendor = _sidecar_field(sidecar, "vendor_file")
        if file is None or vendor is None:
            continue  # not a golden provenance sidecar
        if file in referenced_goldens:
            surviving_goldens.append(sidecar)
            referenced_vendors.add(vendor)
            continue
        image = image_cache / file
        if image.is_file():
            victims.append((image, "unreferenced golden"))
        victims.append((sidecar, "its provenance sidecar"))

    for vendor_path in sorted(image_cache.glob("*.img")):
        if vendor_path.name in referenced_vendors:
            continue
        # a vendor named by NO surviving golden; the victims' goldens above
        # are leaving in the same prune, so the chain goes together
        named_by_surviving = any(
            _sidecar_field(sidecar, "vendor_file") == vendor_path.name
            for sidecar in surviving_goldens
        )
        if not named_by_surviving:
            victims.append((vendor_path, "unreferenced vendor base"))
    return victims

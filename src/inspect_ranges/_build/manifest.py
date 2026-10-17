"""The range build manifest and the per-guest build keys (build-v1 slice 5).

The manifest is the publishable identity of a built range version (range-build's commitment, the spine's wraps-by-reference decision): every input resolved to digests, recipe `(name, version, digest)` triples with their vars hashes, per-guest realized images with content digests, verification results, and never secrets. It lives in the builds cache (`~/.cache/inspect-ranges/builds/<range>/manifest.json`, `INSPECT_RANGES_BUILD_CACHE`), written atomically.

Invalidation follows the spine's two-key algebra: each guest carries a build key hashing its golden digest, its realized-spec projection (provisioning, services, vulnerabilities, canonically dumped), and its ordered recipe digests and vars. A guest whose key matches the recorded manifest boots from its captured realized image and skips its recipes; a build whose guests all match and whose verification is recorded skips entirely, reporting the cached verification (all-or-nothing per the ratified decision), with `--reverify` forcing the full pass.
"""

import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path

from pydantic import BaseModel, ConfigDict

from ..types import Host
from .recipes import ResolvedRecipe, VarValue
from .verify import DeclarationResult

MANIFEST_FORMAT_VERSION = "1"


def default_build_cache() -> Path:
    """`INSPECT_RANGES_BUILD_CACHE`, or `~/.cache/inspect-ranges/builds`.

    The one source of the builds-cache default, mirroring the image and recipe caches.
    """
    override = os.environ.get("INSPECT_RANGES_BUILD_CACHE")
    if override:
        return Path(override)
    return Path.home() / ".cache" / "inspect-ranges" / "builds"


class RecipeRecord(BaseModel):
    """One provisioning step as the manifest records it (the recipe-references triple plus the vars hash)."""

    model_config = ConfigDict(frozen=True)

    name: str
    version: str
    digest: str
    vars_hash: str


class GuestRecord(BaseModel):
    """One host's build inputs and captured output."""

    model_config = ConfigDict(frozen=True)

    name: str
    golden_reference: str
    golden_digest: str
    realized_file: str
    """Cache file name of the captured realized image (qcow2 backed by the golden)."""

    realized_sha256: str
    build_key: str
    recipes: tuple[RecipeRecord, ...]


class VerificationRecord(BaseModel):
    """The build's verification evidence, cached all-or-nothing."""

    model_config = ConfigDict(frozen=True)

    verified_at: str
    declarations: tuple[DeclarationResult, ...]


class BuildManifest(BaseModel):
    """A built range version: resolved inputs, captured outputs, verification results; never secrets."""

    format_version: str = MANIFEST_FORMAT_VERSION
    range_name: str
    schema_version: str
    spec_sha256: str
    """Canonical hash of the validated spec (the normalized form; comments and formatting never participate)."""

    built_at: str
    build_egress: bool = True
    """Whether build-time egress was granted (it always is today; recorded per the build-v1 decision)."""

    realized_sections: tuple[str, ...] = ("provisioning", "services", "vulnerabilities")
    guests: tuple[GuestRecord, ...]
    verification: VerificationRecord

    def guest(self, name: str) -> GuestRecord | None:
        """The record for `name`, or None."""
        return next((g for g in self.guests if g.name == name), None)


def vars_hash(step_vars: dict[str, VarValue]) -> str:
    """Canonical hash of a step's vars."""
    return hashlib.sha256(
        json.dumps(step_vars, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def spec_projection(host: Host) -> str:
    """Canonical hash of the host's realized-relevant declarations.

    Only the sections the build realizes participate (provisioning, services, vulnerabilities), so edits elsewhere (addresses, resources, notes on other hosts) re-render without rebuilding this guest; the projection principle from the spine's checkpoint decision, applied per guest.
    """
    projected = {
        "provisioning": [step.model_dump(mode="json") for step in host.provisioning],
        "services": [service.model_dump(mode="json") for service in host.services],
        "vulnerabilities": [v.model_dump(mode="json") for v in host.vulnerabilities],
    }
    return hashlib.sha256(
        json.dumps(projected, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def guest_build_key(
    golden_digest: str,
    host: Host,
    recipes: list[tuple[ResolvedRecipe, dict[str, VarValue]]],
) -> str:
    """The guest's build key: golden digest, realized-spec projection, ordered recipe digests and vars.

    The spine's rebuild rule in one value: the key changes exactly when an input that lives inside the realized guest changes.
    """
    parts = [f"golden:{golden_digest}", f"spec:{spec_projection(host)}"]
    for recipe, step_vars in recipes:
        parts.append(f"recipe:{recipe.digest}+vars:{vars_hash(step_vars)}")
    return hashlib.sha256("|".join(parts).encode()).hexdigest()


def realized_file_name(range_name: str, guest: str, build_key: str) -> str:
    """Cache file name for a captured realized image; the key prefix keeps generations distinct."""
    return f"{range_name}-{guest}-{build_key[:12]}.qcow2"


def manifest_path(build_cache: Path, range_name: str) -> Path:
    """Where a range's manifest lives in the builds cache."""
    return build_cache / range_name / "manifest.json"


def save_manifest(manifest: BuildManifest, build_cache: Path) -> Path:
    """Write the manifest atomically (temp then rename); returns its path."""
    path = manifest_path(build_cache, manifest.range_name)
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_suffix(".json.writing")
    temp.write_text(manifest.model_dump_json(indent=2) + "\n")
    temp.replace(path)
    return path


def load_manifest(build_cache: Path, range_name: str) -> BuildManifest | None:
    """The recorded manifest for `range_name`, or None when absent or unreadable (treated as never built)."""
    path = manifest_path(build_cache, range_name)
    try:
        return BuildManifest.model_validate_json(path.read_text())
    except (OSError, ValueError):
        return None


def manifest_matches_spec(manifest: BuildManifest, spec_sha256: str) -> bool:
    """Whether a manifest was built from exactly this (normalized) spec."""
    return manifest.spec_sha256 == spec_sha256


def now_iso() -> str:
    """UTC timestamp in the manifest's format."""
    return datetime.now(timezone.utc).isoformat(timespec="seconds")

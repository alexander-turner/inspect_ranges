"""The range build manifest and the per-guest build keys (build-v1 slice 5).

The manifest is the publishable identity of a built range version (range-build's commitment, the spine's wraps-by-reference decision): every input resolved to digests, recipe `(name, version, digest)` triples with their vars hashes, per-guest realized images with content digests, verification results, and never secrets. It lives in the builds cache (`~/.cache/inspect-ranges/builds/<range>/manifest.json`, `INSPECT_RANGES_BUILD_CACHE`), written atomically.

Invalidation follows the spine's two-key algebra: each guest carries a build key hashing its golden digest, its realized-spec projection (provisioning, services, vulnerabilities, canonically dumped), and its ordered recipe digests and vars. A guest whose key matches the recorded manifest boots from its captured realized image and skips its recipes; a build whose guests all match and whose verification is recorded skips entirely, reporting the cached verification (all-or-nothing per the ratified decision), with `--reverify` forcing the full pass.
"""

import fcntl
import hashlib
import json
import os
import re
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path
from typing import TYPE_CHECKING, Any

from pydantic import BaseModel, ConfigDict

from .._diagnostics import Issue
from ..types import Host, has_guest_content

if TYPE_CHECKING:
    from ..types import RangeSpec
from .recipes import ResolvedRecipe, VarValue
from .verify import DeclarationResult

MANIFEST_FORMAT_VERSION = "1"

_RANGE_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9_-]*$")
"""The schema's own `range.name` grammar (parked-decisions item 5: the strict slug IS the v1 contract everywhere; the spine's org-prefixed one-slash published names arrive with the distribution phase)."""


def validate_range_name(name: str) -> Issue | None:
    """`range.name` against the schema grammar, as defense in depth before the name composes cache paths.

    On every reachable path the schema has already enforced this inside spec validation; this gate is belt-and-braces for direct callers. `..`, slashes, and absolute forms cannot pass, which keeps `manifest_path` and `realized_file_name` inside their caches (the slice-1 traversal lesson, applied to range names).
    """
    if _RANGE_NAME_RE.match(name):
        return None
    return Issue(
        code="range-name-invalid",
        path=("range", "name"),
        message=f"range name {name!r} is not a lowercase slug (letters, digits, `_`, `-`), so it cannot name build artifacts",
        hint="rename the range to the schema grammar; org-prefixed published names arrive with the distribution phase",
    )


def default_build_cache() -> Path:
    """`INSPECT_RANGES_BUILD_CACHE`, or `~/.cache/inspect-ranges/builds`.

    The one source of the builds-cache default, mirroring the image and recipe caches.
    """
    override = os.environ.get("INSPECT_RANGES_BUILD_CACHE")
    if override:
        return Path(override)
    return Path.home() / ".cache" / "inspect-ranges" / "builds"


BUILD_REALIZED_SECTIONS: tuple[str, ...] = (
    "provisioning",
    "services",
    "vulnerabilities",
    "users",
    "misconfigurations",
    "data",
    "roles",
    "defense",
    "active_directory",
)
"""The guest sections a build claims as realized: recipes implement them, the build's behavioral checks prove the chain-load-bearing facts, and declared secret `data` is (re)planted per sample by the challenge layer, so baked defaults never score (linux-examples-v1). Windows-ad-v1 slice 4 adds `roles` (the recipe-selection tags the AD recipes install), `defense` (per-host Defender/update toggles, verifiable in one query), and `active_directory` (identity data reaching recipes via `IR_ACTIVE_DIRECTORY`, hashed into every content guest's build key). `scheduled_activity` stays gated: nothing realizes it. The runtime path without a manifest keeps every gate."""


class BaseImageRecord(BaseModel):
    """One guest's base image resolved to a digest at build time."""

    model_config = ConfigDict(frozen=True)

    guest: str
    kind: str
    reference: str
    file: str
    digest: str


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


class BehavioralCheckRecord(BaseModel):
    """One challenge behavioral check's outcome, as slice 6 records it."""

    model_config = ConfigDict(frozen=True)

    challenge: str
    check: str
    status: str
    detail: str = ""


class VerificationRecord(BaseModel):
    """The build's verification evidence, cached all-or-nothing."""

    model_config = ConfigDict(frozen=True)

    verified_at: str
    declarations: tuple[DeclarationResult, ...]
    behavioral_checks: tuple[BehavioralCheckRecord, ...] = ()
    """Challenge behavioral-check results (reference solution passes, insufficient attempt fails, oracle shortcuts fail); populated by slice 6."""


class BuildManifest(BaseModel):
    """A built range version: resolved inputs, captured outputs, verification results; never secrets."""

    format_version: str = MANIFEST_FORMAT_VERSION
    range_name: str
    schema_version: str
    spec_sha256: str
    """Canonical hash of the validated spec (the normalized form; comments and formatting never participate)."""

    spec: dict[str, object] = {}
    """The validated spec embedded (Journey B's recovery promise: a pulled artifact set recovers to source). Scenario credentials are spec-plaintext by design; per-sample proof material never appears in a spec."""

    project: str = ""
    """The realizer project that produced this build (the stage log and verification evidence live under it)."""

    bundle_sha256: str | None = None
    """Wraps-by-reference slot for a runtime realization bundle built from this manifest; the build itself renders only its transient egress bundle, so this populates when the runtime path renders one (slice 6)."""

    seeds: dict[str, str] = {}
    """Reproducibility seeds (topology randomization); empty until the generation layer draws any. Never proof material."""

    built_at: str
    checks_sha256: str = ""
    """Content digest over the range's behavioral-check inputs (`challenges.yaml` plus everything under `checks/`), or empty when the range declares none. Check scripts are proof tools, not guest content, so they participate in the build's cached-path decision through this digest rather than in any guest build key (slice 6 review)."""

    build_egress: bool = True
    """Whether build-time egress was granted (it always is today; recorded per the build-v1 decision)."""

    realized_sections: tuple[str, ...] = BUILD_REALIZED_SECTIONS
    base_images: tuple[BaseImageRecord, ...] = ()
    """Every guest's base image resolved to a digest at build time (range-build's resolved-inputs commitment)."""

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


@lru_cache(maxsize=8)
def _resolved_plan_for_keys(spec_json: str, image_cache: str) -> "Any":
    """One plan resolution per (spec, cache) for build-key fact extraction; planning is pure, so the cache is sound within a process."""
    from .._compiler.plan import PlanOptions, resolve_plan
    from ..schema import RangeSpec as _RangeSpec

    spec = _RangeSpec.model_validate_json(spec_json)
    # the build realizes the recipe-realizable sections, so this pure key-time
    # resolution lifts the same gates the build render lifts (the runtime
    # path keeps its gates; this plan never boots anything)
    return resolve_plan(
        spec,
        PlanOptions(
            image_cache=Path(image_cache),
            realized_sections=frozenset(BUILD_REALIZED_SECTIONS),
        ),
    )


def windows_key_facts(
    spec: "RangeSpec", guest_name: str, *, image_cache: Path
) -> dict[str, object]:
    """The plan-RESOLVED facts the specialize seed bakes for one Windows guest: `render.windows_seed_facts` over a freshly resolved plan.

    The build key must see what the DISK holds, and the disk holds resolution, not declarations (phase review round 2): resolver addresses come from `dns.authoritative` guests' allocated IPs, gateways from router election and hypervisor-address allocation, sibling routes from non-attached networks. The same function feeds the renderer, so the key and the seed can never drift.
    """
    from .._compiler.render import windows_seed_facts

    plan = _resolved_plan_for_keys(spec.model_dump_json(), str(image_cache))
    guest = next(g for g in plan.guests if g.name == guest_name)
    return windows_seed_facts(plan, guest)


def spec_projection(
    host: Host, *, network_state: dict[str, object] | None = None
) -> str:
    """Canonical hash of the host's realized-relevant declarations.

    Only the sections the build realizes participate (provisioning, services, vulnerabilities), so edits elsewhere (addresses, resources, notes on other hosts) re-render without rebuilding this guest; the projection principle from the spine's checkpoint decision, applied per guest.

    A WINDOWS host's projection also carries its name, interface addressing, and `network_state` (`windows_network_projection`; windows-ad-v1 slice 2, completed by the phase review): the unattend specialize pass runs once on the generalized golden, so the captured realized disk holds the hostname, static addresses, routes, and resolvers PERSISTENTLY — a consumer boot cannot re-apply them the way cloud-init re-seeds a Linux guest. Excluding any of it would let an edit re-render against a disk that still holds the old state, with no rebuild and no refusal; including it makes the edit an honest rebuild. A Windows host with no `network_state` refuses here, fail closed.
    """
    projected: dict[str, object] = {
        "provisioning": [step.model_dump(mode="json") for step in host.provisioning],
        "services": [service.model_dump(mode="json") for service in host.services],
        "vulnerabilities": [v.model_dump(mode="json") for v in host.vulnerabilities],
    }
    # realized-at-build sections join the projection only when declared, so
    # every existing range's hash stays byte-identical (windows-ad-v1 slice 4)
    if host.roles:
        projected["roles"] = list(host.roles)
    if host.defense is not None:
        projected["defense"] = host.defense.model_dump(mode="json")
    if host.os.type == "windows":
        if network_state is None:
            raise ValueError(
                f"guest {host.name!r}: a Windows projection needs the network state "
                "the specialize pass bakes into the disk (windows_network_projection)"
            )
        projected["windows_identity"] = {
            "name": host.name,
            "hostname": host.hostname,
            "fqdn": host.fqdn,
            "interfaces": [
                interface.model_dump(mode="json") for interface in host.interfaces
            ],
            "network_state": network_state,
        }
    return hashlib.sha256(
        json.dumps(projected, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def guest_build_key(
    golden_digest: str,
    host: Host,
    recipes: list[tuple[ResolvedRecipe, dict[str, VarValue]]],
    *,
    range_name: str,
    active_directory_hash: str | None = None,
    network_state: dict[str, object] | None = None,
) -> str:
    """The guest's build key: identity (range and guest names), golden digest, realized-spec projection, ordered recipe digests and vars, and the range's Active Directory hash when one is declared.

    The spine's rebuild rule in one value: the key changes exactly when an input that lives inside the realized guest changes. Identity participates so two ranges (or guests) with byte-identical content never share a key or a realized file name, whose collisions caused last-writer-wins captures and digest-refusal ping-pong (round-1 review); a rename rebuilds, which is correct, names are identity. The AD data is range-scoped and enters EVERY content guest's key (windows-ad-v1 slice 4): a user or ACL edit changes what the domain recipes realize on each member, so no guest may reuse across it.
    """
    parts = [
        f"identity:{range_name}/{host.name}",
        f"golden:{golden_digest}",
        f"spec:{spec_projection(host, network_state=network_state)}",
    ]
    if active_directory_hash is not None:
        parts.append(f"ad:{active_directory_hash}")
    for recipe, step_vars in recipes:
        parts.append(f"recipe:{recipe.digest}+vars:{vars_hash(step_vars)}")
    return hashlib.sha256("|".join(parts).encode()).hexdigest()


def active_directory_hash(spec: "RangeSpec") -> str | None:
    """Canonical hash of the range's declared Active Directory identity data, or None when the range declares none; the range-scoped build-key input (see `guest_build_key`)."""
    if spec.active_directory is None:
        return None
    return hashlib.sha256(
        json.dumps(
            spec.active_directory.model_dump(mode="json"),
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
    ).hexdigest()


def realized_file_name(range_name: str, guest: str, build_key: str) -> str:
    """Cache file name for a captured realized image; the key prefix keeps generations distinct, and a slashed range name flattens (file names are layout, not identity)."""
    return f"{range_name.replace('/', '-')}-{guest}-{build_key[:12]}.qcow2"


def is_catalog_realized(range_name: str, guest: str, build_key: str, file: str) -> bool:
    """Whether a realized sidecar describes a CATALOG-pulled image (standard-images-v1): a build's realized file is always `<range>-<guest>-<key12>.qcow2`, so a renamed landing (`attack.qcow2`) is a promoted catalog image, sticky by design and never the realized tier's reclaim bait (consumers hold no factory manifest to reference it)."""
    return file != realized_file_name(range_name, guest, build_key)


def realized_backings(manifest: "BuildManifest") -> dict[str, tuple[str, str]]:
    """Per-guest (golden cache file, recorded digest) for every realized guest.

    Renderers thread this into `PlanOptions.realized_backings` so boot.json records each realized overlay's BACKING image, and `up` re-verifies it at boot: without it the direct-bundle consumer (`up <bundle>`, and the applier in the separated topology) booted overlay-over-whatever-now-sits-at-the-golden's-name, a composition no build verified (round-2 review).
    """
    from .._compiler.plan import image_file_name

    return {
        record.name: (image_file_name(record.golden_reference), record.golden_digest)
        for record in manifest.guests
    }


def recorded_realized_files(build_cache: Path) -> set[str]:
    """Every realized file name any recorded manifest references (both nesting depths): the liveness set for `images prune` and the superseded annotation in `images list`."""
    files: set[str] = set()
    if not build_cache.is_dir():
        return files
    for manifest_file in list(build_cache.glob("*/manifest.json")) + list(
        build_cache.glob("*/*/manifest.json")
    ):
        try:
            manifest = BuildManifest.model_validate_json(manifest_file.read_text())
        except (OSError, ValueError):
            continue
        files |= {record.realized_file for record in manifest.guests}
    return files


def manifest_path(build_cache: Path, range_name: str) -> Path:
    """Where a range's manifest lives in the builds cache."""
    return build_cache / range_name / "manifest.json"


def save_manifest(manifest: BuildManifest, build_cache: Path) -> Path:
    """Write the manifest atomically (temp then rename) under a per-range lock; returns its path."""
    path = manifest_path(build_cache, manifest.range_name)
    path.parent.mkdir(parents=True, exist_ok=True)
    lock_path = path.parent / ".manifest.lock"
    with open(lock_path, "w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        try:
            temp = path.with_suffix(".json.writing")
            temp.write_text(manifest.model_dump_json(indent=2) + "\n")
            temp.replace(path)
        finally:
            fcntl.flock(lock, fcntl.LOCK_UN)
    return path


def stamp_bundle_sha256(
    build_cache: Path, range_name: str, spec_sha256: str, digest: str
) -> bool:
    """Record a rendered runtime bundle's digest on the manifest it was rendered from (wraps-by-reference), atomically.

    The load-compare-save runs under the same per-range lock as `save_manifest`, and the stamp lands only when the on-disk manifest is still the spec revision the render consumed: a concurrent rebuild must never be clobbered by a stale read-modify-write (round-1 review). Returns whether the stamp landed.
    """
    path = manifest_path(build_cache, range_name)
    if not path.parent.is_dir():
        return False
    lock_path = path.parent / ".manifest.lock"
    with open(lock_path, "w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        try:
            current = load_manifest(build_cache, range_name)
            if current is None or current.spec_sha256 != spec_sha256:
                return False
            temp = path.with_suffix(".json.writing")
            temp.write_text(
                current.model_copy(update={"bundle_sha256": digest}).model_dump_json(
                    indent=2
                )
                + "\n"
            )
            temp.replace(path)
            return True
        finally:
            fcntl.flock(lock, fcntl.LOCK_UN)


def save_refused_manifest(
    refused: "BuildManifest", build_cache: Path, supersedes_built_at: str | None
) -> Path | None:
    """Record a failed proof WITHOUT clobbering a concurrent sibling's manifest (round-2 review).

    Under the per-range lock: the refused manifest lands only when the slot is empty or still holds the revision this build loaded at resolve (`supersedes_built_at`); a manifest a sibling build saved since then stays untouched (the old identity-matched retraction's guarantee, carried into the refused-save shape). Returns the path, or None when a newer manifest was preserved.
    """
    path = manifest_path(build_cache, refused.range_name)
    path.parent.mkdir(parents=True, exist_ok=True)
    lock_path = path.parent / ".manifest.lock"
    with open(lock_path, "w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        try:
            current = load_manifest(build_cache, refused.range_name)
            allowed = {refused.built_at}
            if supersedes_built_at is not None:
                allowed.add(supersedes_built_at)
            if current is not None and current.built_at not in allowed:
                return None
            temp = path.with_suffix(".json.writing")
            temp.write_text(refused.model_dump_json(indent=2) + "\n")
            temp.replace(path)
            return path
        finally:
            fcntl.flock(lock, fcntl.LOCK_UN)


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


def apply_build_manifest(
    spec: "RangeSpec",
    *,
    image_cache: Path,
    build_cache: Path,
) -> "tuple[RangeSpec, frozenset[str], BuildManifest | None]":
    """The build-aware runtime gate (ratified 2026-10-17): consume a matching build manifest, or refuse.

    A spec with no realized-content sections passes through untouched. One with content requires a manifest built from exactly this (normalized) spec whose realized images verify in the cache: hosts then boot their captured realized images and the manifest's sections count as realized at planning. Anything else refuses with `range-not-built`: honest-but-inert became honest-or-built.

    Returns:
        The (possibly swapped) spec, the realized sections for `PlanOptions`, and the consumed manifest (None when the spec carries no content).

    Raises:
        IssueError: `range-not-built` when content is declared and no matching, verifiable build exists.
    """
    from ..types import IssueError  # local: keep module import-light

    content_hosts = [host for host in spec.hosts if has_guest_content(host)]
    if not content_hosts:
        return spec, frozenset(), None

    def refuse(reason: str, hint: str) -> "IssueError":
        return IssueError(
            [
                Issue(
                    code="range-not-built",
                    path=("range", "name"),
                    message=f"range {spec.meta.name!r} declares guest content but {reason}",
                    hint=hint,
                )
            ]
        )

    manifest = load_manifest(build_cache, spec.meta.name)
    if manifest is None:
        raise refuse(
            "no build manifest exists for it",
            "run `inspect-ranges build` first (guest content realizes at build, never at boot)",
        )
    from .._compiler.plan import spec_sha256 as _spec_sha256

    if not manifest_matches_spec(manifest, _spec_sha256(spec)):
        raise refuse(
            "the recorded build is for a different spec revision",
            "the spec, or a schema default affecting its normalized form, changed since the last build; run `inspect-ranges build` again",
        )
    failed_checks = [
        record
        for record in manifest.verification.behavioral_checks
        if record.status != "pass"
    ]
    if failed_checks:
        verdict = failed_checks[0]
        raise IssueError(
            [
                Issue(
                    code="range-unproven",
                    path=("range", "name"),
                    message=(
                        f"range {spec.meta.name!r} is built but its behavioral proof "
                        f"failed ({(verdict.challenge + '/') if verdict.challenge else ''}"
                        f"{verdict.check}: {verdict.detail})"
                    ),
                    hint="fix the failing check or chain and run `inspect-ranges build` again (guests are reused; only the proof re-runs)",
                )
            ]
        )
    swapped, sections = swap_realized_spec(spec, manifest, image_cache=image_cache)
    return swapped, sections, manifest


def _realized_sidecar_digest(image_cache: Path, realized_file: str) -> str | None:
    """The `.realized.json` sidecar's recorded digest, or `None` (absent/unreadable sidecars fall back to a full hash)."""
    sidecar = image_cache / (realized_file.removesuffix(".qcow2") + ".realized.json")
    try:
        recorded = json.loads(sidecar.read_text()).get("sha256")
    except (OSError, ValueError):
        return None
    return recorded if isinstance(recorded, str) else None


def _golden_digest_sidecar_first(
    reference: str, image_cache: Path | None
) -> str | None:
    """A golden's digest by its provenance sidecar when present (boot re-verifies bytes), else the full-hash resolution."""
    from .._compiler.plan import image_file_name, resolve_image_reference

    if image_cache is not None:
        file = image_file_name(reference)
        if (image_cache / file).is_file():
            sidecar = image_cache / (file.removesuffix(".qcow2") + ".json")
            try:
                recorded = json.loads(sidecar.read_text()).get("golden_sha256")
            except (OSError, ValueError):
                recorded = None
            if isinstance(recorded, str) and recorded:
                return f"sha256:{recorded}"
    return resolve_image_reference(reference, image_cache).digest


def swap_realized_spec(
    spec: "RangeSpec",
    manifest: "BuildManifest",
    *,
    image_cache: Path,
) -> "tuple[RangeSpec, frozenset[str]]":
    """The gate's consumption step on an already-matched manifest: every content host boots its digest-verified realized image.

    Also used by the build's behavioral phase on the not-yet-saved manifest (the checks must prove the captured artifacts before any manifest becomes consumable), which is why this takes the manifest object rather than loading one.

    Raises:
        IssueError: `range-not-built` when a content host has no record, or a realized image is missing from the cache or fails its digest.
    """
    import hashlib as _hashlib

    from ..types import IssueError
    from ..types import RangeSpec as _RangeSpec

    def refuse(reason: str, hint: str) -> "IssueError":
        return IssueError(
            [
                Issue(
                    code="range-not-built",
                    path=("range", "name"),
                    message=f"range {spec.meta.name!r} declares guest content but {reason}",
                    hint=hint,
                )
            ]
        )

    swapped = spec.model_copy(deep=True)
    golden_digests: dict[str, str | None] = {}
    for host in swapped.hosts:
        record = manifest.guest(host.name)
        if record is None:
            if has_guest_content(host):
                raise refuse(
                    f"its build manifest has no record for guest {host.name!r}",
                    "run `inspect-ranges build` again",
                )
            continue
        # the realized image is an overlay whose backing is the golden BY NAME,
        # and goldens re-derive in place under the same cache name (recipe
        # bumps, daemon updates), so the chain of trust must re-check the
        # golden too or an unverified composition boots under a proven claim
        # (round-1 review)
        if record.golden_reference not in golden_digests:
            golden_digests[record.golden_reference] = _golden_digest_sidecar_first(
                record.golden_reference, image_cache
            )
        golden_digest = golden_digests[record.golden_reference]
        if golden_digest is None:
            raise refuse(
                f"the golden image {record.golden_reference!r} backing guest {host.name!r} is not in the image cache",
                "re-derive the golden, or pull the build artifacts into the cache",
            )
        if golden_digest != record.golden_digest:
            raise refuse(
                f"the golden image {record.golden_reference!r} backing guest {host.name!r} changed since the build",
                "the realized overlay would boot over a composition that was never verified; rebuild, or finish/revert the golden's move (an interrupted images refresh re-runs; a deliberate one wants a rebuild against the new golden)",
            )
        realized = image_cache / record.realized_file
        if not realized.is_file():
            raise refuse(
                f"the realized image {record.realized_file!r} for guest {host.name!r} is not in the image cache",
                "rebuild, or pull the build artifacts into the cache",
            )
        # the sidecar discipline (Journey B, slice-4 round-4 B2): the gate
        # checks presence and the sidecar's recorded digest against the
        # manifest instead of re-hashing multi-GB bytes per eval; BYTE
        # integrity is still verified on every boot by up's verify-images,
        # which hashes the actual files against these same digests, so a
        # corrupt cache refuses at boot with a named cause either way
        sidecar_digest = _realized_sidecar_digest(image_cache, record.realized_file)
        if sidecar_digest != record.realized_sha256:
            hasher = _hashlib.sha256()
            with open(realized, "rb") as handle:
                for chunk in iter(lambda: handle.read(1 << 22), b""):
                    hasher.update(chunk)
            if hasher.hexdigest() != record.realized_sha256:
                raise refuse(
                    f"the realized image for guest {host.name!r} does not match the manifest's digest",
                    "the cache copy changed since the build; rebuild",
                )
        host.image = record.realized_file
    assert isinstance(swapped, _RangeSpec)
    return swapped, frozenset(manifest.realized_sections)

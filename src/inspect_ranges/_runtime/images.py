"""Golden image derivation and the image cache (realizer-v1 slice 1).

A golden is a qcow2 overlay on a digest-pinned vendor cloud image with the guest control daemon baked in and every network listener disabled. Derivation is offline-only (`virt-customize --no-network`; package installation belongs to the build pipeline, per the net-compile spike) and idempotent: the derivation key hashes the recipe version, the vendor digest, and the daemon digest, and a cache hit skips all work. Nothing is written to the cache before the vendor image verifies.

The daemon arrives as the channel track's `daemon-bundle` artifact: a byte-deterministic tarball verified against its `daemon.json` sidecar by bundle digest before any member is extracted (`inspect-ranges daemon-bundle` builds it). The bake uses the bundle's own binary and unit file, and the bundle digest lands in the derivation key and the golden's provenance, per the chunk-1 decision.
"""

import fcntl
import hashlib
import logging
import os
import shutil
import subprocess
import tarfile
import tempfile
from collections.abc import Callable, Generator
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

from pydantic import BaseModel, ConfigDict

from .._channel.bundle import (
    BundleError,
    DaemonBundleInfo,
    bundle_file_name,
    verify_daemon_bundle,
)
from .._channel.protocol import PROTOCOL_VERSION
from .._compiler.plan import image_file_name, image_sidecar_file_name

logger = logging.getLogger(__name__)

RECIPE_VERSION = "4"
"""Bumping this invalidates every derived golden (it is part of the derivation key)."""


def default_image_cache() -> Path:
    """`INSPECT_RANGES_IMAGE_CACHE`, or `~/.cache/inspect-ranges/images`.

    The one source of the image-cache default: the provider, doctor, applier, and every CLI command resolve through here, so the knob cannot drift per surface.
    """
    override = os.environ.get("INSPECT_RANGES_IMAGE_CACHE")
    if override:
        return Path(override)
    return Path.home() / ".cache" / "inspect-ranges" / "images"


Runner = Callable[[list[str], Path], None]
"""Executes an external command (argv, cwd); raises `CalledProcessError` on failure."""


class DaemonPin(BaseModel):
    """The digest-pinned guest control daemon baked into goldens."""

    model_config = ConfigDict(frozen=True)

    name: str
    version: str
    sha256: str


DEFAULT_ARTIFACT_DIR = Path.home() / ".cache" / "inspect-ranges" / "artifacts"
"""Where `inspect-ranges daemon-bundle -o` conventionally publishes, and where derive looks by default."""


class ImageMetadata(BaseModel):
    """Provenance sidecar (`<name>.json`) for a derived golden in the image cache."""

    name: str
    file: str
    recipe_version: str
    derivation_key: str
    vendor_file: str
    vendor_sha256: str
    daemon: DaemonPin
    golden_sha256: str
    created: str
    admin_password: str | None = None
    """Windows goldens only: the built-in Administrator password baked at install (deliberate, LOCAL-ONLY scenario content; the control plane is the vsock daemon as SYSTEM). Render reads it to answer the per-boot OOBE pass."""


class DeriveError(Exception):
    """Derivation failure, naming the stage that failed."""

    def __init__(self, stage: str, message: str) -> None:
        self.stage = stage
        super().__init__(f"[{stage}] {message}")


_RESOLVED_DROPIN = "[Resolve]\nDNSStubListener=no\nLLMNR=no\nMulticastDNS=no\n"


def sha256_file(path: Path) -> str:
    """Hex sha256 of a file, streamed."""
    hasher = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 22), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def resolve_daemon_bundle(
    artifact_dir: Path, expected_sha256: str | None = None
) -> tuple[Path, DaemonBundleInfo]:
    """Locate and verify the daemon-bundle artifact against its sidecar, and against an out-of-band pin when one is given.

    Trust model: the sidecar lives next to the tarball, so sidecar verification alone proves internal consistency, not provenance (whoever can write the artifact directory can rewrite both). Passing `expected_sha256` (the digest `daemon-bundle` printed at publish time) restores the out-of-band pin; the batteries and any unattended derivation should always pass it.

    Raises:
        DeriveError: The artifact or its sidecar is absent, unreadable, protocol-skewed, pin-mismatched, or fails verification; the hint names the command that publishes it.
    """
    sidecar = artifact_dir / "daemon.json"
    if not sidecar.is_file():
        raise DeriveError(
            "resolve-daemon",
            f"no daemon artifact at {artifact_dir} (build one: inspect-ranges daemon-bundle -o {artifact_dir})",
        )
    try:
        info = DaemonBundleInfo.model_validate_json(sidecar.read_text())
    except (OSError, ValueError) as error:
        raise DeriveError(
            "resolve-daemon", f"daemon.json is unreadable or malformed: {error}"
        ) from error
    bundle_path = artifact_dir / bundle_file_name(info.version)
    if not bundle_path.is_file():
        raise DeriveError(
            "resolve-daemon",
            f"daemon bundle missing: {bundle_path} (republish: inspect-ranges daemon-bundle -o {artifact_dir})",
        )
    if expected_sha256 is None:
        logger.warning(
            "daemon artifact unpinned: sidecar-only verification; pass --daemon-sha256 for out-of-band pinning"
        )
    if expected_sha256 is not None:
        pin = expected_sha256.removeprefix("sha256:").lower()
        if info.bundle_sha256 != pin:
            raise DeriveError(
                "resolve-daemon",
                f"daemon bundle digest {info.bundle_sha256} does not match the pin {pin} (republish: inspect-ranges daemon-bundle -o {artifact_dir})",
            )
    if info.protocol != PROTOCOL_VERSION:
        raise DeriveError(
            "resolve-daemon",
            f"daemon bundle speaks protocol {info.protocol}; this build requires {PROTOCOL_VERSION}",
        )
    try:
        verify_daemon_bundle(bundle_path, info)
    except BundleError as error:
        raise DeriveError(
            "resolve-daemon",
            f"{error} (republish: inspect-ranges daemon-bundle -o {artifact_dir})",
        ) from error
    return bundle_path, info


def _extract_daemon(bundle_path: Path, staging: Path) -> tuple[Path, Path]:
    """Extract the verified bundle's binary and unit into `staging`; returns their paths."""
    with tarfile.open(bundle_path, mode="r:") as tar:
        for member in ("linux/vsockd", "linux/vsockd.service"):
            try:
                handle = tar.extractfile(member)
            except KeyError as error:
                raise DeriveError(
                    "resolve-daemon",
                    f"bundle lacks required member {member} (a foreign layout verifies against its own sidecar but is not consumable here)",
                ) from error
            if handle is None:
                raise DeriveError(
                    "resolve-daemon", f"bundle member unreadable: {member}"
                )
            target = staging / Path(member).name
            target.write_bytes(handle.read())
    return staging / "vsockd", staging / "vsockd.service"


def _run(argv: list[str], cwd: Path) -> None:
    result = subprocess.run(argv, cwd=cwd, capture_output=True, text=True)
    if result.returncode != 0:
        raise subprocess.CalledProcessError(
            result.returncode, argv, result.stdout, result.stderr
        )


def _cache_file_name(name: str) -> str:
    # one naming rule with planning's image resolution (realizer-v1 chunk 1 note)
    return image_file_name(name)


def _metadata_path(cache: Path, file: str) -> Path:
    # one naming rule with the compiler, which reads recorded metadata at render
    return cache / image_sidecar_file_name(file)


def _load_metadata(path: Path) -> "ImageMetadata | None":
    """A sidecar's metadata, or None when it is unreadable (treated as stale)."""
    try:
        return ImageMetadata.model_validate_json(path.read_text())
    except (OSError, ValueError):
        return None


def derive_golden(
    vendor: Path,
    vendor_sha256: str,
    cache: Path,
    name: str | None = None,
    runner: Runner | None = None,
    artifact_dir: Path | None = None,
    daemon_sha256: str | None = None,
) -> tuple[ImageMetadata, bool]:
    """Derive a daemon-baked golden overlay from a digest-pinned vendor image.

    The vendor image is verified against `vendor_sha256` before anything is written. The golden is a relative-backing qcow2 overlay in `cache` (the cache mounts as one directory in the range container, so backing references must be relative), customized offline: daemon installed and enabled, ssh and the resolved stub listener disabled, `systemd-networkd-wait-online` masked, cloud-init left enabled for the per-guest seed.

    Args:
        vendor: The vendor cloud image. Copied into the cache atomically when absent; an in-cache copy that no longer matches the pin is replaced from this verified source.
        vendor_sha256: Required pin, hex or `sha256:`-prefixed.
        cache: The image cache directory (created if absent).
        name: Golden name; defaults to `<vendor stem>-golden`.
        runner: Command executor, injectable for tests; defaults to `subprocess.run` with check.
        artifact_dir: Where the daemon-bundle artifact lives; defaults to the shared artifact cache.
        daemon_sha256: Out-of-band pin for the bundle digest (what `daemon-bundle` printed at publish); without it the sidecar proves internal consistency only.

    Returns:
        The golden's metadata and whether the cache already satisfied the request. A hit requires the recorded golden digest and the in-cache vendor pin to both verify; a tampered in-cache vendor logs a warning and re-derives.

    Raises:
        DeriveError: Stage-named failure: vendor missing or digest mismatch, daemon pin mismatch, an unmanaged file or non-conforming sidecar squatting on the target name, a missing host tool, or a failed derivation command (nothing is left behind in the cache).
    """
    base_run = runner or _run

    def run(stage: str, argv: list[str], cwd: Path) -> None:
        try:
            base_run(argv, cwd)
        except FileNotFoundError as error:
            raise DeriveError(stage, f"{argv[0]} not found on this host") from error
        except subprocess.CalledProcessError as error:
            raise DeriveError(stage, f"{argv[0]} failed: {error.stderr}") from error

    expected = vendor_sha256.removeprefix("sha256:").lower()

    if not vendor.is_file():
        raise DeriveError("verify-vendor", f"vendor image not found: {vendor}")
    actual = sha256_file(vendor)
    if actual != expected:
        raise DeriveError(
            "verify-vendor",
            f"vendor image digest mismatch for {vendor.name}: expected {expected}, found {actual}",
        )

    bundle_path, daemon_info = resolve_daemon_bundle(
        artifact_dir if artifact_dir is not None else DEFAULT_ARTIFACT_DIR,
        expected_sha256=daemon_sha256,
    )

    golden_name = name or f"{Path(vendor.name).stem}-golden"
    file = _cache_file_name(golden_name)
    key_material = (
        f"recipe:{RECIPE_VERSION}|vendor:{expected}|daemon:{daemon_info.bundle_sha256}"
    )
    key = hashlib.sha256(key_material.encode()).hexdigest()

    cache.mkdir(parents=True, exist_ok=True)
    golden_path = cache / file
    metadata_path = _metadata_path(cache, file)

    from .._dist.gc import chains_lock

    # shared with the GC's exclusive scan (distribution round-5 B2): a derive
    # landing vendor-then-golden must never look like an orphan mid-flight
    with chains_lock(cache, exclusive=False), _name_lock(cache, file):
        return _derive_locked(
            run,
            vendor,
            expected,
            cache,
            golden_name,
            file,
            key,
            golden_path,
            metadata_path,
            bundle_path,
            daemon_info,
        )


@contextmanager
def _name_lock(cache: Path, file: str) -> Generator[None]:
    """Per-name advisory lock so concurrent derives of one golden cannot interleave temps."""
    lock_path = cache / f".{file}.lock"
    with open(lock_path, "w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(lock, fcntl.LOCK_UN)


def _derive_locked(
    run: "Callable[[str, list[str], Path], None]",
    vendor: Path,
    expected: str,
    cache: Path,
    golden_name: str,
    file: str,
    key: str,
    golden_path: Path,
    metadata_path: Path,
    bundle_path: Path,
    daemon_info: DaemonBundleInfo,
) -> tuple[ImageMetadata, bool]:
    # a crashed prior derive of this name may have left temps; we hold the lock
    temp = cache / f".{file}.deriving"
    metadata_temp = metadata_path.with_suffix(".json.deriving")
    temp.unlink(missing_ok=True)
    metadata_temp.unlink(missing_ok=True)

    if metadata_path.is_file():
        existing = _load_metadata(metadata_path)
        if existing is None:
            # non-conforming sidecar: unmanaged, exactly as `images list` reports it
            raise DeriveError(
                "prepare",
                f"{metadata_path} is not a valid provenance sidecar (unmanaged); refusing to touch it, remove it to re-derive",
            )
        if (
            existing.derivation_key == key
            and golden_path.is_file()
            and sha256_file(golden_path) == existing.golden_sha256
        ):
            # the hit must also stand on an untampered backing file: the
            # overlay reads vendor bytes at boot, and the cache is local
            # working state, not a signed artifact
            vendor_cached = cache / existing.vendor_file
            if (
                vendor_cached.is_file()
                and sha256_file(vendor_cached) == existing.vendor_sha256
            ):
                return existing, True
            logger.warning(
                "in-cache vendor %s no longer matches its pin; re-deriving from the verified source",
                vendor_cached,
            )
    elif golden_path.exists():
        raise DeriveError(
            "prepare",
            f"{golden_path} exists without metadata (unmanaged); refusing to overwrite",
        )

    vendor_in_cache = cache / vendor.name
    if vendor_in_cache.resolve() != vendor.resolve():
        if not vendor_in_cache.is_file() or sha256_file(vendor_in_cache) != expected:
            # atomic: a kill mid-copy must never leave a partial vendor the
            # next derive would refuse forever. The source re-verified above.
            vendor_temp = cache / f".{vendor.name}.{os.getpid()}.deriving"
            try:
                shutil.copy2(vendor, vendor_temp)
                vendor_temp.replace(vendor_in_cache)
            finally:
                vendor_temp.unlink(missing_ok=True)

    try:
        run(
            "create-overlay",
            [
                "qemu-img",
                "create",
                "-f",
                "qcow2",
                "-F",
                "qcow2",
                "-b",
                vendor.name,
                temp.name,
                "10G",
            ],
            cache,
        )

        with tempfile.TemporaryDirectory() as staging_dir:
            staging = Path(staging_dir)
            daemon_binary, daemon_unit = _extract_daemon(bundle_path, staging)
            (staging / "no-stub.conf").write_text(_RESOLVED_DROPIN)
            run(
                "customize",
                [
                    "virt-customize",
                    "-a",
                    temp.name,
                    "--no-network",
                    # the daemon's unprivileged default identity for exec and
                    # file operations (provider-v1 slice 4)
                    "--run-command",
                    "useradd --create-home --home-dir /home/agent --shell /bin/sh agent",
                    "--mkdir",
                    "/opt/inspect-ranges",
                    "--copy-in",
                    f"{daemon_binary}:/opt/inspect-ranges",
                    "--chmod",
                    "0755:/opt/inspect-ranges/vsockd",
                    "--copy-in",
                    f"{daemon_unit}:/etc/systemd/system",
                    "--link",
                    "/etc/systemd/system/vsockd.service:/etc/systemd/system/multi-user.target.wants/vsockd.service",
                    "--link",
                    "/dev/null:/etc/systemd/system/systemd-networkd-wait-online.service",
                    "--link",
                    "/dev/null:/etc/systemd/system/ssh.service",
                    "--link",
                    "/dev/null:/etc/systemd/system/ssh.socket",
                    "--mkdir",
                    "/etc/systemd/resolved.conf.d",
                    "--copy-in",
                    f"{staging / 'no-stub.conf'}:/etc/systemd/resolved.conf.d",
                    "--link",
                    "/run/systemd/resolve/resolv.conf:/etc/resolv.conf",
                ],
                cache,
            )

        metadata = ImageMetadata(
            name=golden_name,
            file=file,
            recipe_version=RECIPE_VERSION,
            derivation_key=key,
            vendor_file=vendor.name,
            vendor_sha256=expected,
            daemon=DaemonPin(
                name=daemon_info.name,
                version=daemon_info.version,
                sha256=daemon_info.bundle_sha256,
            ),
            golden_sha256=sha256_file(temp),
            created=datetime.now(timezone.utc).isoformat(timespec="seconds"),
        )
        # sidecar lands first: a crash between the two renames leaves metadata
        # pointing at a missing or stale golden, which the next derive repairs,
        # never a provenance-less golden the tool would refuse as unmanaged
        metadata_temp.write_text(metadata.model_dump_json(indent=2) + "\n")
        metadata_temp.replace(metadata_path)
        temp.replace(golden_path)
        return metadata, False
    finally:
        temp.unlink(missing_ok=True)
        metadata_temp.unlink(missing_ok=True)


class RealizedListing(BaseModel):
    """A build-captured realized image as `images list` reports it (shape-matched from its `.realized.json` sidecar; the build package owns the full model, and the boundary forbids importing it here)."""

    file: str
    range_name: str
    guest: str
    build_key: str
    created: str


def _load_realized(sidecar: Path) -> "RealizedListing | None":
    try:
        import json
        from typing import cast

        loaded: object = json.loads(sidecar.read_text())
        if not isinstance(loaded, dict):
            return None
        data = cast(dict[str, object], loaded)
        if data.get("type") != "realized":
            return None
        return RealizedListing(
            file=sidecar.name.removesuffix(".realized.json") + ".qcow2",
            range_name=str(data["range_name"]),
            guest=str(data["guest"]),
            build_key=str(data["build_key"]),
            created=str(data["created"]),
        )
    except (OSError, ValueError, KeyError):
        return None


def list_images(
    cache: Path,
) -> tuple[list[ImageMetadata], list[RealizedListing], list[str]]:
    """The cache's managed goldens, build-captured realized images, and unmanaged files.

    Args:
        cache: The image cache directory.

    Returns:
        Managed golden metadata sorted by name, realized listings sorted by file, and unmanaged image file names sorted.
    """
    if not cache.is_dir():
        return [], [], []
    managed: list[ImageMetadata] = []
    managed_files: set[str] = set()
    realized: list[RealizedListing] = []
    for sidecar in sorted(cache.glob("*.realized.json")):
        listing = _load_realized(sidecar)
        if listing is not None and (cache / listing.file).is_file():
            realized.append(listing)
            managed_files.add(listing.file)
    for sidecar in sorted(cache.glob("*.json")):
        if sidecar.name.endswith(".realized.json"):
            continue
        metadata = _load_metadata(sidecar)
        if metadata is None:
            continue  # corrupt sidecar: its image surfaces as unmanaged below
        managed.append(metadata)
        managed_files.add(metadata.file)
        managed_files.add(metadata.vendor_file)
    unmanaged = sorted(
        path.name
        for path in cache.iterdir()
        if path.is_file()
        and (
            path.suffix in (".qcow2", ".img", ".iso")
            or path.name.endswith(".deriving")
            # a crash mid-capture strands a multi-GB `.capturing` temp that the
            # next capture of the SAME name would clean, but a post-crash fix
            # usually changes the build key, so listing must surface it (round-1)
            or path.name.endswith(".capturing")
            # same lesson for a hard-killed pull's `.{name}.pulling-*` temp
            # (the next pull of that name sweeps it, but listing must see it)
            or ".pulling-" in path.name
        )
        and path.name not in managed_files
    )
    return managed, realized, unmanaged

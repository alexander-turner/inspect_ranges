"""Golden image derivation and the image cache (realizer-v1 slice 1).

A golden is a qcow2 overlay on a digest-pinned vendor cloud image with the guest control daemon baked in and every network listener disabled. Derivation is offline-only (`virt-customize --no-network`; package installation belongs to the build pipeline, per the net-compile spike) and idempotent: the derivation key hashes the recipe version, the vendor digest, and the daemon digest, and a cache hit skips all work. Nothing is written to the cache before the vendor image verifies.

The daemon arrives as a pinned artifact (name, version, sha256). Until the channel track publishes its v3 `daemon-bundle`, the pin is the spike v2 daemon vendored as package data; consumption is digest-based either way, so the swap is a pin update.
"""

import fcntl
import hashlib
import logging
import os
import shutil
import subprocess
import tempfile
from collections.abc import Callable, Generator
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

from pydantic import BaseModel, ConfigDict

logger = logging.getLogger(__name__)

RECIPE_VERSION = "2"
"""Bumping this invalidates every derived golden (it is part of the derivation key)."""

Runner = Callable[[list[str], Path], None]
"""Executes an external command (argv, cwd); raises `CalledProcessError` on failure."""


class DaemonPin(BaseModel):
    """The digest-pinned guest control daemon baked into goldens."""

    model_config = ConfigDict(frozen=True)

    name: str
    version: str
    sha256: str


PINNED_DAEMON = DaemonPin(
    name="vsockd",
    version="2",
    sha256="3657f7855fcc660c870fe5e3018bdd9c84e72ef0d951f362e89ef9a30d1e75b7",
)
"""The spike v2 daemon, pinned until the channel track's Go daemon-bundle replaces it."""


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


class DeriveError(Exception):
    """Derivation failure, naming the stage that failed."""

    def __init__(self, stage: str, message: str) -> None:
        self.stage = stage
        super().__init__(f"[{stage}] {message}")


_UNIT = """[Unit]
Description=inspect-ranges guest control daemon
[Service]
ExecStart=/usr/bin/python3 /opt/inspect-ranges/vsockd2.py
Restart=always
[Install]
WantedBy=multi-user.target
"""

_RESOLVED_DROPIN = "[Resolve]\nDNSStubListener=no\nLLMNR=no\nMulticastDNS=no\n"


def sha256_file(path: Path) -> str:
    """Hex sha256 of a file, streamed."""
    hasher = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 22), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def daemon_source() -> Path:
    """Path of the pinned daemon, verified against `PINNED_DAEMON` before every use.

    Raises:
        DeriveError: The packaged daemon does not match the pin (corrupt or tampered install).
    """
    path = Path(__file__).parent / "daemon" / "vsockd2.py"
    if not path.is_file():
        raise DeriveError("resolve-daemon", f"pinned daemon missing at {path}")
    actual = sha256_file(path)
    if actual != PINNED_DAEMON.sha256:
        raise DeriveError(
            "resolve-daemon",
            f"daemon artifact digest mismatch: pinned {PINNED_DAEMON.sha256}, found {actual}",
        )
    return path


def _run(argv: list[str], cwd: Path) -> None:
    result = subprocess.run(argv, cwd=cwd, capture_output=True, text=True)
    if result.returncode != 0:
        raise subprocess.CalledProcessError(
            result.returncode, argv, result.stdout, result.stderr
        )


def _cache_file_name(name: str) -> str:
    normalized = name.replace("/", "-").replace(":", "-")
    return normalized if normalized.endswith(".qcow2") else f"{normalized}.qcow2"


def _metadata_path(cache: Path, file: str) -> Path:
    # full name, not Path.stem: golden names may contain dots
    return cache / (file.removesuffix(".qcow2") + ".json")


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
) -> tuple[ImageMetadata, bool]:
    """Derive a daemon-baked golden overlay from a digest-pinned vendor image.

    The vendor image is verified against `vendor_sha256` before anything is written. The golden is a relative-backing qcow2 overlay in `cache` (the cache mounts as one directory in the range container, so backing references must be relative), customized offline: daemon installed and enabled, ssh and the resolved stub listener disabled, `systemd-networkd-wait-online` masked, cloud-init left enabled for the per-guest seed.

    Args:
        vendor: The vendor cloud image. Copied into the cache atomically when absent; an in-cache copy that no longer matches the pin is replaced from this verified source.
        vendor_sha256: Required pin, hex or `sha256:`-prefixed.
        cache: The image cache directory (created if absent).
        name: Golden name; defaults to `<vendor stem>-golden`.
        runner: Command executor, injectable for tests; defaults to `subprocess.run` with check.

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

    daemon = daemon_source()

    golden_name = name or f"{Path(vendor.name).stem}-golden"
    file = _cache_file_name(golden_name)
    key_material = (
        f"recipe:{RECIPE_VERSION}|vendor:{expected}|daemon:{PINNED_DAEMON.sha256}"
    )
    key = hashlib.sha256(key_material.encode()).hexdigest()

    cache.mkdir(parents=True, exist_ok=True)
    golden_path = cache / file
    metadata_path = _metadata_path(cache, file)

    with _name_lock(cache, file):
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
            daemon,
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
    daemon: Path,
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
            (staging / "vsockd.service").write_text(_UNIT)
            (staging / "no-stub.conf").write_text(_RESOLVED_DROPIN)
            run(
                "customize",
                [
                    "virt-customize",
                    "-a",
                    temp.name,
                    "--no-network",
                    "--mkdir",
                    "/opt/inspect-ranges",
                    "--copy-in",
                    f"{daemon}:/opt/inspect-ranges",
                    "--chmod",
                    "0755:/opt/inspect-ranges/vsockd2.py",
                    "--copy-in",
                    f"{staging / 'vsockd.service'}:/etc/systemd/system",
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
            daemon=PINNED_DAEMON,
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


def list_images(cache: Path) -> tuple[list[ImageMetadata], list[str]]:
    """The cache's managed goldens (with provenance) and unmanaged files (no metadata sidecar).

    Args:
        cache: The image cache directory.

    Returns:
        Managed metadata sorted by name, and unmanaged image file names sorted.
    """
    if not cache.is_dir():
        return [], []
    managed: list[ImageMetadata] = []
    managed_files: set[str] = set()
    for sidecar in sorted(cache.glob("*.json")):
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
            path.suffix in (".qcow2", ".img", ".iso") or path.name.endswith(".deriving")
        )
        and path.name not in managed_files
    )
    return managed, unmanaged

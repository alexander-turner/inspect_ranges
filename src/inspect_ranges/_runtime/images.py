"""Golden image derivation and the image cache (realizer-v1 slice 1).

A golden is a qcow2 overlay on a digest-pinned vendor cloud image with the guest control daemon baked in and every network listener disabled. Derivation is offline-only (`virt-customize --no-network`; package installation belongs to the build pipeline, per the net-compile spike) and idempotent: the derivation key hashes the recipe version, the vendor digest, and the daemon digest, and a cache hit skips all work. Nothing is written to the cache before the vendor image verifies.

The daemon arrives as a pinned artifact (name, version, sha256). Until the channel track publishes its v3 `daemon-bundle`, the pin is the spike v2 daemon vendored as package data; consumption is digest-based either way, so the swap is a pin update.
"""

import hashlib
import shutil
import subprocess
import tempfile
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path

from pydantic import BaseModel, ConfigDict

RECIPE_VERSION = "1"
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

_RESOLVED_DROPIN = "[Resolve]\nDNSStubListener=no\n"


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
    return (
        (name if "." in Path(name).name else f"{name}.qcow2")
        .replace("/", "-")
        .replace(":", "-")
    )


def _metadata_path(cache: Path, file: str) -> Path:
    return cache / (Path(file).stem + ".json")


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
        vendor: The vendor cloud image. Copied into the cache if not already there.
        vendor_sha256: Required pin, hex or `sha256:`-prefixed.
        cache: The image cache directory (created if absent).
        name: Golden name; defaults to `<vendor stem>-golden`.
        runner: Command executor, injectable for tests; defaults to `subprocess.run` with check.

    Returns:
        The golden's metadata and whether the cache already satisfied the request (hit skips all work).

    Raises:
        DeriveError: Stage-named failure: vendor missing or digest mismatch, daemon pin mismatch, an unmanaged file squatting on the target name, or a failed derivation command (nothing is left behind in the cache).
    """
    run = runner or _run
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

    golden_name = name or f"{vendor.name.split('.')[0]}-golden"
    file = _cache_file_name(golden_name)
    key_material = (
        f"recipe:{RECIPE_VERSION}|vendor:{expected}|daemon:{PINNED_DAEMON.sha256}"
    )
    key = hashlib.sha256(key_material.encode()).hexdigest()

    cache.mkdir(parents=True, exist_ok=True)
    golden_path = cache / file
    metadata_path = _metadata_path(cache, file)

    if metadata_path.is_file():
        existing = ImageMetadata.model_validate_json(metadata_path.read_text())
        if (
            existing.derivation_key == key
            and golden_path.is_file()
            and sha256_file(golden_path) == existing.golden_sha256
        ):
            return existing, True
    elif golden_path.exists():
        raise DeriveError(
            "prepare",
            f"{golden_path} exists without metadata (unmanaged); refusing to overwrite",
        )

    vendor_in_cache = cache / vendor.name
    if vendor_in_cache.resolve() != vendor.resolve():
        if vendor_in_cache.is_file() and sha256_file(vendor_in_cache) != expected:
            raise DeriveError(
                "prepare",
                f"{vendor_in_cache} exists with a different digest; refusing to overwrite",
            )
        if not vendor_in_cache.is_file():
            shutil.copy2(vendor, vendor_in_cache)

    temp = cache / f".{file}.deriving"
    try:
        try:
            run(
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
        except subprocess.CalledProcessError as error:
            raise DeriveError(
                "create-overlay", f"qemu-img failed for {file}: {error.stderr}"
            ) from error

        with tempfile.TemporaryDirectory() as staging_dir:
            staging = Path(staging_dir)
            (staging / "vsockd.service").write_text(_UNIT)
            (staging / "no-stub.conf").write_text(_RESOLVED_DROPIN)
            try:
                run(
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
            except subprocess.CalledProcessError as error:
                raise DeriveError(
                    "customize", f"virt-customize failed for {file}: {error.stderr}"
                ) from error

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
        temp.replace(golden_path)
        metadata_temp = metadata_path.with_suffix(".json.deriving")
        metadata_temp.write_text(metadata.model_dump_json(indent=2) + "\n")
        metadata_temp.replace(metadata_path)
        return metadata, False
    finally:
        temp.unlink(missing_ok=True)


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
        metadata = ImageMetadata.model_validate_json(sidecar.read_text())
        managed.append(metadata)
        managed_files.add(metadata.file)
        managed_files.add(metadata.vendor_file)
    unmanaged = sorted(
        path.name
        for path in cache.iterdir()
        if path.is_file()
        and path.suffix in (".qcow2", ".img", ".iso")
        and path.name not in managed_files
    )
    return managed, unmanaged

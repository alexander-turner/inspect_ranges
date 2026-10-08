"""Golden derivation behavior through the public `derive_golden`/`list_images` surface, with the external commands faked."""

import hashlib
import json
import subprocess
from pathlib import Path

import pytest
from inspect_ranges._runtime import DeriveError, derive_golden, list_images
from inspect_ranges._runtime.images import PINNED_DAEMON, daemon_source, sha256_file


def fake_runner(argv: list[str], cwd: Path) -> None:
    """Stands in for qemu-img/virt-customize: creates or appends to the target overlay."""
    if argv[0] == "qemu-img":
        (cwd / argv[-2]).write_bytes(b"overlay:" + argv[argv.index("-b") + 1].encode())
    elif argv[0] == "virt-customize":
        target = cwd / argv[argv.index("-a") + 1]
        target.write_bytes(target.read_bytes() + b"|customized")
    else:  # pragma: no cover - unexpected command is a test bug
        raise AssertionError(f"unexpected command {argv}")


@pytest.fixture()
def vendor(tmp_path: Path) -> tuple[Path, str]:
    image = tmp_path / "noble-server-cloudimg-amd64.img"
    image.write_bytes(b"vendor-bytes")
    return image, hashlib.sha256(b"vendor-bytes").hexdigest()


def test_daemon_pin_matches_packaged_source() -> None:
    assert sha256_file(daemon_source()) == PINNED_DAEMON.sha256


def test_derive_writes_golden_and_provenance(
    tmp_path: Path, vendor: tuple[Path, str]
) -> None:
    image, digest = vendor
    cache = tmp_path / "cache"
    metadata, hit = derive_golden(image, digest, cache, runner=fake_runner)
    assert not hit
    assert metadata.file == "noble-server-cloudimg-amd64-golden.qcow2"
    assert (cache / metadata.file).is_file()
    assert metadata.golden_sha256 == sha256_file(cache / metadata.file)
    assert metadata.vendor_sha256 == digest
    assert metadata.daemon == PINNED_DAEMON
    assert (cache / image.name).is_file(), (
        "vendor copied in for the relative backing ref"
    )
    sidecar = json.loads(
        (cache / "noble-server-cloudimg-amd64-golden.json").read_text()
    )
    assert sidecar["derivation_key"] == metadata.derivation_key


def test_derive_is_idempotent(tmp_path: Path, vendor: tuple[Path, str]) -> None:
    image, digest = vendor
    cache = tmp_path / "cache"
    first, hit_first = derive_golden(image, digest, cache, runner=fake_runner)

    def refusing_runner(argv: list[str], cwd: Path) -> None:
        raise AssertionError("cache hit must not run commands")

    second, hit_second = derive_golden(image, digest, cache, runner=refusing_runner)
    assert (not hit_first, hit_second) == (True, True)
    assert second.golden_sha256 == first.golden_sha256


def test_vendor_digest_mismatch_refuses_before_cache_writes(
    tmp_path: Path, vendor: tuple[Path, str]
) -> None:
    image, _ = vendor
    cache = tmp_path / "cache"
    with pytest.raises(DeriveError, match=r"\[verify-vendor\].*digest mismatch"):
        derive_golden(image, "0" * 64, cache, runner=fake_runner)
    assert not cache.exists() or not any(cache.iterdir())


def test_unmanaged_file_is_never_clobbered(
    tmp_path: Path, vendor: tuple[Path, str]
) -> None:
    image, digest = vendor
    cache = tmp_path / "cache"
    cache.mkdir()
    squatter = cache / "noble-server-cloudimg-amd64-golden.qcow2"
    squatter.write_bytes(b"hand-built")
    with pytest.raises(DeriveError, match=r"\[prepare\].*unmanaged"):
        derive_golden(image, digest, cache, runner=fake_runner)
    assert squatter.read_bytes() == b"hand-built"


def test_failed_customize_leaves_no_cache_residue(
    tmp_path: Path, vendor: tuple[Path, str]
) -> None:
    image, digest = vendor
    cache = tmp_path / "cache"

    def failing_runner(argv: list[str], cwd: Path) -> None:
        if argv[0] == "qemu-img":
            fake_runner(argv, cwd)
        else:
            raise subprocess.CalledProcessError(1, argv, "", "boom")

    with pytest.raises(DeriveError, match=r"\[customize\]"):
        derive_golden(image, digest, cache, runner=failing_runner)
    residue = [p.name for p in cache.iterdir() if p.name != image.name]
    assert residue == [], residue


def test_list_images_separates_managed_and_unmanaged(
    tmp_path: Path, vendor: tuple[Path, str]
) -> None:
    image, digest = vendor
    cache = tmp_path / "cache"
    derive_golden(image, digest, cache, runner=fake_runner)
    (cache / "handmade.qcow2").write_bytes(b"x")
    managed, unmanaged = list_images(cache)
    assert [m.file for m in managed] == ["noble-server-cloudimg-amd64-golden.qcow2"]
    assert unmanaged == ["handmade.qcow2"]

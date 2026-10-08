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
    # the per-name .lock file is deliberate persistent state (unlinking a
    # flock file races concurrent lockers); everything else must be gone
    residue = [
        p.name
        for p in cache.iterdir()
        if p.name != image.name and not p.name.endswith(".lock")
    ]
    assert residue == [], residue


def test_daemon_pin_mismatch_refuses(
    tmp_path: Path, vendor: tuple[Path, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    """A tampered daemon artifact refuses at resolve-daemon, before any derivation work."""
    import inspect_ranges._runtime.images as images_module

    image, digest = vendor
    monkeypatch.setattr(
        images_module,
        "PINNED_DAEMON",
        images_module.PINNED_DAEMON.model_copy(update={"sha256": "f" * 64}),
    )
    with pytest.raises(DeriveError, match=r"\[resolve-daemon\].*digest mismatch"):
        derive_golden(image, digest, tmp_path / "cache", runner=fake_runner)


def test_missing_host_tool_is_stage_named(
    tmp_path: Path, vendor: tuple[Path, str]
) -> None:
    image, digest = vendor

    def no_tool(argv: list[str], cwd: Path) -> None:
        raise FileNotFoundError(argv[0])

    with pytest.raises(DeriveError, match=r"\[create-overlay\].*not found"):
        derive_golden(image, digest, tmp_path / "cache", runner=no_tool)


def test_corrupt_sidecar_is_unmanaged_to_both_list_and_derive(
    tmp_path: Path, vendor: tuple[Path, str]
) -> None:
    """A non-conforming sidecar means unmanaged everywhere: list flags the image, derive refuses to touch it."""
    image, digest = vendor
    cache = tmp_path / "cache"
    metadata, _ = derive_golden(image, digest, cache, runner=fake_runner)
    sidecar = cache / "noble-server-cloudimg-amd64-golden.json"
    sidecar.write_text("{not json")
    managed, unmanaged = list_images(cache)
    assert managed == []
    assert metadata.file in unmanaged
    with pytest.raises(DeriveError, match=r"\[prepare\].*not a valid provenance"):
        derive_golden(image, digest, cache, runner=fake_runner)
    assert sidecar.read_text() == "{not json", "derive must not touch it"


def test_tampered_in_cache_vendor_rederives_on_hit(
    tmp_path: Path, vendor: tuple[Path, str]
) -> None:
    """A cache hit stands only on an untampered backing file; a swapped in-cache vendor re-derives from the verified source."""
    image, digest = vendor
    cache = tmp_path / "cache"
    metadata, _ = derive_golden(image, digest, cache, runner=fake_runner)
    (cache / image.name).write_bytes(b"tampered")
    repaired, hit = derive_golden(image, digest, cache, runner=fake_runner)
    assert not hit
    assert (cache / image.name).read_bytes() == b"vendor-bytes"
    assert repaired.golden_sha256 == metadata.golden_sha256


def test_partial_vendor_copy_is_replaced_not_bricked(
    tmp_path: Path, vendor: tuple[Path, str]
) -> None:
    """A partial in-cache vendor (killed mid-copy) is atomically replaced from the verified source, never refused."""
    image, digest = vendor
    cache = tmp_path / "cache"
    cache.mkdir()
    (cache / image.name).write_bytes(b"vendor-by")  # truncated copy
    metadata, hit = derive_golden(image, digest, cache, runner=fake_runner)
    assert not hit
    assert (cache / image.name).read_bytes() == b"vendor-bytes"
    assert metadata.vendor_sha256 == digest


def test_sidecar_without_golden_is_repaired_not_refused(
    tmp_path: Path, vendor: tuple[Path, str]
) -> None:
    """The crash window (sidecar renamed, golden rename lost) self-heals on the next derive."""
    image, digest = vendor
    cache = tmp_path / "cache"
    metadata, _ = derive_golden(image, digest, cache, runner=fake_runner)
    (cache / metadata.file).unlink()
    repaired, hit = derive_golden(image, digest, cache, runner=fake_runner)
    assert not hit
    assert (cache / metadata.file).is_file()
    assert repaired.golden_sha256 == metadata.golden_sha256


def test_dotted_names_map_to_distinct_files_and_sidecars(
    tmp_path: Path, vendor: tuple[Path, str]
) -> None:
    image, digest = vendor
    cache = tmp_path / "cache"
    first, _ = derive_golden(
        image, digest, cache, name="ubuntu-24.04", runner=fake_runner
    )
    second, _ = derive_golden(
        image, digest, cache, name="ubuntu-24.10", runner=fake_runner
    )
    assert first.file == "ubuntu-24.04.qcow2"
    assert second.file == "ubuntu-24.10.qcow2"
    assert (cache / "ubuntu-24.04.json").is_file()
    assert (cache / "ubuntu-24.10.json").is_file()
    managed, _ = list_images(cache)
    assert {m.file for m in managed} >= {"ubuntu-24.04.qcow2", "ubuntu-24.10.qcow2"}


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

"""Golden derivation behavior through the public `derive_golden`/`list_images` surface, with the external commands faked and the daemon-bundle artifact built as a fixture."""

import hashlib
import json
import subprocess
from pathlib import Path

import pytest
from inspect_ranges._channel.bundle import DaemonBundleInfo, write_bundle
from inspect_ranges._runtime import DeriveError, derive_golden, list_images
from inspect_ranges._runtime.images import sha256_file


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


def make_artifact(directory: Path, binary: bytes = b"#!fake-static-daemon") -> Path:
    """A real daemon-bundle artifact (production layout via the public `write_bundle`) with stand-in binary bytes."""
    write_bundle(directory, binary, version="3.0.0-test")
    return directory


@pytest.fixture()
def artifact(tmp_path: Path) -> Path:
    return make_artifact(tmp_path / "artifacts")


def test_missing_artifact_names_the_publishing_command(
    tmp_path: Path, vendor: tuple[Path, str]
) -> None:
    image, digest = vendor
    with pytest.raises(DeriveError, match=r"\[resolve-daemon\].*daemon-bundle"):
        derive_golden(
            image,
            digest,
            tmp_path / "cache",
            runner=fake_runner,
            artifact_dir=tmp_path / "nowhere",
        )


def test_tampered_artifact_refuses(tmp_path: Path, vendor: tuple[Path, str]) -> None:
    image, digest = vendor
    artifact_dir = make_artifact(tmp_path / "artifacts")
    bundle = next(artifact_dir.glob("vsockd-bundle-*.tar"))
    bundle.write_bytes(bundle.read_bytes() + b"x")
    with pytest.raises(DeriveError, match=r"\[resolve-daemon\].*digest"):
        derive_golden(
            image,
            digest,
            tmp_path / "cache",
            runner=fake_runner,
            artifact_dir=artifact_dir,
        )


def test_derive_writes_golden_and_provenance(
    tmp_path: Path, vendor: tuple[Path, str], artifact: Path
) -> None:
    image, digest = vendor
    cache = tmp_path / "cache"
    metadata, hit = derive_golden(
        image, digest, cache, runner=fake_runner, artifact_dir=artifact
    )
    assert not hit
    assert metadata.file == "noble-server-cloudimg-amd64-golden.qcow2"
    assert (cache / metadata.file).is_file()
    assert metadata.golden_sha256 == sha256_file(cache / metadata.file)
    assert metadata.vendor_sha256 == digest
    assert metadata.daemon.name == "vsockd"
    assert metadata.daemon.version == "3.0.0-test"
    sidecar_info = DaemonBundleInfo.model_validate_json(
        (artifact / "daemon.json").read_text()
    )
    assert metadata.daemon.sha256 == sidecar_info.bundle_sha256
    assert (cache / image.name).is_file(), (
        "vendor copied in for the relative backing ref"
    )
    sidecar = json.loads(
        (cache / "noble-server-cloudimg-amd64-golden.json").read_text()
    )
    assert sidecar["derivation_key"] == metadata.derivation_key


def test_derive_is_idempotent(
    tmp_path: Path, vendor: tuple[Path, str], artifact: Path
) -> None:
    image, digest = vendor
    cache = tmp_path / "cache"
    first, hit_first = derive_golden(
        image, digest, cache, runner=fake_runner, artifact_dir=artifact
    )

    def refusing_runner(argv: list[str], cwd: Path) -> None:
        raise AssertionError("cache hit must not run commands")

    second, hit_second = derive_golden(
        image, digest, cache, runner=refusing_runner, artifact_dir=artifact
    )
    assert (not hit_first, hit_second) == (True, True)
    assert second.golden_sha256 == first.golden_sha256


def test_vendor_digest_mismatch_refuses_before_cache_writes(
    tmp_path: Path, vendor: tuple[Path, str], artifact: Path
) -> None:
    image, _ = vendor
    cache = tmp_path / "cache"
    with pytest.raises(DeriveError, match=r"\[verify-vendor\].*digest mismatch"):
        derive_golden(image, "0" * 64, cache, runner=fake_runner, artifact_dir=artifact)
    assert not cache.exists() or not any(cache.iterdir())


def test_unmanaged_file_is_never_clobbered(
    tmp_path: Path, vendor: tuple[Path, str], artifact: Path
) -> None:
    image, digest = vendor
    cache = tmp_path / "cache"
    cache.mkdir()
    squatter = cache / "noble-server-cloudimg-amd64-golden.qcow2"
    squatter.write_bytes(b"hand-built")
    with pytest.raises(DeriveError, match=r"\[prepare\].*unmanaged"):
        derive_golden(image, digest, cache, runner=fake_runner, artifact_dir=artifact)
    assert squatter.read_bytes() == b"hand-built"


def test_failed_customize_leaves_no_cache_residue(
    tmp_path: Path, vendor: tuple[Path, str], artifact: Path
) -> None:
    image, digest = vendor
    cache = tmp_path / "cache"

    def failing_runner(argv: list[str], cwd: Path) -> None:
        if argv[0] == "qemu-img":
            fake_runner(argv, cwd)
        else:
            raise subprocess.CalledProcessError(1, argv, "", "boom")

    with pytest.raises(DeriveError, match=r"\[customize\]"):
        derive_golden(
            image, digest, cache, runner=failing_runner, artifact_dir=artifact
        )
    # the per-name .lock file is deliberate persistent state (unlinking a
    # flock file races concurrent lockers); everything else must be gone
    residue = [
        p.name
        for p in cache.iterdir()
        if p.name != image.name and not p.name.endswith(".lock")
    ]
    assert residue == [], residue


def test_missing_host_tool_is_stage_named(
    tmp_path: Path, vendor: tuple[Path, str], artifact: Path
) -> None:
    image, digest = vendor

    def no_tool(argv: list[str], cwd: Path) -> None:
        raise FileNotFoundError(argv[0])

    with pytest.raises(DeriveError, match=r"\[create-overlay\].*not found"):
        derive_golden(
            image, digest, tmp_path / "cache", runner=no_tool, artifact_dir=artifact
        )


def test_corrupt_sidecar_is_unmanaged_to_both_list_and_derive(
    tmp_path: Path, vendor: tuple[Path, str], artifact: Path
) -> None:
    """A non-conforming sidecar means unmanaged everywhere: list flags the image, derive refuses to touch it."""
    image, digest = vendor
    cache = tmp_path / "cache"
    metadata, _ = derive_golden(
        image, digest, cache, runner=fake_runner, artifact_dir=artifact
    )
    sidecar = cache / "noble-server-cloudimg-amd64-golden.json"
    sidecar.write_text("{not json")
    managed, unmanaged = list_images(cache)
    assert managed == []
    assert metadata.file in unmanaged
    with pytest.raises(DeriveError, match=r"\[prepare\].*not a valid provenance"):
        derive_golden(image, digest, cache, runner=fake_runner, artifact_dir=artifact)
    assert sidecar.read_text() == "{not json", "derive must not touch it"


def test_tampered_in_cache_vendor_rederives_on_hit(
    tmp_path: Path, vendor: tuple[Path, str], artifact: Path
) -> None:
    """A cache hit stands only on an untampered backing file; a swapped in-cache vendor re-derives from the verified source."""
    image, digest = vendor
    cache = tmp_path / "cache"
    metadata, _ = derive_golden(
        image, digest, cache, runner=fake_runner, artifact_dir=artifact
    )
    (cache / image.name).write_bytes(b"tampered")
    repaired, hit = derive_golden(
        image, digest, cache, runner=fake_runner, artifact_dir=artifact
    )
    assert not hit
    assert (cache / image.name).read_bytes() == b"vendor-bytes"
    assert repaired.golden_sha256 == metadata.golden_sha256


def test_partial_vendor_copy_is_replaced_not_bricked(
    tmp_path: Path, vendor: tuple[Path, str], artifact: Path
) -> None:
    """A partial in-cache vendor (killed mid-copy) is atomically replaced from the verified source, never refused."""
    image, digest = vendor
    cache = tmp_path / "cache"
    cache.mkdir()
    (cache / image.name).write_bytes(b"vendor-by")  # truncated copy
    metadata, hit = derive_golden(
        image, digest, cache, runner=fake_runner, artifact_dir=artifact
    )
    assert not hit
    assert (cache / image.name).read_bytes() == b"vendor-bytes"
    assert metadata.vendor_sha256 == digest


def test_sidecar_without_golden_is_repaired_not_refused(
    tmp_path: Path, vendor: tuple[Path, str], artifact: Path
) -> None:
    """The crash window (sidecar renamed, golden rename lost) self-heals on the next derive."""
    image, digest = vendor
    cache = tmp_path / "cache"
    metadata, _ = derive_golden(
        image, digest, cache, runner=fake_runner, artifact_dir=artifact
    )
    (cache / metadata.file).unlink()
    repaired, hit = derive_golden(
        image, digest, cache, runner=fake_runner, artifact_dir=artifact
    )
    assert not hit
    assert (cache / metadata.file).is_file()
    assert repaired.golden_sha256 == metadata.golden_sha256


def test_dotted_names_map_to_distinct_files_and_sidecars(
    tmp_path: Path, vendor: tuple[Path, str], artifact: Path
) -> None:
    image, digest = vendor
    cache = tmp_path / "cache"
    first, _ = derive_golden(
        image,
        digest,
        cache,
        name="ubuntu-24.04",
        runner=fake_runner,
        artifact_dir=artifact,
    )
    second, _ = derive_golden(
        image,
        digest,
        cache,
        name="ubuntu-24.10",
        runner=fake_runner,
        artifact_dir=artifact,
    )
    assert first.file == "ubuntu-24.04.qcow2"
    assert second.file == "ubuntu-24.10.qcow2"
    assert (cache / "ubuntu-24.04.json").is_file()
    assert (cache / "ubuntu-24.10.json").is_file()
    managed, _ = list_images(cache)
    assert {m.file for m in managed} >= {"ubuntu-24.04.qcow2", "ubuntu-24.10.qcow2"}


def test_list_images_separates_managed_and_unmanaged(
    tmp_path: Path, vendor: tuple[Path, str], artifact: Path
) -> None:
    image, digest = vendor
    cache = tmp_path / "cache"
    derive_golden(image, digest, cache, runner=fake_runner, artifact_dir=artifact)
    (cache / "handmade.qcow2").write_bytes(b"x")
    managed, unmanaged = list_images(cache)
    assert [m.file for m in managed] == ["noble-server-cloudimg-amd64-golden.qcow2"]
    assert unmanaged == ["handmade.qcow2"]


def test_daemon_pin_mismatch_refuses(
    tmp_path: Path, vendor: tuple[Path, str], artifact: Path
) -> None:
    """The out-of-band pin is the provenance check: a self-consistent artifact that does not match it refuses."""
    image, digest = vendor
    with pytest.raises(
        DeriveError, match=r"\[resolve-daemon\].*does not match the pin"
    ):
        derive_golden(
            image,
            digest,
            tmp_path / "cache",
            runner=fake_runner,
            artifact_dir=artifact,
            daemon_sha256="f" * 64,
        )


def test_protocol_skewed_artifact_refuses(
    tmp_path: Path, vendor: tuple[Path, str], artifact: Path
) -> None:
    image, digest = vendor
    sidecar = artifact / "daemon.json"
    info = DaemonBundleInfo.model_validate_json(sidecar.read_text())
    skewed = info.model_dump()
    skewed["protocol"] = 99
    sidecar.write_text(DaemonBundleInfo.model_construct(**skewed).model_dump_json())
    with pytest.raises(DeriveError, match=r"\[resolve-daemon\].*protocol 99"):
        derive_golden(
            image,
            digest,
            tmp_path / "cache",
            runner=fake_runner,
            artifact_dir=artifact,
        )

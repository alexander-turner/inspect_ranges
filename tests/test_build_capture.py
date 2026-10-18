"""Capture semantics through the public seams, no VMs (round-1 review: the module had zero unit coverage and two of its defects would have been caught by exactly these tests)."""

import json
from pathlib import Path

import pytest
from inspect_ranges._build.capture import (
    RealizedImageMeta,
    capture_guest,
    wait_shutoff,
)
from inspect_ranges._build.errors import BuildError


def meta_for(golden: str) -> RealizedImageMeta:
    return RealizedImageMeta(
        range_name="caprange",
        guest="web",
        build_key="k" * 64,
        golden_file=golden,
        sha256="",
        created="2026-10-18T00:00:00Z",
    )


def fake_runner(cache: Path, payload: bytes) -> object:
    def runner(argv: list[str]) -> str:
        if argv[0] == "docker" and argv[1] == "cp":
            Path(argv[-1]).write_bytes(payload)
        return ""

    return runner


def test_capture_places_image_before_sidecar_and_cleans_temps(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    cache = tmp_path / "cache"
    cache.mkdir()
    # stale temps from a crashed prior capture of the SAME name are cleaned
    (cache / ".caprange-web-abc.qcow2.capturing").write_bytes(b"stale")
    placements: list[str] = []
    real_replace = Path.replace

    def tracking_replace(self: Path, target: "Path | str") -> Path:
        placements.append(str(target))
        return real_replace(self, target)

    monkeypatch.setattr(Path, "replace", tracking_replace)
    digest = capture_guest(
        fake_runner(cache, b"overlay-bytes"),  # type: ignore[arg-type]
        "ir-cap-x",
        "web",
        image_cache=cache,
        golden_file="golden.qcow2",
        realized_name="caprange-web-abc.qcow2",
        meta=meta_for("golden.qcow2"),
    )
    monkeypatch.undo()
    image = cache / "caprange-web-abc.qcow2"
    sidecar = cache / "caprange-web-abc.realized.json"
    assert image.read_bytes() == b"overlay-bytes"
    recorded = json.loads(sidecar.read_text())
    assert recorded["sha256"] == digest
    # the image lands FIRST: a crash between placements never leaves a sidecar
    # describing a file that is not there (round-1)
    assert placements.index(str(image)) < placements.index(str(sidecar))
    assert not (cache / ".caprange-web-abc.qcow2.capturing").exists()


def test_capture_failure_leaves_no_temp_or_sidecar(tmp_path: Path) -> None:
    cache = tmp_path / "cache"
    cache.mkdir()

    def failing_runner(argv: list[str]) -> str:
        raise BuildError("capture", "docker cp exited 1: no such container")

    with pytest.raises(BuildError):
        capture_guest(
            failing_runner,  # type: ignore[arg-type]
            "ir-cap-x",
            "web",
            image_cache=cache,
            golden_file="golden.qcow2",
            realized_name="caprange-web-abc.qcow2",
            meta=meta_for("golden.qcow2"),
        )
    assert not (cache / "caprange-web-abc.qcow2").exists()
    assert not (cache / "caprange-web-abc.realized.json").exists()
    assert not (cache / ".caprange-web-abc.qcow2.capturing").exists()


def test_wait_shutoff_timeout_carries_the_shutdown_diagnosis() -> None:
    def never_off(argv: list[str]) -> str:
        return "running"

    with pytest.raises(BuildError) as excinfo:
        wait_shutoff(
            never_off,  # type: ignore[arg-type]
            "ir-cap-x",
            "web",
            timeout_s=0.1,
            shutdown_diagnosis="systemctl poweroff exited 1: bus error",
        )
    message = str(excinfo.value)
    assert "did not reach 'shut off'" in message
    assert "systemctl poweroff exited 1" in message


def write_realized(cache: Path, range_name: str, guest: str, key: str) -> Path:
    image = cache / f"{range_name}-{guest}-{key}.qcow2"
    image.write_bytes(b"x" * 1024)
    sidecar = cache / f"{range_name}-{guest}-{key}.realized.json"
    sidecar.write_text(
        meta_for("golden.qcow2")
        .model_copy(
            update={"range_name": range_name, "guest": guest, "build_key": key * 6}
        )
        .model_dump_json()
    )
    return image


def test_collect_realized_garbage_is_range_scoped_and_keeps_the_kept(
    tmp_path: Path,
) -> None:
    """Parked-decisions item 1: the sweep deletes only this range's unkept generations; other ranges and unreadable sidecars are untouched."""
    from inspect_ranges._build.capture import collect_realized_garbage

    cache = tmp_path / "cache"
    cache.mkdir()
    current = write_realized(cache, "gcrange", "web", "aaaaaaaaaaaa")
    previous = write_realized(cache, "gcrange", "web", "bbbbbbbbbbbb")
    stale = write_realized(cache, "gcrange", "web", "cccccccccccc")
    other = write_realized(cache, "other", "web", "dddddddddddd")
    (cache / "broken-web-eeeeeeeeeeee.realized.json").write_text("{not json")
    deleted, reclaimed = collect_realized_garbage(
        "gcrange", cache, {current.name, previous.name}
    )
    assert deleted == 1 and reclaimed == 1024
    assert current.exists() and previous.exists() and other.exists()
    assert not stale.exists()
    assert not (cache / "gcrange-web-cccccccccccc.realized.json").exists()


def test_live_project_files_reads_boot_json(tmp_path: Path) -> None:
    import json

    from inspect_ranges._build.capture import live_project_files
    from inspect_ranges._runtime.ownership import owner_record, write_owner

    state = tmp_path / "state"
    bundle = tmp_path / "bundle"
    bundle.mkdir()
    (bundle / "boot.json").write_text(
        json.dumps(
            {
                "guests": [
                    {
                        "name": "web",
                        "image_file": "r-web-abc.qcow2",
                        "backing_file": "golden.qcow2",
                    }
                ]
            }
        )
    )
    write_owner(state, owner_record("ir-live-1", "r", "0" * 64, bundle))
    assert live_project_files(state) == {"r-web-abc.qcow2", "golden.qcow2"}

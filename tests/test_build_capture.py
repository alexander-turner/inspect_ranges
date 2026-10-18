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

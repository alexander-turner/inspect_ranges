"""The evidence-capture sidecar in rendered bundles (evidence-v1 slice 2).

The spike's outcome, pinned as render behavior: capture runs in a separate compose service with `CAP_NET_RAW` alone, the range container's capability floor is unchanged, chunks live on a volume the range service never mounts, and the supervisor plus the segment-to-bridge map are bundle artifacts under `capture/`.
"""

import json
import py_compile
import tempfile
from pathlib import Path
from typing import Any

import pytest
import yaml
from inspect_ranges._compiler import PlanOptions, render_bundle
from inspect_ranges._evidence.supervisor import SUPERVISOR_SOURCE

from tests.test_compiler import nat_spec, two_segment_spec


@pytest.fixture()
def cache(tmp_path: Path) -> Path:
    cache = tmp_path / "cache"
    cache.mkdir()
    for name in ("noble-range-guest.qcow2", "img.qcow2", "Ubuntu20.qcow2"):
        (cache / name).write_bytes(b"fake golden: " + name.encode())
    return cache


def options(cache: Path, evidence: bool) -> PlanOptions:
    return PlanOptions(image_cache=cache, evidence_capture=evidence)


def compose_of(bundle: Path) -> dict[str, Any]:
    return yaml.safe_load((bundle / "compose.yaml").read_text())


def test_default_renders_no_capture(cache: Path, tmp_path: Path) -> None:
    out = tmp_path / "bundle"
    plan = render_bundle(two_segment_spec(), out, options(cache, evidence=False))
    assert plan.requirements.evidence_capture is False
    compose = compose_of(out)
    assert "capture" not in compose["services"]
    assert "capture" not in compose["volumes"]
    assert not (out / "capture").exists()


def test_capture_service_and_floor(cache: Path, tmp_path: Path) -> None:
    out = tmp_path / "bundle"
    plan = render_bundle(two_segment_spec(), out, options(cache, evidence=True))
    assert plan.requirements.evidence_capture is True
    compose = compose_of(out)

    capture = compose["services"]["capture"]
    assert capture["cap_drop"] == ["ALL"]
    assert capture["cap_add"] == ["NET_RAW"]
    assert capture["network_mode"] == "service:range"
    assert capture["security_opt"] == ["no-new-privileges:true"]
    assert "capture:/capture" in capture["volumes"]
    assert ".:/render:ro" in capture["volumes"]
    assert "capture" in compose["volumes"]

    # the whole rendered compose minus the inserted sidecar block is
    # byte-identical to the capture-off render (adopted from the chunk-1
    # verification probe): nothing but the sidecar changes
    from inspect_ranges._compiler.render import _COMPOSE_CAPTURE_SERVICE

    plain = tmp_path / "plain"
    render_bundle(two_segment_spec(), plain, options(cache, evidence=False))
    with_capture = (out / "compose.yaml").read_text()
    stripped = with_capture.replace("\n" + _COMPOSE_CAPTURE_SERVICE, "", 1).replace(
        "volumes:\n  scratch:\n  capture:\n", "volumes:\n  scratch:\n"
    )
    assert stripped == (plain / "compose.yaml").read_text()
    # the range service never mounts the capture volume
    assert all("capture" not in v for v in compose["services"]["range"]["volumes"])


def test_capture_bundle_files(cache: Path, tmp_path: Path) -> None:
    out = tmp_path / "bundle"
    plan = render_bundle(two_segment_spec(), out, options(cache, evidence=True))
    bridges = (out / "capture" / "bridges.tsv").read_text()
    expected = {network.name: network.bridge for network in plan.networks}
    assert bridges == "".join(
        f"{name}\t{bridge}\n" for name, bridge in sorted(expected.items())
    )
    assert (out / "capture" / "capture.py").read_text() == SUPERVISOR_SOURCE
    manifest = json.loads((out / "manifest.json").read_text())
    assert "capture/bridges.tsv" in manifest["files"]
    assert "capture/capture.py" in manifest["files"]


def test_capture_render_is_deterministic(cache: Path, tmp_path: Path) -> None:
    render_bundle(two_segment_spec(), tmp_path / "a", options(cache, evidence=True))
    render_bundle(two_segment_spec(), tmp_path / "b", options(cache, evidence=True))
    assert (tmp_path / "a" / "manifest.json").read_bytes() == (
        tmp_path / "b" / "manifest.json"
    ).read_bytes()


def test_capture_with_uplink_template(cache: Path, tmp_path: Path) -> None:
    out = tmp_path / "bundle"
    render_bundle(nat_spec(), out, options(cache, evidence=True))
    compose = compose_of(out)
    assert "capture" in compose["services"]
    assert compose["services"]["capture"]["cap_add"] == ["NET_RAW"]
    assert "uplink" in compose["networks"]
    assert "capture" in compose["volumes"] and "scratch" in compose["volumes"]
    # the sidecar shares the range netns; it must not join the uplink network
    assert "networks" not in compose["services"]["capture"]
    # byte-identity holds for the uplink template too
    from inspect_ranges._compiler.render import _COMPOSE_CAPTURE_SERVICE

    plain = tmp_path / "plain"
    render_bundle(nat_spec(), plain, options(cache, evidence=False))
    with_capture = (out / "compose.yaml").read_text()
    stripped = with_capture.replace("\n" + _COMPOSE_CAPTURE_SERVICE, "", 1).replace(
        "volumes:\n  scratch:\n  capture:\n", "volumes:\n  scratch:\n"
    )
    assert stripped == (plain / "compose.yaml").read_text()


def test_supervisor_source_compiles() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        source = Path(tmp) / "capture.py"
        source.write_text(SUPERVISOR_SOURCE)
        py_compile.compile(str(source), doraise=True)

"""`provider: glovebox` attacker: an externally-managed attack box (a glovebox Kata/Cloud Hypervisor cell). Ranges reserves its segment IP/MAC and stands up the bridge, but does not render, boot, or list it in `boot.json`; the box is supplied and driven externally. The marker is mutually exclusive with `vmm:` and with a `host:` foothold."""

import json
from pathlib import Path

import pytest
from inspect_ranges._compiler import PlanOptions, render_bundle, resolve_plan
from inspect_ranges.types import Attacker, Interface, IssueError, RangeSpec
from pydantic import ValidationError

from tests.test_compiler import two_segment_spec


def glovebox_spec() -> RangeSpec:
    spec = two_segment_spec()
    spec.attacker = Attacker(
        provider="glovebox",
        interfaces=[Interface(network="dmz")],
        entry="external",
    )
    return spec


@pytest.fixture()
def cache(tmp_path: Path) -> Path:
    cache = tmp_path / "cache"
    cache.mkdir()
    (cache / "img.qcow2").write_bytes(b"fake golden")
    (cache / "ubuntu-noble.qcow2").write_bytes(b"fake router golden")
    return cache


def test_provider_defaults_to_ranges() -> None:
    attacker = Attacker(interfaces=[Interface(network="dmz")], entry="external")
    assert attacker.provider == "ranges"


def test_provider_glovebox_refuses_a_vmm() -> None:
    with pytest.raises((IssueError, ValidationError), match="provider: glovebox"):
        Attacker(
            provider="glovebox",
            vmm="cloud-hypervisor",
            interfaces=[Interface(network="dmz")],
            entry="external",
        )


def test_provider_glovebox_refuses_a_host_foothold() -> None:
    with pytest.raises((IssueError, ValidationError), match="provider: glovebox"):
        Attacker(provider="glovebox", host="web", entry="assumed-breach")


def test_plan_reserves_the_glovebox_attacker_address_and_marks_it() -> None:
    plan = resolve_plan(glovebox_spec(), PlanOptions())
    attacker = next(guest for guest in plan.guests if guest.kind == "attacker")
    assert attacker.provider == "glovebox"
    # the attacker still holds a reserved dmz address (routers take .1, so .2)
    assert [str(nic.ip) for nic in attacker.interfaces] == ["10.80.10.2"]


def test_render_does_not_boot_the_glovebox_attacker_but_keeps_the_bridge(
    cache: Path, tmp_path: Path
) -> None:
    out = tmp_path / "bundle"
    render_bundle(glovebox_spec(), out, PlanOptions(image_cache=cache))
    boot = json.loads((out / "boot.json").read_text())
    names = {guest["name"] for guest in boot["guests"]}
    assert "attacker" not in names
    assert names == {"web", "db", "router"}
    assert not (out / "guests/attacker").exists()
    # the dmz bridge the external cell attaches to is still stood up
    assert "br-dmz" in (out / "netns/bridges.txt").read_text().split()


def test_render_does_not_require_an_image_for_the_glovebox_attacker(
    cache: Path, tmp_path: Path
) -> None:
    # the attacker declares no image and none is in the cache; a ranges-managed
    # attacker would trip image-not-in-cache, a glovebox one must not
    render_bundle(glovebox_spec(), tmp_path / "bundle", PlanOptions(image_cache=cache))

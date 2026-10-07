import hashlib
import json
from pathlib import Path

import pytest
from inspect_ranges._compiler import (
    PlanOptions,
    plan_json,
    render_bundle,
    resolve_plan,
)
from inspect_ranges.types import (
    Attacker,
    Host,
    Interface,
    IssueError,
    Network,
    Os,
    RangeMeta,
    RangeSpec,
    Service,
)

from tests.test_compiler import chained_spec, nat_spec, netsvc_spec, two_segment_spec


@pytest.fixture()
def cache(tmp_path: Path) -> Path:
    cache = tmp_path / "cache"
    cache.mkdir()
    for name in ("noble-range-guest.qcow2", "img.qcow2", "Ubuntu20.qcow2"):
        (cache / name).write_bytes(b"fake golden: " + name.encode())
    return cache


def options(cache: Path) -> PlanOptions:
    return PlanOptions(image_cache=cache)


def test_plan_is_deterministic(cache: Path) -> None:
    first = plan_json(resolve_plan(chained_spec(), options(cache)))
    second = plan_json(resolve_plan(chained_spec(), options(cache)))
    assert first == second


def test_plan_resolves_networks_and_guests(cache: Path) -> None:
    plan = resolve_plan(netsvc_spec(), options(cache))
    lab = next(network for network in plan.networks if network.name == "lab")
    assert lab.bridge == "br-lab" and lab.dhcp
    assert lab.hypervisor_address is not None
    assert lab.resolvers == [lab.hypervisor_address]
    assert lab.search == "lab.internal"
    assert lab.gateway is None  # isolated: a service address is not a gateway
    web = next(guest for guest in plan.guests if guest.name == "web")
    assert web.image.digest is not None and web.image.digest.startswith("sha256:")
    assert (plan.totals.guests, plan.totals.cpus) == (3, 3)
    assert plan.requirements.egress_uplink is False


def test_egress_uplink_derived_from_modes(cache: Path) -> None:
    assert resolve_plan(nat_spec(), options(cache)).requirements.egress_uplink
    assert not resolve_plan(
        two_segment_spec(), options(cache)
    ).requirements.egress_uplink


def test_image_cache_miss_is_loud(cache: Path, tmp_path: Path) -> None:
    spec = two_segment_spec()
    spec.hosts[0].image = "ghost-image"
    plan = resolve_plan(spec, options(cache))
    assert plan.guests[0].image.digest is None  # visible in the plan
    with pytest.raises(IssueError) as excinfo:
        render_bundle(spec, tmp_path / "bundle", options(cache))
    assert excinfo.value.issues[0].code == "image-not-in-cache"
    assert excinfo.value.issues[0].path == ("hosts", 0, "image")


def test_windows_guests_refuse_at_planning() -> None:
    spec = RangeSpec(
        meta=RangeMeta(name="win", description="windows refusal"),
        networks=[Network(name="lab", cidr="10.0.0.0/24", mode="isolated")],
        hosts=[
            Host(
                name="dc",
                os=Os(type="windows"),
                image="win-golden",
                interfaces=[Interface(network="lab")],
            )
        ],
        attacker=Attacker(interfaces=[Interface(network="lab")], entry="external"),
    )
    with pytest.raises(IssueError) as excinfo:
        resolve_plan(spec)
    issue = excinfo.value.issues[0]
    assert issue.code == "windows-render-not-supported"
    assert issue.path == ("hosts", 0, "os", "type")


def test_guest_config_gates_at_planning() -> None:
    spec = two_segment_spec()
    spec.hosts[0].services = [Service(name="httpd", port=80)]
    with pytest.raises(IssueError) as excinfo:
        resolve_plan(spec)
    issue = excinfo.value.issues[0]
    assert issue.code == "guest-config-not-realized"
    assert issue.path == ("hosts", 0, "services")


def test_variables_gate_at_planning() -> None:
    from inspect_ranges.types import Variable

    spec = two_segment_spec()
    spec.variables = {"flag_hint": Variable(default="warm")}
    with pytest.raises(IssueError) as excinfo:
        resolve_plan(spec)
    issue = excinfo.value.issues[0]
    assert issue.code == "randomization-not-realized"
    assert issue.path == ("variables",)


def test_render_is_byte_deterministic(cache: Path, tmp_path: Path) -> None:
    render_bundle(chained_spec(), tmp_path / "a", options(cache))
    render_bundle(chained_spec(), tmp_path / "b", options(cache))
    manifest_a = (tmp_path / "a" / "manifest.json").read_bytes()
    assert manifest_a == (tmp_path / "b" / "manifest.json").read_bytes()
    assert (tmp_path / "a" / "plan.json").read_bytes() == (
        tmp_path / "b" / "plan.json"
    ).read_bytes()


def test_bundle_manifest_self_verifies(cache: Path, tmp_path: Path) -> None:
    out = tmp_path / "bundle"
    render_bundle(netsvc_spec(), out, options(cache))
    manifest = json.loads((out / "manifest.json").read_text())
    assert manifest["files"], "manifest lists no files"
    for relative, meta in manifest["files"].items():
        data = (out / relative).read_bytes()
        assert hashlib.sha256(data).hexdigest() == meta["sha256"], relative
        assert len(data) == meta["size"]
    # dhcp network: dnsmasq needs raw sockets, so NET_RAW joins the cap floor
    compose = (out / "compose.yaml").read_text()
    assert "NET_BIND_SERVICE" in compose and "NET_RAW" in compose
    listed = set(manifest["files"]) | {"manifest.json"}
    on_disk = {str(p.relative_to(out)) for p in out.rglob("*") if p.is_file()}
    assert listed == on_disk


def test_bundle_artifacts_reflect_the_plan(cache: Path, tmp_path: Path) -> None:
    out = tmp_path / "bundle"
    render_bundle(chained_spec(), out, options(cache))
    # the transit router's seed carries its generated ruleset and static routes
    r2_user_data = (out / "guests/r2/seed/user-data").read_text()
    assert "ip saddr 10.80.10.0/24" in r2_user_data
    r2_netplan = (out / "guests/r2/seed/network-config").read_text()
    assert "10.80.10.0/24" in r2_netplan and "10.80.20.1" in r2_netplan
    # explicit domain XML on the strict profile
    xml = (out / "guests/safe/domain.xml").read_text()
    assert "<memballoon model='none'/>" in xml
    assert "<cid auto='no' address='3'/>" in xml
    assert "<cpu mode='host-passthrough'/>" in xml
    # isolated range: hardened compose with no Docker networking; no dhcp -> no NET_RAW
    compose = (out / "compose.yaml").read_text()
    assert "network_mode: none" in compose
    assert "NET_RAW" not in compose
    boot = json.loads((out / "boot.json").read_text())
    assert [guest["name"] for guest in boot["guests"]] == [
        "safe",
        "r1",
        "r2",
        "attacker",
    ]


def test_uplink_compose_variant(cache: Path, tmp_path: Path) -> None:
    out = tmp_path / "bundle"
    render_bundle(nat_spec(), out, options(cache))
    compose = (out / "compose.yaml").read_text()
    assert "network_mode: none" not in compose
    assert "UPLINK_NETWORK" in compose and "ip_forward=1" in compose


def test_render_refuses_nonempty_directory(cache: Path, tmp_path: Path) -> None:
    out = tmp_path / "bundle"
    out.mkdir()
    (out / "stale").write_text("x")
    with pytest.raises(FileExistsError):
        render_bundle(two_segment_spec(), out, options(cache))

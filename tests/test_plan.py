import hashlib
import json
import re
from collections.abc import Callable
from pathlib import Path
from xml.etree import ElementTree

import pytest
import yaml
from inspect_ranges._compiler import (
    PlanOptions,
    plan_json,
    render_bundle,
    resolve_plan,
)
from inspect_ranges._runtime.rangeimage import range_image_context
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
    for name in (
        "noble-range-guest.qcow2",
        "img.qcow2",
        "Ubuntu20.qcow2",
        "attack.qcow2",
    ):
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


def test_attacker_defaults_to_the_catalog_attack_image(cache: Path) -> None:
    """An undeclared dedicated attack box resolves to `attack` (standard-images-v1 slice 4: the schema's standard-attack-image promise gets its referent); routers keep the default guest image; a declared image opts out."""
    plan = resolve_plan(two_segment_spec(), options(cache))
    by_kind = {guest.kind: guest for guest in plan.guests}
    assert by_kind["attacker"].image.reference == "attack"
    assert by_kind["router"].image.reference == "noble-range-guest"
    spec = two_segment_spec()
    opted_out = spec.model_copy(
        update={"attacker": spec.attacker.model_copy(update={"image": "img"})}
    )
    declared = resolve_plan(opted_out, options(cache))
    attacker = next(g for g in declared.guests if g.kind == "attacker")
    assert attacker.image.reference == "img"


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


def test_realized_sections_exempt_exactly_their_gate() -> None:
    from inspect_ranges.types import ProvisioningStep, Service

    spec = two_segment_spec()
    spec.hosts[0].provisioning = [ProvisioningStep(recipe="acme.web")]
    build_options = PlanOptions(realized_sections=frozenset({"provisioning"}))
    plan = resolve_plan(spec, build_options)
    assert plan.range.name == spec.meta.name
    # other sections stay gated even in build mode
    spec.hosts[0].services = [Service(name="httpd", port=80)]
    with pytest.raises(IssueError) as excinfo:
        resolve_plan(spec, build_options)
    assert excinfo.value.issues[0].path == ("hosts", 0, "services")
    # and the runtime path (no realized_sections) still gates provisioning
    spec.hosts[0].services = []
    with pytest.raises(IssueError) as excinfo:
        resolve_plan(spec)
    assert excinfo.value.issues[0].path == ("hosts", 0, "provisioning")


def test_hostname_and_fqdn_gate_at_planning() -> None:
    spec = two_segment_spec()
    spec.hosts[0].hostname = "dc01-nyc"
    spec.hosts[0].fqdn = "dc01-nyc.corp.local"
    with pytest.raises(IssueError) as excinfo:
        resolve_plan(spec)
    paths = {issue.path for issue in excinfo.value.issues}
    codes = {issue.code for issue in excinfo.value.issues}
    assert codes == {"guest-config-not-realized"}
    assert ("hosts", 0, "hostname") in paths and ("hosts", 0, "fqdn") in paths


def test_variables_resolve_to_defaults_at_planning(cache: Path) -> None:
    """Linux-examples-v1: declared variables no longer gate planning; loading already substituted their defaults, so a spec with variables plans concretely (per-sample secrets stay the plant layer's job; the generation layer is parked)."""
    from inspect_ranges.schema import load_range

    spec_yaml = """
range:
  name: vars-resolve
  schema_version: "0.3"
  description: variables resolve to defaults
variables:
  svc_port: { type: port, min: 1500, default: 2323 }
networks:
  - name: lab
    cidr: 10.0.0.0/24
    mode: isolated
hosts:
  - name: web
    os: { type: linux }
    image: noble-range-guest
    interfaces: [{ network: lab, ip: 10.0.0.10 }]
attacker:
  image: noble-range-guest
  interfaces: [{ network: lab }]
  entry: external
"""
    spec_path = cache.parent / "vars-range.yaml"
    spec_path.write_text(spec_yaml)
    spec = load_range(spec_path)
    plan = resolve_plan(spec, options(cache))
    assert plan.range.name == "vars-resolve"


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


def test_domain_turns_off_q35_legacy_devices(cache: Path, tmp_path: Path) -> None:
    # q35 adds devices no configuration names; the domain removes those no
    # guest uses (natively where libvirt 10.0 can, else on the QEMU command
    # line) and keeps the PIT and PIC
    out = tmp_path / "bundle"
    render_bundle(chained_spec(), out, options(cache))
    qemu = "{http://libvirt.org/schemas/domain/qemu/1.0}"
    domains = sorted(out.glob("guests/*/domain.xml"))
    # the attacker defaults to cloud-hypervisor (no domain XML), so the glob
    # covers the qemu guests; assert they are exactly the ones expected rather
    # than silently shrinking (round-2 review)
    assert [path.parent.name for path in domains] == sorted(
        guest.name
        for guest in resolve_plan(chained_spec(), options(cache)).guests
        if guest.vmm == "qemu"
    )
    assert domains
    for xml in domains:
        domain = ElementTree.fromstring(xml.read_text())
        vmport = domain.find("features/vmport")
        assert vmport is not None and vmport.get("state") == "off"
        hpet = domain.find("clock/timer[@name='hpet']")
        assert hpet is not None and hpet.get("present") == "no"
        args = [arg.get("value") for arg in domain.iter(f"{qemu}arg")]
        assert args == [
            "-machine",
            "sata=off,smbus=off,i8042=off",
            "-global",
            "kvm-apic.vapic=false",
        ]


def test_uplink_compose_variant(cache: Path, tmp_path: Path) -> None:
    out = tmp_path / "bundle"
    render_bundle(nat_spec(), out, options(cache))
    compose = (out / "compose.yaml").read_text()
    assert "network_mode: none" not in compose
    assert "UPLINK_NETWORK" in compose


@pytest.mark.parametrize(
    ("spec", "expected"),
    [
        (two_segment_spec, ["net.ipv6.conf.default.disable_ipv6=1"]),
        (nat_spec, ["net.ipv6.conf.default.disable_ipv6=1", "net.ipv4.ip_forward=1"]),
    ],
    ids=["isolated", "uplink"],
)
def test_range_service_sysctls(
    spec: Callable[[], RangeSpec], expected: list[str], cache: Path, tmp_path: Path
) -> None:
    # bridges come up after the container starts and inherit IPv6 off, so no
    # management address answers on a segment (agent-containment.md)
    out = tmp_path / "bundle"
    render_bundle(spec(), out, options(cache))
    compose = yaml.safe_load((out / "compose.yaml").read_text())
    assert compose["services"]["range"]["sysctls"] == expected


def test_range_bridges_are_created_without_multicast_snooping() -> None:
    # a snooping bridge joins 224.0.0.106 and sends an IGMP report from its own
    # MAC when it comes up: a frame on the segment that belongs to no guest
    entrypoint = (range_image_context() / "entrypoint.sh").read_text()
    assert re.search(r"ip link add \S+ type bridge\b.*\bmcast_snooping 0\b", entrypoint)


def test_render_refuses_nonempty_directory(cache: Path, tmp_path: Path) -> None:
    out = tmp_path / "bundle"
    out.mkdir()
    (out / "stale").write_text("x")
    with pytest.raises(FileExistsError):
        render_bundle(two_segment_spec(), out, options(cache))


def test_every_qemu_domain_carries_its_own_dac_principal(
    cache: Path, tmp_path: Path
) -> None:
    """Issue #5: sVirt AppArmor cannot load profiles inside the hardened container, so per-VM confinement is per-VM identity: each QEMU runs as GUEST_UID_BASE+cid, relabel off (the boot script pre-owns the files)."""
    from xml.etree import ElementTree

    from inspect_ranges._compiler.plan import guest_uid

    out = tmp_path / "bundle"
    plan = resolve_plan(chained_spec(), options(cache))
    render_bundle(chained_spec(), out, options(cache))
    uids: set[int] = set()
    for guest in plan.guests:
        if guest.vmm != "qemu":
            continue
        domain = ElementTree.fromstring(
            (out / "guests" / guest.name / "domain.xml").read_text()
        )
        seclabel = domain.find("seclabel")
        assert seclabel is not None
        assert seclabel.get("model") == "dac"
        assert seclabel.get("type") == "static"
        assert seclabel.get("relabel") == "no"
        label = seclabel.find("label")
        assert label is not None and label.text == f"+{guest_uid(guest.cid)}:kvm"
        uids.add(guest_uid(guest.cid))
    assert len(uids) == sum(1 for g in plan.guests if g.vmm == "qemu")  # all distinct


def test_multihomed_guest_default_route_election(cache: Path, tmp_path: Path) -> None:
    """A guest with one router-gatewayed and one NAT attachment (the build-uplink shape) elects the NAT default deterministically by metric and keeps sibling-subnet routes via the router; a single-gatewayed guest renders exactly as before (no metrics)."""
    import yaml
    from inspect_ranges.schema import load_range

    spec_yaml = """
range:
  name: multihome
  schema_version: "0.3"
  description: deterministic default election
networks:
  - name: a
    cidr: 192.168.20.0/24
    mode: routed
  - name: b
    cidr: 192.168.30.0/24
    mode: routed
  - name: uplink
    cidr: 10.254.169.0/24
    mode: nat
hosts:
  - name: dual
    os: { type: linux }
    image: noble-range-guest
    interfaces:
      - { network: a, ip: 192.168.20.5 }
      - { network: uplink }
  - name: single
    os: { type: linux }
    image: noble-range-guest
    interfaces: [{ network: b, ip: 192.168.30.5 }]
routers:
  - name: r
    interfaces:
      - { network: a, ip: 192.168.20.1 }
      - { network: b, ip: 192.168.30.1 }
attacker:
  image: noble-range-guest
  interfaces: [{ network: uplink }]
  entry: external
"""
    spec_path = tmp_path / "multihome.yaml"
    spec_path.write_text(spec_yaml)
    out = tmp_path / "bundle"
    render_bundle(load_range(spec_path), out, options(cache))
    seeds = {p.parent.parent.name: p for p in out.rglob("network-config")}
    dual = yaml.safe_load(seeds["dual"].read_text())["ethernets"]
    routed_routes = dual["eth0"]["routes"]
    uplink_routes = dual["eth1"]["routes"]
    assert {"to": "default", "via": "192.168.20.1", "metric": 200} in routed_routes
    assert {"to": "192.168.30.0/24", "via": "192.168.20.1"} in routed_routes
    assert uplink_routes[0]["to"] == "default" and uplink_routes[0]["metric"] == 50
    single = yaml.safe_load(seeds["single"].read_text())["ethernets"]
    assert single["eth0"]["routes"] == [{"to": "default", "via": "192.168.30.1"}]


def test_guest_hostnames_sanitize_to_rfc_form() -> None:
    """Underscored guest names (the terraform-derived shape) render hostname-safe: an invalid hostname makes noble's cloud-init degraded and readiness refuses (linux-examples-v1 slice 3)."""
    from inspect_ranges._compiler.render import guest_hostname

    assert guest_hostname("router_external") == "router-external"
    assert guest_hostname("database_0") == "database-0"
    assert guest_hostname("web") == "web"
    assert guest_hostname("web_") == "web"
    assert guest_hostname("a.b_c") == "a-b-c"


def test_colliding_sanitized_hostnames_refuse_at_planning(cache: Path) -> None:
    """Two legal guest names that sanitize to one hostname would be agent-visible identity confusion; planning refuses."""
    spec = two_segment_spec()
    collided = spec.model_copy(deep=True)
    collided.hosts[0].name = "web_0"
    collided.hosts[1].name = "web.0"
    with pytest.raises(IssueError) as excinfo:
        resolve_plan(collided, options(cache))
    assert any(issue.code == "hostname-collision" for issue in excinfo.value.issues)

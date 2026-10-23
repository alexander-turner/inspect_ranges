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
    Router,
    Service,
)

from tests.test_compiler import chained_spec, nat_spec, netsvc_spec, two_segment_spec


@pytest.fixture()
def cache(tmp_path: Path) -> Path:
    cache = tmp_path / "cache"
    cache.mkdir()
    for name in (
        "ubuntu-noble.qcow2",
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
    assert by_kind["router"].image.reference == "ubuntu-noble"
    spec = two_segment_spec()
    opted_out = spec.model_copy(
        update={"attacker": spec.attacker.model_copy(update={"image": "img"})}
    )
    declared = resolve_plan(opted_out, options(cache))
    attacker = next(g for g in declared.guests if g.kind == "attacker")
    assert attacker.image.reference == "img"


def test_windows_hosts_plan_and_windows_routers_refuse(cache: Path) -> None:
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
    # windows HOSTS plan as of windows-ad-v1 slice 1: the unattend injector
    # and daemon-only readiness; nothing cloud-init touches them
    plan = resolve_plan(spec, PlanOptions(image_cache=cache))
    dc = next(g for g in plan.guests if g.name == "dc")
    assert (dc.os, dc.injector, dc.readiness) == ("windows", "unattend", "daemon")
    # windows ROUTERS still refuse
    routed = spec.model_copy(deep=True)
    routed.networks.append(Network(name="lab2", cidr="10.1.0.0/24", mode="isolated"))
    routed.routers = [
        Router(
            name="winrt",
            os=Os(type="windows"),
            interfaces=[Interface(network="lab"), Interface(network="lab2")],
        )
    ]
    with pytest.raises(IssueError) as excinfo:
        resolve_plan(routed, PlanOptions(image_cache=cache))
    assert any(
        issue.code == "windows-render-not-supported" for issue in excinfo.value.issues
    )


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


def test_router_content_gates_at_planning() -> None:
    """Router `users`/`provisioning` gate exactly like host content: refused on the runtime path, lifted by the build's realized sections, with the coherence rules on top (users realize only through router recipes; content pins a declared image)."""
    from inspect_ranges.types import ProvisioningStep, User

    runtime: frozenset[str] = frozenset()
    build = frozenset({"users", "provisioning"})
    users = [User(name="robot.abc", password="abcrb1357")]
    steps = [ProvisioningStep(recipe="acme.fw")]
    cases: list[
        tuple[
            str,
            list[User],
            list[ProvisioningStep],
            str | None,
            frozenset[str],
            str,
            tuple[str | int, ...],
        ]
    ] = [
        (
            "users gate on the runtime path",
            users,
            [],
            "fw-golden",
            runtime,
            "guest-config-not-realized",
            ("routers", 0, "users"),
        ),
        (
            "provisioning gates on the runtime path",
            [],
            steps,
            "fw-golden",
            runtime,
            "guest-config-not-realized",
            ("routers", 0, "provisioning"),
        ),
        (
            "users without provisioning never realize",
            users,
            [],
            "fw-golden",
            build,
            "realized-section-unconsumed",
            ("routers", 0, "provisioning"),
        ),
        (
            "content on the appliance default cannot key",
            [],
            steps,
            None,
            build,
            "router-image-required",
            ("routers", 0, "image"),
        ),
    ]
    for label, declared_users, declared_steps, image, sections, code, path in cases:
        spec = two_segment_spec()
        spec.routers[0].users = declared_users
        spec.routers[0].provisioning = declared_steps
        spec.routers[0].image = image
        with pytest.raises(IssueError) as excinfo:
            resolve_plan(spec, PlanOptions(realized_sections=sections))
        assert [(i.code, i.path) for i in excinfo.value.issues] == [(code, path)], label
    # the build path with recipes and a declared image plans clean
    spec = two_segment_spec()
    spec.routers[0].users = users
    spec.routers[0].provisioning = steps
    spec.routers[0].image = "fw-golden"
    plan = resolve_plan(spec, PlanOptions(realized_sections=build))
    router = next(g for g in plan.guests if g.kind == "router")
    assert router.image.reference == "fw-golden"


def test_hostname_renders_and_fqdn_gates_at_planning() -> None:
    """A declared `hostname:` renders (realized at render as of windows-ad-v1 slice 4: the plan resolves it, sanitized, for every injector); `fqdn` stays gated on the runtime path — only the build's AD recipes realize it (promotion/join set the primary DNS suffix)."""
    spec = two_segment_spec()
    spec.hosts[0].hostname = "dc01-nyc"
    plan = resolve_plan(spec)
    assert plan.guests[0].hostname == "dc01-nyc"
    underived = next(g for g in plan.guests if g.name == spec.hosts[1].name)
    assert underived.hostname == spec.hosts[1].name  # no declaration: derived
    spec.hosts[0].fqdn = "dc01-nyc.corp.local"
    with pytest.raises(IssueError) as excinfo:
        resolve_plan(spec)
    issue = excinfo.value.issues[0]
    assert issue.code == "guest-config-not-realized"
    assert issue.path == ("hosts", 0, "fqdn")
    # the build path (active_directory realized) lifts the fqdn gate
    assert (
        resolve_plan(
            spec, PlanOptions(realized_sections=frozenset({"active_directory"}))
        )
        .guests[0]
        .hostname
        == "dc01-nyc"
    )


def test_declared_hostnames_feed_the_collision_gate() -> None:
    """Two hosts whose DECLARED hostnames render identically refuse at planning, exactly like colliding names."""
    spec = two_segment_spec()
    spec.hosts[0].hostname = "same-host"
    spec.hosts[1].hostname = "same-host"
    with pytest.raises(IssueError) as excinfo:
        resolve_plan(spec)
    assert any(issue.code == "hostname-collision" for issue in excinfo.value.issues)


def test_variables_resolve_to_defaults_at_planning(cache: Path) -> None:
    """Linux-examples-v1: declared variables never gate planning; loading already substituted their defaults, so a spec with variables plans concretely. A `draw: boot` variable changes nothing here either (variable-draws-v0): draws are a render input, and planning stays on the defaults."""
    from inspect_ranges.schema import load_range

    spec_yaml = """
range:
  name: vars-resolve
  schema_version: "0.3"
  description: variables resolve to defaults
variables:
  svc_port: { type: port, min: 1500, default: 2323, draw: boot }
networks:
  - name: lab
    cidr: 10.0.0.0/24
    mode: isolated
hosts:
  - name: web
    os: { type: linux }
    image: ubuntu-noble
    interfaces: [{ network: lab, ip: 10.0.0.10 }]
attacker:
  image: ubuntu-noble
  interfaces: [{ network: lab }]
  entry: external
"""
    spec_path = cache.parent / "vars-range.yaml"
    spec_path.write_text(spec_yaml)
    spec = load_range(spec_path)
    plan = resolve_plan(spec, options(cache))
    assert plan.range.name == "vars-resolve"


def test_render_carries_the_draws_file(cache: Path, tmp_path: Path) -> None:
    """A render with draws writes the draws file into every Linux guest's seed EXCEPT the agent's foothold (a drawn value is often the expected answer; routers keep their nftables entry beside it); without draws no file appears, and the plan never sees the draws either way (variable-draws-v0)."""
    spec = chained_spec()
    drawn_out = tmp_path / "drawn"
    draws: dict[str, int | str] = {"svc_port": 1507, "flavor": "b"}
    render_bundle(spec, drawn_out, PlanOptions(image_cache=cache, draws=draws))
    for guest in ("safe", "r1", "r2"):
        user_data = yaml.safe_load(
            (drawn_out / f"guests/{guest}/seed/user-data").read_text()
        )
        [entry] = [
            e for e in user_data["write_files"] if e["path"] == "/etc/guestd/draws.json"
        ]
        assert json.loads(entry["content"]) == draws
        assert entry["permissions"] == "0644"
    foothold = yaml.safe_load(
        (drawn_out / "guests/attacker/seed/user-data").read_text()
    )
    assert "write_files" not in foothold, "the foothold never gets the draws file"
    r1 = yaml.safe_load((drawn_out / "guests/r1/seed/user-data").read_text())
    assert any(e["path"] == "/etc/nftables.conf" for e in r1["write_files"])
    plain_out = tmp_path / "plain"
    render_bundle(spec, plain_out, options(cache))
    plain = yaml.safe_load((plain_out / "guests/safe/seed/user-data").read_text())
    assert "write_files" not in plain
    assert (drawn_out / "plan.json").read_bytes() == (
        plain_out / "plan.json"
    ).read_bytes(), "planning ignores draws"


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
    image: ubuntu-noble
    interfaces:
      - { network: a, ip: 192.168.20.5 }
      - { network: uplink }
  - name: single
    os: { type: linux }
    image: ubuntu-noble
    interfaces: [{ network: b, ip: 192.168.30.5 }]
routers:
  - name: r
    interfaces:
      - { network: a, ip: 192.168.20.1 }
      - { network: b, ip: 192.168.30.1 }
attacker:
  image: ubuntu-noble
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


def test_multihomed_tie_break_and_sibling_exclusion(
    cache: Path, tmp_path: Path
) -> None:
    """Two non-NAT gatewayed attachments tie-break by interface index, and sibling routes never shadow a directly-attached subnet (phase review round 1 N3)."""
    import yaml
    from inspect_ranges.schema import load_range

    spec_yaml = """
range:
  name: dualrouted
  schema_version: "0.3"
  description: tie-break and sibling exclusion
networks:
  - name: a
    cidr: 192.168.20.0/24
    mode: isolated
  - name: b
    cidr: 192.168.30.0/24
    mode: isolated
  - name: c
    cidr: 192.168.40.0/24
    mode: isolated
hosts:
  - name: dual
    os: { type: linux }
    image: ubuntu-noble
    interfaces:
      - { network: a, ip: 192.168.20.5 }
      - { network: b, ip: 192.168.30.5 }
routers:
  - name: r
    interfaces:
      - { network: a, ip: 192.168.20.1 }
      - { network: b, ip: 192.168.30.1 }
      - { network: c, ip: 192.168.40.1 }
attacker:
  image: ubuntu-noble
  interfaces: [{ network: c }]
  entry: external
"""
    spec_path = tmp_path / "dualrouted.yaml"
    spec_path.write_text(spec_yaml)
    out = tmp_path / "bundle"
    render_bundle(load_range(spec_path), out, options(cache))
    seeds = {p.parent.parent.name: p for p in out.rglob("network-config")}
    dual = yaml.safe_load(seeds["dual"].read_text())["ethernets"]
    eth0 = dual["eth0"]["routes"]
    eth1 = dual["eth1"]["routes"]
    assert {"to": "default", "via": "192.168.20.1", "metric": 200} in eth0
    assert {"to": "default", "via": "192.168.30.1", "metric": 201} in eth1
    # the sibling list excludes BOTH directly-attached subnets; only c remains
    for routes in (eth0, eth1):
        subnets = [r["to"] for r in routes if r["to"] != "default"]
        assert subnets == ["192.168.40.0/24"], subnets


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


def test_windows_guest_renders_unattend_seed(cache: Path, tmp_path: Path) -> None:
    """Windows-ad-v1 slice 1: a windows host's seed is the per-boot answer file (hostname, MAC-keyed static address, gateway route), its domain carries the scsi-cdrom seed stanza (the implicit specialize search reads removable media; SATA is stripped), and boot.json records the unattend injector with daemon readiness."""
    (cache / "windows-2022.qcow2").write_bytes(b"fake windows golden")
    spec_yaml = """
range:
  name: winrange
  schema_version: "0.3"
  description: one windows host
networks:
  - name: corp
    cidr: 10.20.0.0/24
    mode: isolated
hosts:
  - name: dc_one
    os: { type: windows, version: server-2022 }
    image: windows-2022
    interfaces: [{ network: corp, ip: 10.20.0.10 }]
attacker:
  image: ubuntu-noble
  vmm: qemu                      # a domain XML exists to compare stanzas against
  interfaces: [{ network: corp }]
  entry: external
"""
    from inspect_ranges.schema import load_range

    spec_path = tmp_path / "winrange.yaml"
    spec_path.write_text(spec_yaml)
    out = tmp_path / "bundle"
    render_bundle(load_range(spec_path), out, options(cache))
    unattend = (out / "guests" / "dc_one" / "seed" / "unattend.xml").read_text()
    assert "<ComputerName>dc-one</ComputerName>" in unattend
    assert (
        '<IpAddress wcm:action="add" wcm:keyValue="1">10.20.0.10/24</IpAddress>'
        in unattend
    )
    assert "<DhcpEnabled>false</DhcpEnabled>" in unattend
    assert "RangeAdm" in unattend  # the documented default password answers OOBE
    assert not (out / "guests" / "dc_one" / "seed" / "user-data").exists()
    domain = (out / "guests" / "dc_one" / "domain.xml").read_text()
    assert "virtio-scsi" in domain and "device='cdrom'" in domain
    linux_domain = (out / "guests" / "attacker" / "domain.xml").read_text()
    assert "device='cdrom'" not in linux_domain
    boot = json.loads((out / "boot.json").read_text())
    by_name = {g["name"]: g for g in boot["guests"]}
    assert by_name["dc_one"]["injector"] == "unattend"
    assert by_name["dc_one"]["readiness"] == "daemon"
    assert by_name["attacker"]["injector"] == "cloud-init"


def test_boot_overlay_clamps_to_the_backing_virtual_size(
    cache: Path, tmp_path: Path
) -> None:
    """An overlay created smaller than its backing truncates the guest's disk (Windows refuses 0xc0000001, measured); boot.json clamps overlay_gb up to the backing qcow2's virtual size and leaves larger declarations alone."""
    import subprocess

    subprocess.run(
        ["qemu-img", "create", "-f", "qcow2", str(cache / "big-golden.qcow2"), "40G"],
        check=True,
        capture_output=True,
    )
    from inspect_ranges.schema import load_range

    spec_yaml = """
range:
  name: clampcheck
  schema_version: "0.3"
  description: overlay clamp
networks:
  - name: lab
    cidr: 10.30.0.0/24
    mode: isolated
hosts:
  - name: big
    os: { type: linux }
    image: big-golden
    interfaces: [{ network: lab, ip: 10.30.0.10 }]
  - name: roomy
    os: { type: linux }
    image: big-golden
    resources: { cpus: 1, memory_mb: 1024, disk_gb: 80 }
    interfaces: [{ network: lab, ip: 10.30.0.11 }]
attacker:
  image: ubuntu-noble
  interfaces: [{ network: lab }]
  entry: external
"""
    spec_path = tmp_path / "clampcheck.yaml"
    spec_path.write_text(spec_yaml)
    out = tmp_path / "bundle"
    render_bundle(load_range(spec_path), out, options(cache))
    boot = json.loads((out / "boot.json").read_text())
    by_name = {g["name"]: g for g in boot["guests"]}
    assert by_name["big"]["overlay_gb"] == 40  # clamped up from the 10G default
    assert by_name["roomy"]["overlay_gb"] == 80  # larger declarations stand


def test_windows_cloud_hypervisor_refuses_at_planning(cache: Path) -> None:
    """A Windows host on cloud-hypervisor can never specialize (the unattend seed rides removable media, which CH cannot present), so planning refuses instead of hanging at readiness (slice-1 review finding)."""
    spec = RangeSpec(
        meta=RangeMeta(name="winch", description="windows on cloud-hypervisor"),
        networks=[Network(name="lab", cidr="10.0.0.0/24", mode="isolated")],
        hosts=[
            Host(
                name="dc",
                os=Os(type="windows"),
                image="win-golden",
                vmm="cloud-hypervisor",
                interfaces=[Interface(network="lab")],
            )
        ],
        attacker=Attacker(interfaces=[Interface(network="lab")], entry="external"),
    )
    with pytest.raises(IssueError) as excinfo:
        resolve_plan(spec, options(cache))
    issue = next(
        issue
        for issue in excinfo.value.issues
        if issue.code == "windows-vmm-not-supported"
    )
    assert issue.path == ("hosts", 0, "vmm")


def test_windows_content_host_requires_explicit_ips(cache: Path) -> None:
    """A captured Windows disk bakes its addresses and the build key sees only DECLARED addressing, so a content-carrying Windows host with an auto-allocated interface refuses at planning: an allocator shift elsewhere in the spec would silently re-render against a stale disk (slice-2 review, blocking)."""
    from inspect_ranges.types import ProvisioningStep

    spec = RangeSpec(
        meta=RangeMeta(name="winip", description="windows content ip gate"),
        networks=[Network(name="lab", cidr="10.0.0.0/24", mode="isolated")],
        hosts=[
            Host(
                name="dc",
                os=Os(type="windows"),
                image="win-golden",
                interfaces=[Interface(network="lab")],  # no ip: allocator-assigned
                provisioning=[ProvisioningStep(recipe="win.dc-promote")],
            )
        ],
        attacker=Attacker(interfaces=[Interface(network="lab")], entry="external"),
    )
    build_options = PlanOptions(
        image_cache=cache, realized_sections=frozenset({"provisioning"})
    )
    with pytest.raises(IssueError) as excinfo:
        resolve_plan(spec, build_options)
    issue = next(
        issue for issue in excinfo.value.issues if issue.code == "windows-ip-required"
    )
    assert issue.path == ("hosts", 0, "interfaces", 0)
    # explicit ip resolves it; a content-free windows host stays free to allocate
    spec.hosts[0].interfaces = [Interface(network="lab", ip="10.0.0.10")]
    plan = resolve_plan(spec, build_options)
    assert plan.guests[0].os == "windows"
    free = spec.model_copy(deep=True)
    free.hosts[0].provisioning = []
    free.hosts[0].interfaces = [Interface(network="lab")]
    assert resolve_plan(free, options(cache)).guests[0].os == "windows"


def test_windows_netbios_truncation_collides_at_planning(cache: Path) -> None:
    """Two Windows hosts whose names differ only past the 15-character NetBIOS limit render the same ComputerName; the collision gate checks the truncated form (slice-1 review finding)."""
    spec = RangeSpec(
        meta=RangeMeta(name="winnb", description="netbios collision"),
        networks=[Network(name="lab", cidr="10.0.0.0/24", mode="isolated")],
        hosts=[
            Host(
                name="dc-server-alpha-primary",
                os=Os(type="windows"),
                image="win-golden",
                interfaces=[Interface(network="lab", ip="10.0.0.10")],
            ),
            Host(
                name="dc-server-alpha-secondary",
                os=Os(type="windows"),
                image="win-golden",
                interfaces=[Interface(network="lab", ip="10.0.0.11")],
            ),
        ],
        attacker=Attacker(interfaces=[Interface(network="lab")], entry="external"),
    )
    with pytest.raises(IssueError) as excinfo:
        resolve_plan(spec, options(cache))
    assert any(issue.code == "hostname-collision" for issue in excinfo.value.issues)


@pytest.mark.parametrize(
    ("name", "expected"),
    [
        ("dc", "dc"),
        ("abcdefghijklmno", "abcdefghijklmno"),  # exactly the limit
        ("abcdefghijklmn-xyz", "abcdefghijklmn"),  # no trailing hyphen survives
        ("web_server.alpha99", "web-server-alph"),  # sanitize, then clamp
    ],
)
def test_windows_hostname_clamps_to_netbios(name: str, expected: str) -> None:
    from inspect_ranges._compiler.render import windows_hostname

    assert windows_hostname(name) == expected


def test_windows_seed_carries_the_goldens_recorded_password_escaped(
    cache: Path, tmp_path: Path
) -> None:
    """The seed's Administrator password comes from the golden's provenance sidecar, XML-escaped: a password carrying `<&>` must neither break the answer file's parse nor smuggle elements into it (slice-1 review finding)."""
    recorded = 'P@ss<&>"w'
    (cache / "windows-2022.qcow2").write_bytes(b"fake windows golden")
    (cache / "windows-2022.json").write_text(json.dumps({"admin_password": recorded}))
    spec_yaml = """
range:
  name: winpw
  schema_version: "0.3"
  description: recorded password renders escaped
networks:
  - name: corp
    cidr: 10.20.0.0/24
    mode: isolated
hosts:
  - name: dc
    os: { type: windows, version: server-2022 }
    image: windows-2022
    interfaces: [{ network: corp, ip: 10.20.0.10 }]
attacker:
  image: ubuntu-noble
  interfaces: [{ network: corp }]
  entry: external
"""
    from inspect_ranges.schema import load_range

    spec_path = tmp_path / "winpw.yaml"
    spec_path.write_text(spec_yaml)
    out = tmp_path / "bundle"
    render_bundle(load_range(spec_path), out, options(cache))
    seed = out / "guests" / "dc" / "seed" / "unattend.xml"
    root = ElementTree.fromstring(seed.read_text())  # well-formed despite <&>
    namespace = "{urn:schemas-microsoft-com:unattend}"
    value = root.find(
        f".//{namespace}AdministratorPassword/{namespace}Value",
    )
    assert value is not None and value.text == recorded  # round-trips exactly


def test_windows_multi_gatewayed_host_elects_one_default_route(
    cache: Path, tmp_path: Path
) -> None:
    """A Windows host attached to two gatewayed segments mirrors the Linux election: the NAT attachment's default wins on metric, the router-gatewayed attachment's default is deprioritized — never two unmetered defaults (slice-1 review finding)."""
    (cache / "windows-2022.qcow2").write_bytes(b"fake windows golden")
    spec_yaml = """
range:
  name: winuplink
  schema_version: "0.3"
  description: windows build-uplink shape
networks:
  - name: uplink
    cidr: 10.40.0.0/24
    mode: nat
  - name: corp
    cidr: 10.41.0.0/24
    mode: isolated
routers:
  - name: edge
    interfaces:
      - { network: corp, ip: 10.41.0.1 }
      - { network: uplink }
hosts:
  - name: dc
    os: { type: windows, version: server-2022 }
    image: windows-2022
    interfaces:
      - { network: uplink, ip: 10.40.0.10 }
      - { network: corp, ip: 10.41.0.10 }
attacker:
  image: ubuntu-noble
  interfaces: [{ network: corp }]
  entry: external
"""
    from inspect_ranges.schema import load_range

    spec_path = tmp_path / "winuplink.yaml"
    spec_path.write_text(spec_yaml)
    out = tmp_path / "bundle"
    render_bundle(load_range(spec_path), out, options(cache))
    unattend = (out / "guests" / "dc" / "seed" / "unattend.xml").read_text()
    assert unattend.count("<Prefix>0.0.0.0/0</Prefix>") == 2
    assert "<Metric>50</Metric>" in unattend  # the NAT attachment wins
    assert "<Metric>201</Metric>" in unattend  # corp (index 1) deprioritized


def test_windows_seed_routes_a_link_local_resolver_via_the_gateway(
    cache: Path, tmp_path: Path
) -> None:
    """Windows treats 169.254/16 as on-link and ARPs for it instead of routing it, so a link-local resolver (the VPC-resolver shape the build hands guests) gets an explicit /32 route via the gateway (measured live: resolution dead without it)."""
    (cache / "windows-2022.qcow2").write_bytes(b"fake windows golden")
    spec_yaml = """
range:
  name: winlinklocal
  schema_version: "0.3"
  description: link-local resolver route
networks:
  - name: corp
    cidr: 10.24.0.0/24
    mode: nat
    dns:
      nameservers: [169.254.169.253]
hosts:
  - name: dc
    os: { type: windows, version: server-2022 }
    image: windows-2022
    interfaces: [{ network: corp, ip: 10.24.0.10 }]
attacker:
  image: ubuntu-noble
  interfaces: [{ network: corp }]
  entry: external
"""
    from inspect_ranges.schema import load_range

    spec_path = tmp_path / "winlinklocal.yaml"
    spec_path.write_text(spec_yaml)
    out = tmp_path / "bundle"
    render_bundle(load_range(spec_path), out, options(cache))
    unattend = (out / "guests" / "dc" / "seed" / "unattend.xml").read_text()
    assert "<Prefix>169.254.169.253/32</Prefix>" in unattend
    assert unattend.count("<Prefix>0.0.0.0/0</Prefix>") == 1


def test_windows_seed_carries_the_search_domain(cache: Path, tmp_path: Path) -> None:
    """A records-serving network's derived search domain renders as the Windows connection-specific DNS suffix (`DNSDomain`), the netplan `nameservers.search` analogue — AD short-name resolution needs it (windows-ad-v1 slice 2)."""
    (cache / "windows-2022.qcow2").write_bytes(b"fake windows golden")
    spec_yaml = """
range:
  name: winsearch
  schema_version: "0.3"
  description: windows search suffix
networks:
  - name: corp
    cidr: 10.22.0.0/24
    mode: isolated
    dns:
      records:
        - { name: dc, ip: 10.22.0.10 }
hosts:
  - name: dc
    os: { type: windows, version: server-2022 }
    image: windows-2022
    interfaces: [{ network: corp, ip: 10.22.0.10 }]
attacker:
  image: ubuntu-noble
  interfaces: [{ network: corp }]
  entry: external
"""
    from inspect_ranges.schema import load_range

    spec_path = tmp_path / "winsearch.yaml"
    spec_path.write_text(spec_yaml)
    out = tmp_path / "bundle"
    render_bundle(load_range(spec_path), out, options(cache))
    unattend = (out / "guests" / "dc" / "seed" / "unattend.xml").read_text()
    assert "<DNSDomain>corp.internal</DNSDomain>" in unattend


def test_realized_windows_image_chases_password_to_its_golden(
    cache: Path, tmp_path: Path
) -> None:
    """A captured Windows build's image has only a `.realized.json` sidecar; the seed's Administrator password chases through its `golden_file` to the golden's record instead of silently falling back to the default (windows-ad-v1 slice 2)."""
    recorded = "Fr0m-the-g0lden"
    (cache / "windows-2022.qcow2").write_bytes(b"fake windows golden")
    (cache / "windows-2022.json").write_text(json.dumps({"admin_password": recorded}))
    (cache / "winrange-dc-abc123.qcow2").write_bytes(b"fake realized windows")
    (cache / "winrange-dc-abc123.realized.json").write_text(
        json.dumps(
            {
                "type": "realized",
                "range_name": "winrange",
                "guest": "dc",
                "build_key": "abc123",
                "golden_file": "windows-2022.qcow2",
                "sha256": "x",
                "created": "2026-10-19T00:00:00Z",
            }
        )
    )
    spec_yaml = """
range:
  name: winrealized
  schema_version: "0.3"
  description: realized windows password chase
networks:
  - name: corp
    cidr: 10.23.0.0/24
    mode: isolated
hosts:
  - name: dc
    os: { type: windows, version: server-2022 }
    image: winrange-dc-abc123
    interfaces: [{ network: corp, ip: 10.23.0.10 }]
attacker:
  image: ubuntu-noble
  interfaces: [{ network: corp }]
  entry: external
"""
    from inspect_ranges.schema import load_range

    spec_path = tmp_path / "winrealized.yaml"
    spec_path.write_text(spec_yaml)
    out = tmp_path / "bundle"
    render_bundle(load_range(spec_path), out, options(cache))
    unattend = (out / "guests" / "dc" / "seed" / "unattend.xml").read_text()
    assert recorded in unattend


def test_realized_sections_demand_a_consuming_recipe(cache: Path) -> None:
    """The build claims roles/defense/active_directory REALIZED, and only recipes realize them: a recipe-less host declaring them (or a recipe-less DC under a declared active_directory) refuses `realized-section-unconsumed` on the build path (slice-4 review)."""
    from inspect_ranges.types import (
        ActiveDirectory,
        AdDomain,
        HostDefense,
        ProvisioningStep,
    )

    build_options = PlanOptions(
        image_cache=cache,
        realized_sections=frozenset(
            {"roles", "defense", "active_directory", "provisioning"}
        ),
    )
    spec = RangeSpec(
        meta=RangeMeta(name="unconsumed", description="gate test"),
        networks=[Network(name="lab", cidr="10.0.0.0/24", mode="isolated")],
        hosts=[
            Host(
                name="web",
                os=Os(type="linux"),
                image="ubuntu-noble",
                interfaces=[Interface(network="lab", ip="10.0.0.10")],
                defense=HostDefense(defender=False),
            )
        ],
        attacker=Attacker(interfaces=[Interface(network="lab")], entry="external"),
    )
    with pytest.raises(IssueError) as excinfo:
        resolve_plan(spec, build_options)
    assert any(
        issue.code == "realized-section-unconsumed" for issue in excinfo.value.issues
    )
    # a recipe lifts it
    spec.hosts[0].provisioning = [ProvisioningStep(recipe="acme.web")]
    assert resolve_plan(spec, build_options).guests[0].name == "web"
    # a declared AD whose DC carries no recipe refuses too
    spec.active_directory = ActiveDirectory(
        forest="corp.local",
        domains=[AdDomain(name="corp.local", netbios="CORP", dc="bare")],
    )
    spec.hosts.append(
        Host(
            name="bare",
            os=Os(type="windows"),
            image="windows-2022",
            interfaces=[Interface(network="lab", ip="10.0.0.11")],
        )
    )
    (cache / "windows-2022.qcow2").write_bytes(b"fake windows golden")
    with pytest.raises(IssueError) as excinfo:
        resolve_plan(spec, build_options)
    issue = next(
        issue
        for issue in excinfo.value.issues
        if issue.code == "realized-section-unconsumed"
    )
    assert issue.path == ("active_directory", "domains", 0, "dc")


def test_spec_defense_lifts_only_with_realized_telemetry(cache: Path) -> None:
    """Windows-ad-v1 slice 5: a bare `defense: tier` stays gated everywhere (a classification has no realizable referent — the kypo precedent); a telemetry-bearing posture lifts on the build path, and each flow's source and sink must carry a recipe (`realized-section-unconsumed`)."""
    from inspect_ranges.types import Defense, ProvisioningStep, Telemetry

    def two_hosts() -> RangeSpec:
        return RangeSpec(
            meta=RangeMeta(name="teltier", description="telemetry gate"),
            networks=[Network(name="lab", cidr="10.0.0.0/24", mode="isolated")],
            hosts=[
                Host(
                    name="sensor",
                    os=Os(type="linux"),
                    image="ubuntu-noble",
                    interfaces=[Interface(network="lab", ip="10.0.0.10")],
                    provisioning=[ProvisioningStep(recipe="acme.web")],
                ),
                Host(
                    name="collector",
                    os=Os(type="linux"),
                    image="ubuntu-noble",
                    interfaces=[Interface(network="lab", ip="10.0.0.11")],
                    provisioning=[ProvisioningStep(recipe="acme.db")],
                ),
            ],
            attacker=Attacker(interfaces=[Interface(network="lab")], entry="external"),
        )

    build_options = PlanOptions(
        image_cache=cache,
        realized_sections=frozenset({"defense", "provisioning"}),
    )
    # a bare tier refuses even on the build path
    bare = two_hosts()
    bare.defense = Defense(tier="D2")
    with pytest.raises(IssueError) as excinfo:
        resolve_plan(bare, build_options)
    assert any(issue.path == ("defense",) for issue in excinfo.value.issues)
    # a telemetry-bearing posture with recipes on both ends plans
    flowing = two_hosts()
    flowing.defense = Defense(
        tier="D2",
        telemetry=[Telemetry(source="sensor", collector="sysmon", sink="collector")],
    )
    assert resolve_plan(flowing, build_options).totals.guests == 3
    # the runtime path still refuses it
    with pytest.raises(IssueError) as excinfo:
        resolve_plan(flowing, options(cache))
    assert any(issue.path == ("defense",) for issue in excinfo.value.issues)
    # a recipe-less end refuses as unconsumed
    lame = two_hosts()
    lame.hosts[1].provisioning = []
    lame.defense = Defense(
        tier="D2",
        telemetry=[Telemetry(source="sensor", collector="sysmon", sink="collector")],
    )
    with pytest.raises(IssueError) as excinfo:
        resolve_plan(lame, build_options)
    issue = next(
        issue
        for issue in excinfo.value.issues
        if issue.code == "realized-section-unconsumed"
    )
    assert issue.path == ("defense", "telemetry", 0, "sink")


def test_windows_foothold_attacker_refuses_at_planning(cache: Path) -> None:
    """The attacker surface is POSIX by construction (behavioral chains exec bash on the foothold), so attacker.host naming a Windows guest refuses at planning instead of breaking every chain (phase review round 1 finding A4)."""
    spec = RangeSpec(
        meta=RangeMeta(name="winfoot", description="windows foothold"),
        networks=[Network(name="lab", cidr="10.0.0.0/24", mode="isolated")],
        hosts=[
            Host(
                name="dc",
                os=Os(type="windows"),
                image="win-golden",
                interfaces=[Interface(network="lab", ip="10.0.0.5")],
            )
        ],
        attacker=Attacker(host="dc", entry="external"),
    )
    with pytest.raises(IssueError) as excinfo:
        resolve_plan(spec, options(cache))
    issue = next(
        issue
        for issue in excinfo.value.issues
        if issue.code == "windows-foothold-not-supported"
    )
    assert issue.path == ("attacker", "host")


def test_empty_rendered_hostname_refuses_at_planning(cache: Path) -> None:
    """A declared hostname that sanitizes to nothing (the sanitizer is lowercase-alphabet, so e.g. all-uppercase renders empty) breaks Windows specialize mid-boot and degrades cloud-init; planning refuses per the fail-at-planning contract (phase review round 1 finding A2)."""
    spec = RangeSpec(
        meta=RangeMeta(name="emptyhost", description="empty hostname"),
        networks=[Network(name="lab", cidr="10.0.0.0/24", mode="isolated")],
        hosts=[
            Host(
                name="web",
                hostname="WEB",
                os=Os(type="linux"),
                image="focal",
                interfaces=[Interface(network="lab")],
            )
        ],
        attacker=Attacker(interfaces=[Interface(network="lab")], entry="external"),
    )
    with pytest.raises(IssueError) as excinfo:
        resolve_plan(spec, options(cache))
    issue = next(
        issue for issue in excinfo.value.issues if issue.code == "hostname-empty"
    )
    assert "WEB" in issue.message
    # the Windows branch: 15+ leading invalid chars empty ONLY after the
    # NetBIOS truncate + rstrip, so the per-OS form must be what the gate tests
    win = spec.model_copy(
        update={
            "hosts": [
                Host(
                    name="dc",
                    hostname="_" * 15 + "x",
                    os=Os(type="windows"),
                    image="win-golden",
                    interfaces=[Interface(network="lab", ip="10.0.0.5")],
                )
            ]
        }
    )
    with pytest.raises(IssueError) as excinfo2:
        resolve_plan(win, options(cache))
    assert any(issue.code == "hostname-empty" for issue in excinfo2.value.issues)


def test_scheduled_activity_gates_and_lifts() -> None:
    """`scheduled_activity` gates like every build-claimed section: refused on the runtime path, lifted by the build's realized sections (scheduled-activity-v1)."""
    from inspect_ranges.types import ScheduledActivity

    spec = two_segment_spec()
    spec.hosts[0].scheduled_activity = [
        ScheduledActivity(script="tick.sh", schedule="every 5m")
    ]
    with pytest.raises(IssueError) as excinfo:
        resolve_plan(spec)
    issue = excinfo.value.issues[0]
    assert issue.code == "guest-config-not-realized"
    assert issue.path == ("hosts", 0, "scheduled_activity")
    plan = resolve_plan(
        spec, PlanOptions(realized_sections=frozenset({"scheduled_activity"}))
    )
    assert plan.range.name == spec.meta.name

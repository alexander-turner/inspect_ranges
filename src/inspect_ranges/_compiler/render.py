"""Render the realization bundle: everything `apply` needs to realize a range, with zero further round trips.

The bundle is a directory under a digest-listing `manifest.json`: the resolved plan, the normalized spec (audit), the hardened compose project, the range-netns artifacts (bridges, hypervisor addresses, nftables, dnsmasq), explicit per-guest domain XML (the min-devices strict profile), cloud-init seed inputs, and `boot.json` (images, overlays, CIDs, readiness probes). An applier verifies every digest before acting and refuses on mismatch; rendering is byte-deterministic, so the same spec and options always produce the same bundle digest.

Applier contract (in order): create bridges from `netns/bridges.txt`; add `netns/addresses.txt` addresses; start one dnsmasq per `netns/dnsmasq/*.conf`; load `netns/range.nft`; start libvirtd; build each guest's seed ISO from `guests/<name>/seed/`; define each `guests/<name>/domain.xml` and start it per `boot.json`; wait on every guest's readiness probe.
"""

import hashlib
import json
from ipaddress import IPv4Address, IPv4Network
from pathlib import Path
from typing import Any

import yaml

from ..types import Issue, IssueError, RangeSpec
from .allocate import Allocation
from .dnsmasq import render_dnsmasq_conf
from .egress import render_egress_nftables
from .nftables import render_router_nftables
from .plan import (
    PlannedGuest,
    PlanOptions,
    ResolvedPlan,
    guest_allocation,
    plan_json,
    resolve_plan,
)

_DOMAIN_XML = """<domain type='kvm'>
  <name>{name}</name>
  <memory unit='MiB'>{memory_mb}</memory>
  <vcpu>{cpus}</vcpu>
  <os>
    <type arch='x86_64' machine='q35'>hvm</type>
    <boot dev='hd'/>
  </os>
  <features><acpi/><apic/></features>
  {cpu}
  <on_poweroff>destroy</on_poweroff>
  <on_reboot>restart</on_reboot>
  <on_crash>destroy</on_crash>
  <devices>
    <emulator>/usr/bin/qemu-system-x86_64</emulator>
    <disk type='file' device='disk'>
      <driver name='qemu' type='qcow2'/>
      <source file='/scratch/{name}.qcow2'/>
      <target dev='vda' bus='virtio'/>
    </disk>
    <disk type='file' device='disk'>
      <driver name='qemu' type='raw'/>
      <source file='/scratch/{name}-seed.iso'/>
      <target dev='vdb' bus='virtio'/>
      <readonly/>
    </disk>
{interfaces}    <vsock model='virtio'>
      <cid auto='no' address='{cid}'/>
    </vsock>
    <serial type='file'>
      <source path='/scratch/console/{name}.log' append='on'/>
      <target port='0'/>
    </serial>
    <rng model='virtio'>
      <backend model='random'>/dev/urandom</backend>
    </rng>
    <memballoon model='none'/>
    <controller type='usb' model='none'/>
  </devices>
</domain>
"""

_INTERFACE_XML = """    <interface type='bridge'>
      <source bridge='{bridge}'/>
      <mac address='{mac}'/>
      <model type='virtio'/>
    </interface>
"""

_COMPOSE_ISOLATED = """# Generated realization bundle: hardened range container profile
# (see design/spikes/hardened-container). Docker provides no networking.
services:
  range:
    image: ${RANGE_IMAGE:-inspect-ranges-range:dev}
    init: true
    network_mode: none
    cap_drop: [ALL]
    cap_add: [__CAPS__]
    security_opt:
      - no-new-privileges:true
    devices:
      - /dev/kvm
      - /dev/vhost-vsock
      - /dev/vhost-net
      - /dev/net/tun
    volumes:
      - ${IMAGE_CACHE:-~/.cache/inspect-ranges/images}:/images:ro
      - scratch:/scratch
      - .:/render:ro
    healthcheck:
      test: ["CMD", "test", "-e", "/run/range-ready"]
      interval: 2s
      timeout: 2s
      retries: 30

volumes:
  scratch:
"""

_COMPOSE_UPLINK = _COMPOSE_ISOLATED.replace(
    "    network_mode: none\n",
    """    # this range requests egress: the deployment supplies the uplink network
    networks: [uplink]
    sysctls:
      - net.ipv4.ip_forward=1
""",
).replace(
    "volumes:\n  scratch:\n",
    """networks:
  uplink:
    name: ${UPLINK_NETWORK:?this range requests egress; set UPLINK_NETWORK to the deployment-supplied uplink}
    external: true

volumes:
  scratch:
""",
)


def render_bundle(
    spec: RangeSpec, out: Path, options: PlanOptions | None = None
) -> ResolvedPlan:
    """Resolve a spec and write its realization bundle.

    Args:
        spec: A validated range definition.
        out: Bundle directory (created; must be empty or absent).
        options: Planning options (image cache location, CPU model).

    Returns:
        The resolved plan the bundle carries.

    Raises:
        IssueError: Planning refused (e.g. Windows guests), or a guest image is absent from the cache (`image-not-in-cache`), making a self-sufficient bundle impossible.
        FileExistsError: `out` exists and is not empty.
    """
    plan = resolve_plan(spec, options)
    _require_cached_images(spec, plan)
    out.mkdir(parents=True, exist_ok=True)
    if any(out.iterdir()):
        raise FileExistsError(f"bundle directory {out} is not empty")
    allocation = guest_allocation(plan)
    networks = {network.name: network for network in plan.networks}

    files: dict[str, str] = {}

    def write(relative: str, content: str) -> None:
        path = out / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
        files[relative] = content

    write("plan.json", plan_json(plan))
    write(
        "spec.yaml",
        yaml.safe_dump(
            spec.model_dump(mode="json", by_alias=True, exclude_none=True),
            sort_keys=True,
        ),
    )
    # the measured capability floor (hardened-container spike), widened only by
    # what the plan's services demand, each by an observed failure without it:
    # dnsmasq binding 53/67 needs NET_BIND_SERVICE; DHCP's raw sockets need NET_RAW
    caps = [
        "NET_ADMIN",
        "CHOWN",
        "DAC_OVERRIDE",
        "FOWNER",
        "SETUID",
        "SETGID",
        "SETPCAP",
        "KILL",
    ]
    if any(network.dhcp or network.search is not None for network in plan.networks):
        caps.append("NET_BIND_SERVICE")
    if any(network.dhcp for network in plan.networks):
        caps.append("NET_RAW")
    template = _COMPOSE_UPLINK if plan.requirements.egress_uplink else _COMPOSE_ISOLATED
    write("compose.yaml", template.replace("__CAPS__", ", ".join(caps)))

    write("netns/bridges.txt", "".join(f"{n.bridge}\n" for n in plan.networks))
    write(
        "netns/addresses.txt",
        "".join(
            f"{n.bridge} {n.hypervisor_address}/{n.cidr.prefixlen}\n"
            for n in plan.networks
            if n.hypervisor_address is not None
        ),
    )
    write("netns/range.nft", render_egress_nftables(spec, allocation, uplink="eth0"))
    for network in plan.networks:
        conf = render_dnsmasq_conf(spec, allocation, network.name)
        if conf is not None:
            write(f"netns/dnsmasq/{network.name}.conf", conf)

    for guest in plan.guests:
        cpu = (
            "<cpu mode='host-passthrough'/>"
            if plan.requirements.cpu_model == "host-passthrough"
            else "<cpu mode='custom' match='exact'>"
            f"<model fallback='forbid'>{plan.requirements.cpu_model}</model></cpu>"
        )
        interfaces = "".join(
            _INTERFACE_XML.format(
                bridge=networks[interface.network].bridge, mac=interface.mac
            )
            for interface in guest.interfaces
        )
        write(
            f"guests/{guest.name}/domain.xml",
            _DOMAIN_XML.format(
                name=guest.name,
                memory_mb=guest.memory_mb,
                cpus=guest.cpus,
                cpu=cpu,
                cid=guest.cid,
                interfaces=interfaces,
            ),
        )
        write(
            f"guests/{guest.name}/seed/meta-data",
            f"instance-id: {plan.range.name}-{guest.name}\nlocal-hostname: {guest.name}\n",
        )
        write(
            f"guests/{guest.name}/seed/network-config",
            yaml.safe_dump(_netplan(plan, guest), sort_keys=False),
        )
        write(
            f"guests/{guest.name}/seed/user-data",
            "#cloud-config\n"
            + yaml.safe_dump(
                _user_data(spec, plan, guest, allocation), sort_keys=False
            ),
        )

    write(
        "boot.json",
        json.dumps(
            {
                "parallel": True,
                "guests": [
                    {
                        "name": guest.name,
                        "cid": guest.cid,
                        "image_file": guest.image.file,
                        "image_digest": guest.image.digest,
                        "overlay_gb": guest.disk_gb,
                        "readiness": guest.readiness,
                    }
                    for guest in plan.guests
                ],
                "verify": {"reserved": True},
            },
            sort_keys=True,
            indent=2,
        )
        + "\n",
    )

    manifest = {
        "format_version": "1",
        "range": plan.range.name,
        "spec_sha256": plan.range.spec_sha256,
        "plan_sha256": hashlib.sha256(files["plan.json"].encode()).hexdigest(),
        "files": {
            relative: {
                "sha256": hashlib.sha256(content.encode()).hexdigest(),
                "size": len(content.encode()),
            }
            for relative, content in sorted(files.items())
        },
    }
    (out / "manifest.json").write_text(
        json.dumps(manifest, sort_keys=True, indent=2) + "\n"
    )
    return plan


def _require_cached_images(spec: RangeSpec, plan: ResolvedPlan) -> None:
    paths: dict[str, tuple[Any, ...]] = {
        host.name: ("hosts", index, "image") for index, host in enumerate(spec.hosts)
    }
    for index, router in enumerate(spec.routers):
        paths[router.name] = ("routers", index, "image")
    if spec.attacker.host is None:
        paths[spec.attacker.name] = ("attacker", "image")
    issues = [
        Issue(
            code="image-not-in-cache",
            path=paths[guest.name],
            message=f"image {guest.image.reference!r} for guest {guest.name!r} is not in the image cache, so the bundle cannot be self-sufficient",
            hint="pull or build the image into the cache (pass --image-cache / PlanOptions.image_cache)",
        )
        for guest in plan.guests
        if guest.image.digest is None
    ]
    if issues:
        raise IssueError(issues)


def _netplan(plan: ResolvedPlan, guest: PlannedGuest) -> dict[str, Any]:
    networks = {network.name: network for network in plan.networks}
    ethernets: dict[str, Any] = {}
    for index, interface in enumerate(guest.interfaces):
        nic = f"eth{index}"  # matches router_nic_names() and the rendered rulesets
        network = networks[interface.network]
        entry: dict[str, Any] = {
            "match": {"macaddress": interface.mac},
            "set-name": nic,
        }
        if network.dhcp and guest.kind != "router":
            entry["dhcp4"] = True
        else:
            entry["addresses"] = [f"{interface.ip}/{network.cidr.prefixlen}"]
            if guest.kind == "router":
                static: list[dict[str, str]] = []
                for route in guest.routes:
                    if (
                        isinstance(route.via, IPv4Address)
                        and isinstance(network.cidr, IPv4Network)
                        and route.via in network.cidr
                    ):
                        static.append({"to": str(route.to), "via": str(route.via)})
                if static:
                    entry["routes"] = static
            else:
                if network.gateway is not None:
                    entry["routes"] = [{"to": "default", "via": str(network.gateway)}]
                nameservers: dict[str, Any] = {}
                if network.resolvers:
                    nameservers["addresses"] = [
                        str(address) for address in network.resolvers
                    ]
                if network.search is not None:
                    nameservers["search"] = [network.search]
                if nameservers:
                    entry["nameservers"] = nameservers
        ethernets[nic] = entry
    return {"version": 2, "ethernets": ethernets}


def _user_data(
    spec: RangeSpec, plan: ResolvedPlan, guest: PlannedGuest, allocation: Allocation
) -> dict[str, Any]:
    user_data: dict[str, Any] = {"hostname": guest.name}
    if guest.kind == "router":
        ruleset = "flush ruleset\n" + render_router_nftables(
            spec, guest.name, allocation
        )
        user_data["write_files"] = [{"path": "/etc/nftables.conf", "content": ruleset}]
        user_data["runcmd"] = [
            ["sysctl", "-w", "net.ipv4.ip_forward=1"],
            ["systemctl", "enable", "--now", "nftables"],
        ]
    return user_data

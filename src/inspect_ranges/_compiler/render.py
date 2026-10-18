"""Render the realization bundle: everything `apply` needs to realize a range, with zero further round trips.

The bundle is a directory under a digest-listing `manifest.json`: the resolved plan, the normalized spec (audit), the hardened compose project, the range-netns artifacts (bridges, hypervisor addresses, nftables, dnsmasq), explicit per-guest domain XML (the min-devices strict profile), cloud-init seed inputs, and `boot.json` (images, overlays, CIDs, readiness probes). An applier verifies every digest before acting and refuses on mismatch; rendering is byte-deterministic, so the same spec and options always produce the same bundle digest.

Applier contract (in order): create bridges from `netns/bridges.txt`; add `netns/addresses.txt` addresses; start one dnsmasq per `netns/dnsmasq/*.conf`; load `netns/range.nft`; start libvirtd; build each guest's seed ISO from `guests/<name>/seed/`; define each `guests/<name>/domain.xml` and start it per `boot.json`; wait on every guest's readiness probe.
"""

import hashlib
import json
import logging
import re
from ipaddress import IPv4Address, IPv4Network
from pathlib import Path
from typing import Any, cast
from xml.sax.saxutils import escape

import yaml

from .._evidence.supervisor import (
    BRIDGES_FILENAME,
    SUPERVISOR_FILENAME,
    SUPERVISOR_SOURCE,
    render_bridges_tsv,
)
from ..types import Issue, IssueError, RangeSpec
from .allocate import Allocation
from .dnsmasq import render_dnsmasq_conf
from .egress import render_egress_nftables
from .nftables import render_router_nftables
from .plan import (
    PlannedGuest,
    PlannedNetwork,
    PlanOptions,
    ResolvedPlan,
    guest_allocation,
    guest_uid,
    image_sidecar_file_name,
    plan_json,
    resolve_plan,
)
from .probe import (
    PROBECLIENT_FILENAME,
    PROBECLIENT_SOURCE,
    PROBES_FILENAME,
    render_probe_clamp_nftables,
    render_probes_txt,
)

_DOMAIN_XML = """<domain type='kvm' xmlns:qemu='http://libvirt.org/schemas/domain/qemu/1.0'>
  <name>{name}</name>
  <memory unit='MiB'>{memory_mb}</memory>
  <vcpu>{cpus}</vcpu>
  <os>
    <type arch='x86_64' machine='q35'>hvm</type>
    <boot dev='hd'/>
  </os>
  <features><acpi/><apic/><vmport state='off'/></features>
  {cpu}
  <clock offset='utc'>
    <timer name='hpet' present='no'/>
  </clock>
  <on_poweroff>destroy</on_poweroff>
  <on_reboot>restart</on_reboot>
  <on_crash>destroy</on_crash>
  <!-- per-guest DAC principal (issue #5): sVirt AppArmor cannot load profiles
       inside the hardened container (CAP_MAC_ADMIN + securityfs are denied by
       the outer jail), so per-VM confinement is per-VM IDENTITY instead: each
       QEMU runs as its own uid, the same scheme Cloud Hypervisor guests use;
       relabel stays off because the boot script pre-owns the guest's files -->
  <seclabel type='static' model='dac' relabel='no'>
    <label>+{uid}:kvm</label>
  </seclabel>
  <devices>
    <emulator>/usr/bin/qemu-system-x86_64</emulator>
    <disk type='file' device='disk'>
      <driver name='qemu' type='qcow2'/>
      <source file='/scratch/{name}.qcow2'/>
      <target dev='vda' bus='virtio'/>
    </disk>
{seed_stanza}{interfaces}    <vsock model='virtio'>
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
  <!-- q35 legacy devices no guest uses and libvirt 10.0 has no element for
       (the AHCI controller, the SMBus and its SPD EEPROMs, the i8042 keyboard
       controller, the kvmvapic option ROM); the PIT and PIC stay on -->
  <qemu:commandline>
    <qemu:arg value='-machine'/>
    <qemu:arg value='sata=off,smbus=off,i8042=off'/>
    <qemu:arg value='-global'/>
    <qemu:arg value='kvm-apic.vapic=false'/>
  </qemu:commandline>
</domain>
"""

_INTERFACE_XML = """    <interface type='bridge'>
      <source bridge='{bridge}'/>
      <mac address='{mac}'/>
      <model type='virtio'/>
    </interface>
"""

_SEED_STANZA_LINUX = """\
    <disk type='file' device='disk'>
      <driver name='qemu' type='raw'/>
      <source file='/scratch/{name}-seed.iso'/>
      <target dev='vdb' bus='virtio'/>
      <readonly/>
    </disk>
"""

# Windows' implicit answer-file search covers removable media only, and the
# strict profile strips SATA, so the unattend seed rides a virtio-scsi cdrom
# (the vioscsi driver ships in the golden's guest tools)
_SEED_STANZA_WINDOWS = """\
    <controller type='scsi' model='virtio-scsi'/>
    <disk type='file' device='cdrom'>
      <driver name='qemu' type='raw'/>
      <source file='/scratch/{name}-seed.iso'/>
      <target dev='sda' bus='scsi'/>
      <readonly/>
    </disk>
    <!-- windows setup passes (specialize/OOBE) hang without a display
         adapter (measured: the installer and the first clone boot both);
         the VNC listener binds the range container's loopback, which no
         guest segment can reach -->
    <graphics type='vnc' listen='127.0.0.1' autoport='yes'/>
    <video><model type='vga'/></video>
"""

_COMPOSE_ISOLATED = """# Generated realization bundle: hardened range container profile
# (see design/spikes/hardened-container). Docker provides no networking.
services:
  range:
    image: ${RANGE_IMAGE:-inspect-ranges-range:dev}
    init: true
    network_mode: none
    sysctls: [__SYSCTLS__]
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

_COMPOSE_CAPTURE_SERVICE = """\
  # evidence-capture sidecar (evidence-v1.md, evidence-capture spike): shares
  # the range netns with CAP_NET_RAW alone, so the range container's measured
  # capability floor does not grow and pre-stream pcap chunks live on a volume
  # the range container never mounts
  capture:
    image: ${RANGE_IMAGE:-inspect-ranges-range:dev}
    init: true
    network_mode: service:range
    cap_drop: [ALL]
    cap_add: [NET_RAW]
    security_opt:
      - no-new-privileges:true
    entrypoint: ["python3", "/render/capture/capture.py"]
    environment:
      - CAPTURE_CHUNK_MB=${CAPTURE_CHUNK_MB:-10}
      - CAPTURE_CAP_MB=${CAPTURE_CAP_MB:-2048}
      - CAPTURE_MAX_RESTARTS=${CAPTURE_MAX_RESTARTS:-5}
    volumes:
      - capture:/capture
      - .:/render:ro
"""


def _compose_with_capture(compose: str) -> str:
    """Insert the capture sidecar service and its private volume into a rendered compose text."""
    compose = compose.replace(
        "volumes:\n  scratch:\n", "volumes:\n  scratch:\n  capture:\n"
    )
    marker = "\nnetworks:\n" if "\nnetworks:\n" in compose else "\nvolumes:\n"
    return compose.replace(marker, "\n" + _COMPOSE_CAPTURE_SERVICE + marker, 1)


_COMPOSE_PROBE_SERVICE = """\
  # active-prober sidecar (challenges-v1.md, challenge-prober spike): shares
  # the range netns with ZERO capabilities (the clamped probe veth already
  # exists; the kernel stack does the protocol work), so probes originate from
  # the declared probe identity without growing any capability floor
  probe:
    image: ${RANGE_IMAGE:-inspect-ranges-range:dev}
    init: true
    network_mode: service:range
    cap_drop: [ALL]
    security_opt:
      - no-new-privileges:true
    entrypoint: ["sleep", "infinity"]
    volumes:
      - .:/render:ro
"""


def _compose_with_probe(compose: str) -> str:
    """Insert the zero-capability probe sidecar into a rendered compose text."""
    marker = "\nnetworks:\n" if "\nnetworks:\n" in compose else "\nvolumes:\n"
    return compose.replace(marker, "\n" + _COMPOSE_PROBE_SERVICE + marker, 1)


_COMPOSE_UPLINK = _COMPOSE_ISOLATED.replace(
    "    network_mode: none\n",
    """    # this range requests egress: the deployment supplies the uplink network
    networks: [uplink]
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
    # Guests Ranges itself renders and boots. A `provider: glovebox` guest keeps
    # its reserved IP/MAC allocation (so its segment address is not reused) but is
    # supplied by an external manager, so it gets no domain, seed, or boot entry.
    bootable = [guest for guest in plan.guests if guest.provider == "ranges"]

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
    # interfaces created later in the range netns (bridges, taps) inherit
    # `default`, so none holds an IPv6 address on a segment; set at container
    # create because /proc/sys is read-only inside the container
    sysctls = ["net.ipv6.conf.default.disable_ipv6=1"]
    if plan.requirements.egress_uplink:
        sysctls.append("net.ipv4.ip_forward=1")
    compose = template.replace("__CAPS__", ", ".join(caps)).replace(
        "__SYSCTLS__", ", ".join(sysctls)
    )
    if any(guest.vmm == "cloud-hypervisor" for guest in bootable):
        # Cloud Hypervisor exposes guest vsock as a Unix socket per guest, not
        # through the host kernel's vhost-vsock: the sockets land in a host
        # directory the applier supplies, so host-side dialers can reach them
        anchor = "      - .:/render:ro\n"
        if compose.count(anchor) != 1:
            raise RuntimeError(
                f"compose template has {compose.count(anchor)} {anchor.strip()!r} mounts; "
                "expected exactly one to anchor the cloud-hypervisor vsock mount"
            )
        compose = compose.replace(
            anchor,
            anchor
            + "      - ${CH_VSOCK_DIR:?this range has cloud-hypervisor guests; set CH_VSOCK_DIR}:/run/ch-vsock\n",
        )
    if plan.requirements.evidence_capture:
        compose = _compose_with_capture(compose)
        write(
            f"capture/{BRIDGES_FILENAME}",
            render_bridges_tsv({n.name: n.bridge for n in plan.networks}),
        )
        write(f"capture/{SUPERVISOR_FILENAME}", SUPERVISOR_SOURCE)
    if plan.requirements.probe_segments:
        compose = _compose_with_probe(compose)
        write(f"probe/{PROBECLIENT_FILENAME}", PROBECLIENT_SOURCE)
    write("compose.yaml", compose)

    write("netns/bridges.txt", "".join(f"{n.bridge}\n" for n in plan.networks))
    write(
        "netns/addresses.txt",
        "".join(
            f"{n.bridge} {n.hypervisor_address}/{n.cidr.prefixlen}\n"
            for n in plan.networks
            if n.hypervisor_address is not None
        ),
    )
    if allocation.probe_endpoints:
        subnets = {
            network.name: network.cidr
            for network in plan.networks
            if isinstance(network.cidr, IPv4Network)
        }
        write(f"netns/{PROBES_FILENAME}", render_probes_txt(allocation, subnets))
    nft = render_egress_nftables(spec, allocation, uplink="eth0")
    clamp = render_probe_clamp_nftables(allocation)
    write("netns/range.nft", nft + clamp if clamp else nft)
    for network in plan.networks:
        conf = render_dnsmasq_conf(spec, allocation, network.name)
        if conf is not None:
            write(f"netns/dnsmasq/{network.name}.conf", conf)

    for guest in bootable:
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
        if guest.vmm == "qemu":
            write(
                f"guests/{guest.name}/domain.xml",
                _DOMAIN_XML.format(
                    name=guest.name,
                    memory_mb=guest.memory_mb,
                    cpus=guest.cpus,
                    cpu=cpu,
                    cid=guest.cid,
                    uid=guest_uid(guest.cid),
                    interfaces=interfaces,
                    seed_stanza=(
                        _SEED_STANZA_WINDOWS
                        if guest.os == "windows"
                        else _SEED_STANZA_LINUX
                    ).format(name=guest.name),
                ),
            )
        if guest.injector == "unattend":
            # the file MUST be named unattend.xml: the specialize/OOBE passes'
            # implicit answer-file search matches that name on removable media
            # (autounattend.xml is the installation-media name; measured:
            # specialize ignored it and booted with defaults)
            write(
                f"guests/{guest.name}/seed/unattend.xml",
                _windows_unattend(plan, guest, options),
            )
        else:
            write(
                f"guests/{guest.name}/seed/meta-data",
                # the image file keys the instance-id (parked-decisions item 2):
                # a realized image's name embeds its build key, so a new build
                # generation is a NEW instance and cloud-init re-applies runtime
                # seeds instead of skipping them as already-run
                f"instance-id: {plan.range.name}-{guest.name}-{hashlib.sha256(guest.image.file.encode()).hexdigest()[:8]}\n"
                f"local-hostname: {guest_hostname(guest.name)}\n",
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

    backings = options.realized_backings if options is not None else {}
    write(
        "boot.json",
        json.dumps(
            {
                "parallel": True,
                "guests": [
                    _boot_guest(
                        guest,
                        networks,
                        backings,
                        options.image_cache if options is not None else None,
                    )
                    for guest in bootable
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


def _overlay_gb(guest: PlannedGuest, image_cache: Path | None) -> int:
    """The guest overlay's virtual size: the declared `disk_gb`, clamped up to the backing image's own virtual size (a smaller overlay truncates the disk under the guest)."""
    if image_cache is None:
        return guest.disk_gb
    backing = _qcow2_virtual_gb(image_cache / guest.image.file)
    if backing is None:
        return guest.disk_gb
    return max(guest.disk_gb, backing)


def _qcow2_virtual_gb(path: Path) -> int | None:
    """The qcow2 header's virtual size, in whole GiB rounded up; `None` for raw or unreadable images. An overlay created SMALLER than its backing truncates the guest's disk (Windows refuses to boot with 0xc0000001; measured, windows-ad-v1 slice 1), so boot overlays clamp to this."""
    try:
        with path.open("rb") as handle:
            header = handle.read(32)
    except OSError:
        return None
    if len(header) < 32 or header[:4] != b"QFI\xfb":
        return None
    size = int.from_bytes(header[24:32], "big")
    return max(1, -(-size // (1 << 30)))


def _boot_guest(
    guest: PlannedGuest,
    networks: dict[str, PlannedNetwork],
    backings: dict[str, tuple[str, str]],
    image_cache: Path | None,
) -> dict[str, Any]:
    """One guest's `boot.json` entry; a Cloud Hypervisor guest also carries what its command line needs (it has no domain XML), and a realized guest carries its backing golden (verified by `up`: the overlay digest cannot see its backing)."""
    entry: dict[str, Any] = {
        "name": guest.name,
        "cid": guest.cid,
        "image_file": guest.image.file,
        "image_digest": guest.image.digest,
        "backing_file": backings.get(guest.name, (None, None))[0],
        "backing_digest": backings.get(guest.name, (None, None))[1],
        "overlay_gb": _overlay_gb(guest, image_cache),
        "readiness": guest.readiness,
        "injector": guest.injector,
        "vmm": guest.vmm,
    }
    if guest.vmm == "cloud-hypervisor":
        entry["cpus"] = guest.cpus
        entry["memory_mb"] = guest.memory_mb
        entry["interfaces"] = [
            {"bridge": networks[interface.network].bridge, "mac": interface.mac}
            for interface in guest.interfaces
        ]
    return entry


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
        if guest.provider == "ranges" and guest.image.digest is None
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
                    gatewayed = [
                        networks[other.network]
                        for other in guest.interfaces
                        if networks[other.network].gateway is not None
                    ]
                    if len(gatewayed) == 1:
                        entry["routes"] = [
                            {"to": "default", "via": str(network.gateway)}
                        ]
                    else:
                        # a multi-homed guest (the build uplink shape) must
                        # elect its default deterministically: the NAT-mode
                        # attachment wins; deprioritized router-gatewayed
                        # attachments tie-break by interface index and keep
                        # explicit sibling-subnet routes so cross-segment
                        # traffic still crosses the router. Siblings exclude
                        # the guest's own attachments (connected routes win)
                        # and, until multi-router plans exist (parked: router
                        # provisioning), every non-NAT segment routes via this
                        # gateway.
                        default_metric = 50 if network.mode == "nat" else 200 + index
                        routes = [
                            {
                                "to": "default",
                                "via": str(network.gateway),
                                "metric": default_metric,
                            }
                        ]
                        if network.mode != "nat":
                            attached = {other.network for other in guest.interfaces}
                            routes.extend(
                                {
                                    "to": str(sibling.cidr),
                                    "via": str(network.gateway),
                                }
                                for sibling in plan.networks
                                if sibling.name not in attached
                                and sibling.mode != "nat"
                            )
                        entry["routes"] = routes
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


def guest_hostname(name: str) -> str:
    """The in-guest hostname for a guest name: hostname-invalid characters become hyphens and trailing separators drop. Spec names allow underscores and dots (terraform-derived ranges use them heavily), RFC hostnames do not, and an unsanitized name makes cloud-init's set-hostname module fail — which noble's cloud-init reports as DEGRADED, so `cloud-init status --wait` exits 2 and readiness refuses the guest (linux-examples-v1 slice 3). Planning refuses two guests whose names sanitize identically (`hostname-collision`)."""
    return re.sub(r"[^a-z0-9-]", "-", name).rstrip("-")


logger = logging.getLogger("inspect_ranges.render")

DEFAULT_WINDOWS_ADMIN_PASSWORD = "RangeAdm!n2026"
"""The Windows golden's built-in Administrator password when none was recorded: deliberate scenario content (ranges authenticate in-guest with it; the CONTROL plane is the vsock daemon as SYSTEM and never uses it). The install recipe (`winimage`) shares this constant, so a default-derived golden and a default-rendered seed agree."""

_WINDOWS_UNATTEND_TEMPLATE = """<?xml version="1.0" encoding="utf-8"?>
<!-- Per-boot specialize seed for a sysprep'd inspect-ranges Windows golden:
     hostname, static addressing (interfaces keyed by MAC), and the OOBE
     answers that keep the first boot unattended. Rendered per guest. -->
<unattend xmlns="urn:schemas-microsoft-com:unattend"
          xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State">
  <settings pass="specialize">
    <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64"
               publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
      <ComputerName>{hostname}</ComputerName>
      <TimeZone>UTC</TimeZone>
    </component>
    <component name="Microsoft-Windows-TCPIP" processorArchitecture="amd64"
               publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
      <Interfaces>
{tcpip_interfaces}      </Interfaces>
    </component>
    <component name="Microsoft-Windows-DNS-Client" processorArchitecture="amd64"
               publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
      <Interfaces>
{dns_interfaces}      </Interfaces>
    </component>
  </settings>
  <settings pass="oobeSystem">
    <component name="Microsoft-Windows-International-Core" processorArchitecture="amd64"
               publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
      <InputLocale>en-US</InputLocale>
      <SystemLocale>en-US</SystemLocale>
      <UILanguage>en-US</UILanguage>
      <UserLocale>en-US</UserLocale>
    </component>
    <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64"
               publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
      <OOBE>
        <HideEULAPage>true</HideEULAPage>
        <HideLocalAccountScreen>true</HideLocalAccountScreen>
        <HideOEMRegistrationScreen>true</HideOEMRegistrationScreen>
        <HideOnlineAccountScreens>true</HideOnlineAccountScreens>
        <HideWirelessSetupInOOBE>true</HideWirelessSetupInOOBE>
        <ProtectYourPC>3</ProtectYourPC>
      </OOBE>
      <UserAccounts>
        <AdministratorPassword>
          <Value>{admin_password}</Value><PlainText>true</PlainText>
        </AdministratorPassword>
      </UserAccounts>
    </component>
  </settings>
</unattend>
"""

_TCPIP_INTERFACE = """\
        <Interface wcm:action="add">
          <Identifier>{mac}</Identifier>
          <Ipv4Settings>
            <DhcpEnabled>false</DhcpEnabled>
            <RouterDiscoveryEnabled>false</RouterDiscoveryEnabled>
          </Ipv4Settings>
          <UnicastIpAddresses>
            <IpAddress wcm:action="add" wcm:keyValue="1">{ip}/{prefix}</IpAddress>
          </UnicastIpAddresses>
{routes}        </Interface>
"""

_TCPIP_ROUTES_WRAPPER = """\
          <Routes>
{routes}          </Routes>
"""

_TCPIP_ROUTE = """\
            <Route wcm:action="add">
              <Identifier>{identifier}</Identifier>
              <Prefix>{prefix}</Prefix>
              <NextHopAddress>{via}</NextHopAddress>
{metric}            </Route>
"""

_DNS_INTERFACE = """\
        <Interface wcm:action="add">
          <Identifier>{mac}</Identifier>
          <DNSServerSearchOrder>
{servers}          </DNSServerSearchOrder>
        </Interface>
"""


def windows_hostname(name: str) -> str:
    """The NetBIOS-safe in-guest name: the sanitized hostname truncated to 15 characters (the NetBIOS limit; longer names make specialize warn and truncate unpredictably)."""
    return guest_hostname(name)[:15].rstrip("-")


def _windows_unattend(
    plan: ResolvedPlan, guest: PlannedGuest, options: "PlanOptions | None"
) -> str:
    """The per-boot specialize answer file for a Windows guest: hostname, MAC-keyed static addressing, resolvers, and the OOBE answers. The Administrator password comes from the golden's recorded metadata (scenario content, local-only), falling back to the documented default."""
    networks = {network.name: network for network in plan.networks}
    gatewayed = [
        networks[other.network]
        for other in guest.interfaces
        if networks[other.network].gateway is not None
    ]
    tcpip: list[str] = []
    dns: list[str] = []
    for index, interface in enumerate(guest.interfaces):
        network = networks[interface.network]
        mac = interface.mac.upper().replace(":", "-")
        route_specs: list[tuple[str, str, int | None]] = []
        if network.gateway is not None:
            if len(gatewayed) == 1:
                route_specs.append(("0.0.0.0/0", str(network.gateway), None))
            else:
                # the linux election, mirrored (the build uplink shape): the
                # NAT-mode attachment wins the default; deprioritized
                # router-gatewayed attachments tie-break by interface index
                # and keep explicit sibling-subnet routes so cross-segment
                # traffic still crosses the router
                default_metric = 50 if network.mode == "nat" else 200 + index
                route_specs.append(("0.0.0.0/0", str(network.gateway), default_metric))
                if network.mode != "nat":
                    attached = {other.network for other in guest.interfaces}
                    route_specs.extend(
                        (str(sibling.cidr), str(network.gateway), None)
                        for sibling in plan.networks
                        if sibling.name not in attached and sibling.mode != "nat"
                    )
        routes = ""
        if route_specs:
            rendered = "".join(
                _TCPIP_ROUTE.format(
                    identifier=identifier,
                    prefix=prefix,
                    via=via,
                    metric=(
                        f"              <Metric>{metric}</Metric>\n"
                        if metric is not None
                        else ""
                    ),
                )
                for identifier, (prefix, via, metric) in enumerate(route_specs, start=1)
            )
            routes = _TCPIP_ROUTES_WRAPPER.format(routes=rendered)
        tcpip.append(
            _TCPIP_INTERFACE.format(
                mac=mac,
                ip=interface.ip,
                prefix=network.cidr.prefixlen,
                routes=routes,
            )
        )
        if network.resolvers:
            servers = "".join(
                f'            <IpAddress wcm:action="add" wcm:keyValue="{index + 1}">{address}</IpAddress>\n'
                for index, address in enumerate(network.resolvers)
            )
            dns.append(_DNS_INTERFACE.format(mac=mac, servers=servers))
    return _WINDOWS_UNATTEND_TEMPLATE.format(
        hostname=windows_hostname(guest.name),
        tcpip_interfaces="".join(tcpip),
        dns_interfaces="".join(dns),
        # the password is the one spec-side value a template cannot constrain:
        # XML-escape it so no password can break (or smuggle elements into)
        # the answer file
        admin_password=escape(_windows_admin_password(options, guest)),
    )


def _windows_admin_password(options: "PlanOptions | None", guest: PlannedGuest) -> str:
    """The golden's recorded Administrator password (its provenance sidecar, local-only scenario content), else `DEFAULT_WINDOWS_ADMIN_PASSWORD`. Every fallback logs: a seed carrying the wrong password RESETS the clone's Administrator at OOBE, so silence here would diverge a range from its golden invisibly."""
    if options is None or options.image_cache is None:
        logger.warning(
            "windows guest %r renders without an image cache; the seed carries the default Administrator password",
            guest.name,
        )
        return DEFAULT_WINDOWS_ADMIN_PASSWORD
    sidecar = options.image_cache / image_sidecar_file_name(guest.image.file)
    try:
        loaded: object = json.loads(sidecar.read_text())
    except FileNotFoundError:
        logger.warning(
            "windows guest %r: image %s has no provenance sidecar; the seed carries the default Administrator password",
            guest.name,
            guest.image.file,
        )
        return DEFAULT_WINDOWS_ADMIN_PASSWORD
    except (OSError, ValueError):
        logger.warning(
            "windows guest %r: sidecar %s is unreadable; the seed carries the default Administrator password",
            guest.name,
            sidecar.name,
        )
        return DEFAULT_WINDOWS_ADMIN_PASSWORD
    if isinstance(loaded, dict):
        password = cast(dict[str, object], loaded).get("admin_password")
        if isinstance(password, str) and password:
            return password
    logger.warning(
        "windows guest %r: golden %s records no Administrator password; the seed carries the default",
        guest.name,
        guest.image.file,
    )
    return DEFAULT_WINDOWS_ADMIN_PASSWORD


def _user_data(
    spec: RangeSpec, plan: ResolvedPlan, guest: PlannedGuest, allocation: Allocation
) -> dict[str, Any]:
    user_data: dict[str, Any] = {"hostname": guest_hostname(guest.name)}
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

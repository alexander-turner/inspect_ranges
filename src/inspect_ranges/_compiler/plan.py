"""The resolved plan: one immutable, deterministic resolution of a spec, emitted before any mutation.

`resolve_plan` turns a validated `RangeSpec` into everything downstream stages consume: per-guest allocations (addresses, MACs, CIDs), per-network realization facts (bridge, gateway, resolvers, search domain), image references with cache-resolved digests, host requirements, and resource totals. Unsupported combinations fail here, at planning, as `IssueError`s with stable codes — never mid-boot. The plan is pure data with no timestamps, so the same spec and options always produce byte-identical `plan.json` (see `plan_json`).

Render scope: Linux guests inject configuration via cloud-init; Windows HOSTS inject via a per-boot unattend seed with daemon-only readiness (windows-ad-v1 slice 1). Windows routers and attackers still refuse at planning (`windows-render-not-supported`).
"""

import hashlib
import json
import re
from ipaddress import IPv4Address
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, Field

from ..types import AnyIPNetwork, Attacker, Issue, IssueError, RangeSpec, Route, Vmm
from .allocate import (
    Allocation,
    GuestAllocation,
    GuestKind,
    InterfaceAllocation,
    ProbeEndpoint,
    allocate,
)
from .dnsmasq import resolvers_for, search_domain
from .egress import bridge_name
from .routing import elect_gateways

DEFAULT_ROUTER_IMAGE = "ubuntu-noble"
"""Image for routers when none is declared (module constant so pre-plan consumers, like the provider's catalog-image fetch, apply the same default)."""

DEFAULT_ATTACKER_IMAGE = "attack"
"""Image for a dedicated attack box when none is declared: the catalog's standard attack image."""


class PlanOptions(BaseModel):
    """Host-class declarations and resolution inputs for planning (never per-instance probes)."""

    image_cache: Path | None = None
    """Local image cache for digest resolution; images not found resolve with `digest: None`, loudly visible in the plan."""

    cpu_model: str = "host-passthrough"
    """Guest CPU model; checkpointed fleets use a named model (see range-build.md)."""

    default_router_image: str = DEFAULT_ROUTER_IMAGE
    """Image for routers when none is declared."""

    default_attacker_image: str = DEFAULT_ATTACKER_IMAGE
    """Image for a dedicated attack box when none is declared: the catalog's standard attack image (standard-images-v1), resolved like any bare name (pin, cache, then the search path, whose default tail is the public org)."""

    cid_base: int = Field(default=3, ge=3)
    """First vsock CID; at least 3 (0 through 2 are reserved by vsock itself). A plan-time input: CIDs are render inputs, host-kernel-global, and partitioned per realizer-v1.md (batteries at 3000 and up, the channel harness below 3000)."""

    evidence_capture: bool = False
    """Render the evidence-capture sidecar (per-segment pcap per `evidence-v1.md`). A plan-time input because the sidecar is part of the realization: the bundle's compose project and digest change with it."""

    probe_segments: tuple[str, ...] = ()
    """Networks that get a declared probe endpoint (the clamped veth of the challenge-prober spike) plus the zero-capability probe sidecar. A plan-time input for the same reason as `evidence_capture`; set by the provider from the challenge's `active-prober` requirements."""

    realized_sections: frozenset[str] = frozenset()
    """Host guest-config sections the caller realizes itself, exempted from the `guest-config-not-realized` gate. Set by the build pipeline (`provisioning` as of build-v1 slice 2); the runtime path never sets it, so unbuilt content stays honestly inert."""

    realized_backings: dict[str, tuple[str, str]] = {}
    """Per-guest (backing golden cache file, `sha256:` digest) for realized overlays, recorded into boot.json so `up` verifies the overlay's backing at boot (round-2 review: goldens re-derive in place under the same name, and the overlay's own digest cannot see its backing). Set from the consumed build manifest by every gate consumer that renders."""


class ImageRef(BaseModel):
    """An image as the plan records it: the logical reference plus its cache-resolved digest."""

    reference: str
    """The spec's image reference, verbatim."""

    file: str
    """The cache file name realization uses (mounted at `/images` in the range container)."""

    digest: str | None
    """`sha256:...` of the cache file, or `None` when the image is not in the cache (digest-pinning discipline arrives with the image pipeline)."""


class PlannedNetwork(BaseModel):
    """One network, fully resolved for realization."""

    name: str
    cidr: AnyIPNetwork
    mode: Literal["isolated", "nat", "routed"]
    bridge: str
    """The range-netns bridge device name."""
    dhcp: bool
    gateway: IPv4Address | None
    """The elected default gateway (router or hypervisor), when one exists."""
    hypervisor_address: IPv4Address | None
    """The reserved bridge address, when the hypervisor must be present (nat/routed gateway, dhcp/records service)."""
    resolvers: list[IPv4Address]
    """Resolver addresses handed to this network's guests."""
    search: str | None
    """Derived search domain, for records-serving networks."""
    probe_endpoint: ProbeEndpoint | None = None
    """The declared probe endpoint (clamped veth), when a challenge's `active-prober` observer requested this segment."""


class PlannedGuest(BaseModel):
    """One guest, fully resolved for realization."""

    name: str
    kind: GuestKind
    cid: int
    os: Literal["linux", "windows"]
    image: ImageRef
    cpus: int
    memory_mb: int
    disk_gb: int
    interfaces: list[InterfaceAllocation]
    routes: list[Route]
    """Static routes (routers only)."""
    injector: Literal["cloud-init", "unattend"]
    """How configuration reaches the guest (render v1: cloud-init only)."""
    readiness: Literal["cloud-init", "daemon"]
    """What the applier waits on before the range is ready."""
    profile: Literal["strict"]
    """Device-model profile (min-devices strict; richer profiles arrive with a schema field)."""
    vmm: Vmm = "qemu"
    """Virtual machine monitor: `qemu` boots from the guest's domain XML via libvirt; `cloud-hypervisor` is started directly by the boot script."""


class Requirements(BaseModel):
    """What a host must provide to realize this plan; mismatches refuse at admission, not mid-boot."""

    cpu_model: str
    devices: list[str]
    """Host device nodes the range container needs."""
    egress_uplink: bool
    """Whether the deployment must supply an uplink network (any nat/routed network or attacker egress)."""

    evidence_capture: bool = False
    """Whether the bundle carries the evidence-capture sidecar (per-segment pcap on a `CAP_NET_RAW`-only compose service; the range container's own capability floor is unchanged by this)."""

    probe_segments: tuple[str, ...] = ()
    """Networks carrying a declared probe endpoint and the zero-capability probe sidecar (sorted; empty means no prober)."""


class Totals(BaseModel):
    """Admission-control sums."""

    guests: int
    cpus: int
    memory_mb: int


class RangeIdentity(BaseModel):
    """Which spec this plan resolves."""

    name: str
    schema_version: str
    spec_sha256: str
    """sha256 of the normalized spec (stable across YAML formatting)."""


class ResolvedPlan(BaseModel):
    """The immutable resolution every downstream stage consumes."""

    format_version: Literal["1"] = "1"
    range: RangeIdentity
    networks: list[PlannedNetwork]
    guests: list[PlannedGuest]
    requirements: Requirements
    totals: Totals


def spec_sha256(spec: RangeSpec) -> str:
    """The normalized spec hash: canonical JSON of the validated model, independent of YAML formatting."""
    normalized = json.dumps(spec.model_dump(mode="json", by_alias=True), sort_keys=True)
    return hashlib.sha256(normalized.encode()).hexdigest()


def plan_json(plan: ResolvedPlan) -> str:
    """The plan's canonical serialization: sorted keys, no timestamps, byte-deterministic."""
    return json.dumps(plan.model_dump(mode="json"), sort_keys=True, indent=2) + "\n"


_EVIDENCE_NAME = re.compile(r"^[a-z0-9][a-z0-9._-]*$")
"""Names that fit the evidence stream grammar (`pcap/<network>`, `console/<guest>`); checked at planning when capture is enabled so a nonconforming name refuses up front instead of silently shipping no evidence."""


def _evidence_name_issues(spec: RangeSpec) -> list[Issue]:
    issues: list[Issue] = []
    named: list[tuple[str, tuple[Any, ...]]] = [
        (network.name, ("networks", index, "name"))
        for index, network in enumerate(spec.networks)
    ]
    named += [
        (host.name, ("hosts", index, "name")) for index, host in enumerate(spec.hosts)
    ]
    named += [
        (router.name, ("routers", index, "name"))
        for index, router in enumerate(spec.routers)
    ]
    if spec.attacker.host is None:
        named.append((spec.attacker.name, ("attacker", "name")))
    for name, path in named:
        if _EVIDENCE_NAME.match(name) is None:
            issues.append(
                Issue(
                    code="evidence-capture-name",
                    path=path,
                    message=f"name {name!r} does not fit the evidence stream grammar (lowercase letters, digits, '._-', starting alphanumeric), so its pcap/console streams cannot be recorded",
                    hint="rename the network/guest, or render without --evidence-capture",
                )
            )
    return issues


def _attacker_vmm(attacker: Attacker) -> Vmm:
    """The attacker box's effective VMM: a declared value wins; a dedicated attack box with none declared defaults to `cloud-hypervisor` (hosts and routers default to `qemu`)."""
    return attacker.vmm or "cloud-hypervisor"


def resolve_plan(spec: RangeSpec, options: PlanOptions | None = None) -> ResolvedPlan:
    """Resolve a validated spec into the immutable plan.

    Args:
        spec: A validated range definition.
        options: Host-class declarations (image cache, CPU model, defaults).

    Returns:
        The resolved plan.

    Raises:
        IssueError: The spec uses constructs planning cannot realize (e.g. Windows guests in render v1), with one issue per occurrence.
    """
    options = options or PlanOptions()
    issues: list[Issue] = []
    if options.evidence_capture:
        issues.extend(_evidence_name_issues(spec))
    declared_networks = {network.name for network in spec.networks}
    for segment in options.probe_segments:
        if segment not in declared_networks:
            issues.append(
                Issue(
                    code="probe-segment-unknown",
                    path=("networks",),
                    message=f"probe segment {segment!r} is not a declared network",
                    hint="probe segments come from the challenge's active-prober goals; the goal's host must sit on a declared network",
                )
            )
    # windows HOSTS realize (windows-ad-v1 slice 1: the unattend injector and
    # daemon readiness); windows routers still refuse below, and the attacker
    # is linux by construction (the Attacker schema declares no `os` field)
    for section, declared_list in (("hosts", spec.hosts), ("routers", spec.routers)):
        for index, guest_decl in enumerate(declared_list):
            content = any(
                getattr(guest_decl, section_field, None)
                for section_field in ("provisioning", "services", "vulnerabilities")
            )
            if guest_decl.vmm == "cloud-hypervisor" and content:
                # the build captures provisioned guests through virsh domstate,
                # which cannot see Cloud Hypervisor guests: fail closed until
                # CH capture lands (parked with the CH follow-ups)
                issues.append(
                    Issue(
                        code="cloud-hypervisor-content-unsupported",
                        path=(section, index, "vmm"),
                        message=f"guest {guest_decl.name!r} runs on cloud-hypervisor and declares guest content, which the build cannot capture yet",
                        hint="run this guest on qemu, or drop its content sections",
                    )
                )
    if options.cpu_model != "host-passthrough":
        # Cloud Hypervisor takes no CPU model: its guests always see the host
        # CPU, so a pinned model would silently not apply to them
        pinned_cpu_guests: list[tuple[tuple[Any, ...], str, Any]] = [
            (("hosts", index), host.name, host.vmm)
            for index, host in enumerate(spec.hosts)
        ]
        pinned_cpu_guests += [
            (("routers", index), r.name, r.vmm) for index, r in enumerate(spec.routers)
        ]
        if spec.attacker.host is None:
            pinned_cpu_guests.append(
                (("attacker",), spec.attacker.name, _attacker_vmm(spec.attacker))
            )
        issues.extend(
            Issue(
                code="cloud-hypervisor-cpu-model",
                path=(*path, "vmm"),
                message=f"guest {name!r} runs on cloud-hypervisor, which cannot apply the pinned CPU model {options.cpu_model!r}",
                hint="use cpu_model host-passthrough, or run this guest on qemu",
            )
            for path, name, vmm in pinned_cpu_guests
            if vmm == "cloud-hypervisor"
        )
    for index, router in enumerate(spec.routers):
        if router.os is not None and router.os.type == "windows":
            issues.append(
                Issue(
                    code="windows-render-not-supported",
                    path=("routers", index, "os", "type"),
                    message=f"router {router.name!r} is a Windows guest, which render v1 cannot realize",
                    hint="Windows injectors (unattend/qemu-ga, checkpoints) arrive with the build-manifest phase",
                )
            )
    for index, host in enumerate(spec.hosts):
        if host.os.type == "windows" and host.vmm == "cloud-hypervisor":
            # the unattend seed rides a removable scsi cdrom and Windows'
            # implicit answer-file search only looks at removable media; Cloud
            # Hypervisor attaches disks as plain virtio-blk, so such a guest
            # would boot and never specialize — fail here, never mid-boot
            issues.append(
                Issue(
                    code="windows-vmm-not-supported",
                    path=("hosts", index, "vmm"),
                    message=f"host {host.name!r} is a Windows guest declared on cloud-hypervisor, which cannot deliver the unattend specialize seed",
                    hint="run Windows hosts on qemu (the default)",
                )
            )
    from .render import guest_hostname, windows_hostname

    hostnames: dict[str, str] = {}
    named_guests: list[tuple[str, bool]] = [
        (host.name, host.os.type == "windows") for host in spec.hosts
    ]
    named_guests += [(router.name, False) for router in spec.routers]
    if spec.attacker.host is None:
        named_guests.append((spec.attacker.name, False))
    for guest_name, is_windows in named_guests:
        # the collision gate checks the hostname each guest actually renders:
        # Windows names also truncate to the 15-character NetBIOS limit, so two
        # long names can collide after truncation alone
        sanitized = (
            windows_hostname(guest_name) if is_windows else guest_hostname(guest_name)
        )
        if sanitized in hostnames and hostnames[sanitized] != guest_name:
            issues.append(
                Issue(
                    code="hostname-collision",
                    path=("hosts",),
                    message=f"guests {hostnames[sanitized]!r} and {guest_name!r} both render the in-guest hostname {sanitized!r}",
                    hint="hostname-invalid characters sanitize to hyphens and Windows names truncate to the 15-character NetBIOS limit; rename one guest so the rendered forms differ",
                )
            )
        else:
            hostnames[sanitized] = guest_name
    _GUEST_CONTENT_HINT = "guest configuration is applied and verified at range build; the build pipeline is the next phase (see guest-config-v0.3)"
    for index, host in enumerate(spec.hosts):
        fields = [
            "users",
            "services",
            "vulnerabilities",
            "misconfigurations",
            "data",
            "provisioning",
            "roles",
            "scheduled_activity",
        ]
        for field_name in fields:
            if field_name in options.realized_sections:
                continue
            if getattr(host, field_name):
                issues.append(
                    Issue(
                        code="guest-config-not-realized",
                        path=("hosts", index, field_name),
                        message=f"host {host.name!r} declares {field_name}, which the build phase has not yet realized",
                        hint=_GUEST_CONTENT_HINT,
                    )
                )
        if host.defense is not None:
            issues.append(
                Issue(
                    code="guest-config-not-realized",
                    path=("hosts", index, "defense"),
                    message=f"host {host.name!r} declares defense toggles, which the build phase has not yet realized",
                    hint=_GUEST_CONTENT_HINT,
                )
            )
        for field_name in ("hostname", "fqdn"):
            if getattr(host, field_name) is not None:
                issues.append(
                    Issue(
                        code="guest-config-not-realized",
                        path=("hosts", index, field_name),
                        message=f"host {host.name!r} declares {field_name}, which render v1 does not realize (the rendered in-guest hostname is the hostname-safe form of the host's name)",
                        hint=_GUEST_CONTENT_HINT,
                    )
                )
    for index, router in enumerate(spec.routers):
        if router.users:
            issues.append(
                Issue(
                    code="guest-config-not-realized",
                    path=("routers", index, "users"),
                    message=f"router {router.name!r} declares users, which the build phase has not yet realized",
                    hint=_GUEST_CONTENT_HINT,
                )
            )
    if spec.defense is not None:
        issues.append(
            Issue(
                code="guest-config-not-realized",
                path=("defense",),
                message="the range declares a defensive posture, which the build phase has not yet realized",
                hint=_GUEST_CONTENT_HINT,
            )
        )
    if spec.active_directory is not None:
        issues.append(
            Issue(
                code="guest-config-not-realized",
                path=("active_directory",),
                message="the range declares Active Directory identity data, which the build phase has not yet realized",
                hint=_GUEST_CONTENT_HINT,
            )
        )
    if issues:
        raise IssueError(issues)

    allocation = allocate(
        spec,
        cid_base=options.cid_base,
        probe_networks=frozenset(options.probe_segments),
    )
    gateways = elect_gateways(spec, allocation)

    networks: list[PlannedNetwork] = []
    for network in spec.networks:
        serves_records = network.dns is not None and network.dns.records is not None
        networks.append(
            PlannedNetwork(
                name=network.name,
                cidr=network.cidr,
                mode=network.mode,
                bridge=bridge_name(network.name),
                dhcp=network.dhcp,
                gateway=gateways.get(network.name),
                hypervisor_address=allocation.hypervisor_addresses.get(network.name),
                probe_endpoint=allocation.probe_endpoints.get(network.name),
                resolvers=resolvers_for(spec, allocation, network.name),
                search=search_domain(network.name) if serves_records else None,
            )
        )

    specs_by_name: dict[str, Any] = {host.name: host for host in spec.hosts}
    for router in spec.routers:
        specs_by_name[router.name] = router
    if spec.attacker.host is None:
        specs_by_name[spec.attacker.name] = spec.attacker

    guests: list[PlannedGuest] = []
    for guest in allocation.guests:
        declared = specs_by_name[guest.name]
        reference = getattr(declared, "image", None)
        if reference is None:
            reference = (
                options.default_attacker_image
                if guest.kind == "attacker"
                else options.default_router_image
            )
        resources = getattr(declared, "resources", None)
        vmm = _attacker_vmm(spec.attacker) if guest.kind == "attacker" else declared.vmm
        # windows hosts realize through the unattend injector and daemon-only
        # readiness (windows-ad-v1 slice 1); routers and attackers stay linux
        windows = (
            guest.kind == "host" and specs_by_name[guest.name].os.type == "windows"
        )
        guests.append(
            PlannedGuest(
                name=guest.name,
                kind=guest.kind,
                cid=guest.cid,
                os="windows" if windows else "linux",
                image=_resolve_image(reference, options.image_cache),
                cpus=resources.cpus if resources else 1,
                memory_mb=resources.memory_mb if resources else 1024,
                disk_gb=(resources.disk_gb if resources and resources.disk_gb else 10),
                interfaces=guest.interfaces,
                routes=list(getattr(declared, "routes", [])),
                injector="unattend" if windows else "cloud-init",
                readiness="daemon" if windows else "cloud-init",
                profile="strict",
                vmm=vmm,
            )
        )

    egress_uplink = (
        any(network.mode in ("nat", "routed") for network in spec.networks)
        or spec.attacker.egress != "none"
    )

    return ResolvedPlan(
        range=RangeIdentity(
            name=spec.meta.name,
            schema_version=spec.meta.schema_version,
            spec_sha256=spec_sha256(spec),
        ),
        networks=networks,
        guests=guests,
        requirements=Requirements(
            cpu_model=options.cpu_model,
            devices=["/dev/kvm", "/dev/vhost-vsock", "/dev/vhost-net", "/dev/net/tun"],
            egress_uplink=egress_uplink,
            evidence_capture=options.evidence_capture,
            probe_segments=tuple(sorted(options.probe_segments)),
        ),
        totals=Totals(
            guests=len(guests),
            cpus=sum(guest.cpus for guest in guests),
            memory_mb=sum(guest.memory_mb for guest in guests),
        ),
    )


def image_file_name(reference: str) -> str:
    """The cache file a logical image reference maps to: `/` and `:` become `-`, and `.qcow2` is appended unless the reference already names a known image format. One rule shared by planning and `images derive`."""
    normalized = reference.replace("/", "-").replace(":", "-")
    if normalized.endswith((".qcow2", ".img", ".iso")):
        return normalized
    return f"{normalized}.qcow2"


def image_sidecar_file_name(file: str) -> str:
    """The provenance sidecar name for a cache image file: the full name with `.qcow2` swapped for `.json` (not `Path.stem`: golden names may contain dots). One rule shared by the image cache and the render stages that read recorded metadata."""
    return file.removesuffix(".qcow2") + ".json"


GUEST_UID_BASE = 1_000_000
"""Every guest VMM runs as its own uid, `GUEST_UID_BASE + cid`: CIDs are leased host-unique, so no two VMM processes (QEMU via the DAC seclabel, Cloud Hypervisor via setpriv) share a uid, and none shares `libvirt-qemu` or root."""


def guest_uid(cid: int) -> int:
    """The uid the guest's VMM process runs as (see `GUEST_UID_BASE`)."""
    return GUEST_UID_BASE + cid


def resolve_image_reference(reference: str, cache: Path | None) -> ImageRef:
    """Resolve a logical image reference against the cache (the shared file-name rule plus a content digest when present); the build pipeline's public entry to the same resolution planning uses."""
    return _resolve_image(reference, cache)


def _resolve_image(reference: str, cache: Path | None) -> ImageRef:
    file = image_file_name(reference)
    digest: str | None = None
    if cache is not None and (cache / file).is_file():
        hasher = hashlib.sha256()
        with open(cache / file, "rb") as handle:
            for chunk in iter(lambda: handle.read(1 << 22), b""):
                hasher.update(chunk)
        digest = f"sha256:{hasher.hexdigest()}"
    return ImageRef(reference=reference, file=file, digest=digest)


def guest_allocation(plan: ResolvedPlan) -> Allocation:
    """Reconstruct the `Allocation` view of a plan, for the render stages that consume one."""
    return Allocation(
        guests=[
            GuestAllocation(
                name=guest.name,
                kind=guest.kind,
                cid=guest.cid,
                interfaces=guest.interfaces,
            )
            for guest in plan.guests
        ],
        hypervisor_addresses={
            network.name: network.hypervisor_address
            for network in plan.networks
            if network.hypervisor_address is not None
        },
        probe_endpoints={
            network.name: network.probe_endpoint
            for network in plan.networks
            if network.probe_endpoint is not None
        },
    )

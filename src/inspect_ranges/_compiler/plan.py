"""The resolved plan: one immutable, deterministic resolution of a spec, emitted before any mutation.

`resolve_plan` turns a validated `RangeSpec` into everything downstream stages consume: per-guest allocations (addresses, MACs, CIDs), per-network realization facts (bridge, gateway, resolvers, search domain), image references with cache-resolved digests, host requirements, and resource totals. Unsupported combinations fail here, at planning, as `IssueError`s with stable codes — never mid-boot. The plan is pure data with no timestamps, so the same spec and options always produce byte-identical `plan.json` (see `plan_json`).

Render v1 scope: guests whose configuration injector is cloud-init (Linux). Windows guests refuse at planning (`windows-render-not-supported`); their injectors (unattend/qemu-ga, checkpoints) arrive with the build-manifest phase.
"""

import hashlib
import json
from ipaddress import IPv4Address
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel

from ..types import AnyIPNetwork, Issue, IssueError, RangeSpec, Route
from .allocate import (
    Allocation,
    GuestAllocation,
    GuestKind,
    InterfaceAllocation,
    allocate,
)
from .dnsmasq import resolvers_for, search_domain
from .egress import bridge_name
from .routing import elect_gateways


class PlanOptions(BaseModel):
    """Host-class declarations and resolution inputs for planning (never per-instance probes)."""

    image_cache: Path | None = None
    """Local image cache for digest resolution; images not found resolve with `digest: None`, loudly visible in the plan."""

    cpu_model: str = "host-passthrough"
    """Guest CPU model; checkpointed fleets use a named model (see range-build.md)."""

    default_router_image: str = "noble-range-guest"
    """Image for routers that declare none (the backend's default router appliance)."""


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
    injector: Literal["cloud-init"]
    """How configuration reaches the guest (render v1: cloud-init only)."""
    readiness: Literal["cloud-init"]
    """What the applier waits on before the range is ready."""
    profile: Literal["strict"]
    """Device-model profile (min-devices strict; richer profiles arrive with a schema field)."""


class Requirements(BaseModel):
    """What a host must provide to realize this plan; mismatches refuse at admission, not mid-boot."""

    cpu_model: str
    devices: list[str]
    """Host device nodes the range container needs."""
    egress_uplink: bool
    """Whether the deployment must supply an uplink network (any nat/routed network or attacker egress)."""


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
    for index, host in enumerate(spec.hosts):
        if host.os.type == "windows":
            issues.append(
                Issue(
                    code="windows-render-not-supported",
                    path=("hosts", index, "os", "type"),
                    message=f"host {host.name!r} is a Windows guest, which render v1 cannot realize",
                    hint="Windows injectors (unattend/qemu-ga, checkpoints) arrive with the build-manifest phase",
                )
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
    if spec.variables:
        issues.append(
            Issue(
                code="randomization-not-realized",
                path=("variables",),
                message="the range declares per-instance variables; draws arrive with the generation layer (defaults are in effect until then)",
                hint="validation substitutes defaults, so the definition realizes concretely today",
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

    allocation = allocate(spec)
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
            reference = options.default_router_image
        resources = getattr(declared, "resources", None)
        guests.append(
            PlannedGuest(
                name=guest.name,
                kind=guest.kind,
                cid=guest.cid,
                os="linux",
                image=_resolve_image(reference, options.image_cache),
                cpus=resources.cpus if resources else 1,
                memory_mb=resources.memory_mb if resources else 1024,
                disk_gb=(resources.disk_gb if resources and resources.disk_gb else 10),
                interfaces=guest.interfaces,
                routes=list(getattr(declared, "routes", [])),
                injector="cloud-init",
                readiness="cloud-init",
                profile="strict",
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
        ),
        totals=Totals(
            guests=len(guests),
            cpus=sum(guest.cpus for guest in guests),
            memory_mb=sum(guest.memory_mb for guest in guests),
        ),
    )


def _resolve_image(reference: str, cache: Path | None) -> ImageRef:
    file = reference if "." in Path(reference).name else f"{reference}.qcow2"
    file = file.replace("/", "-").replace(":", "-")
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
    )

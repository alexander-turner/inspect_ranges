"""Public types for `range.yaml` schema v0.1: the strict, runtime-consumed core of a range definition.

These models are the typed form of the sandbox configuration: `sandbox=("libvirt_range", RangeSpec(...))` and `sandbox=("libvirt_range", "range.yaml")` are equally supported, and both surfaces are governed by `schema_version`. Construction reads like the YAML (strings coerce to address types, literals take plain strings, nested dicts are accepted via `model_validate`); the one spelling divergence is `AclRule`'s `from_=` keyword for the YAML `from:`.

Models validate fully at construction (structural and cross-reference checks), and stay mutable for flexible programmatic construction. Validity is therefore a point-in-time property: every consumer boundary revalidates, so a spec mutated after construction is re-checked when it is handed to the sandbox, the compiler, or `revalidate_range`.

v0.1 deliberately covers only the five sections the runtime consumes — `range`, `networks`, `routers`, `hosts`, `attacker` — and rejects everything else loudly. Sections awaiting real design (`attack_path`, `goals`, `variables`, `defense`, `vulnerabilities`, guest configuration, ...) are excluded entirely; see `design/inspect-ranges/schema-v0.1-scope.md` for the deferral rationale.
"""

import re
from ipaddress import IPv4Address, IPv4Network
from typing import TYPE_CHECKING, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from ._diagnostics import (
    Issue,
    IssueError,
    PathElement,
    ValidationReport,
    did_you_mean,
)

__all__ = [
    "AclRule",
    "Attacker",
    "DnsConfig",
    "DnsRecord",
    "Host",
    "Interface",
    "Issue",
    "Network",
    "Os",
    "RangeMeta",
    "RangeSpec",
    "Resources",
    "Router",
    "ValidationReport",
    "semantic_issues",
]

_ALLOW_RULE = re.compile(r"^(tcp|udp)/(\d{1,5})(?:-(\d{1,5}))?$")


class _StrictModel(BaseModel):
    """Base for all schema models: unknown keys are errors, aliases are accepted."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True)


class RangeMeta(_StrictModel):
    """Identity of the range.

    Upstream provenance is a convention, not schema: record it in a `source.md` next to the `range.yaml`.
    """

    name: str
    """Short identifier, e.g. `vulhub-zabbix`."""

    schema_version: Literal["0.1"] = "0.1"
    """Schema version this definition targets (omitted means the current version)."""

    description: str
    """What the range is and why it exists."""


class DnsRecord(_StrictModel):
    """A name record served on a network."""

    name: str
    """Hostname to resolve."""

    ip: IPv4Address | None = None
    """Address, when not derivable from the named guest's interface."""

    if TYPE_CHECKING:
        # static signature only: address fields also accept strings (runtime-coerced by pydantic)
        def __init__(
            self, *, name: str, ip: IPv4Address | str | None = None
        ) -> None: ...


class DnsConfig(_StrictModel):
    """Per-network DNS, as a union of the shapes real ranges need.

    `records` serves name-based discovery on flat networks; `nameservers` points guests at external resolvers; `authoritative` names guests (e.g. domain controllers) that are the network's DNS servers, optionally chaining to `forwarder`.
    """

    records: list[DnsRecord] | None = None
    """Name records served by the range for this network."""

    nameservers: list[IPv4Address] | None = None
    """External resolvers handed to guests."""

    authoritative: list[str] | None = None
    """Guests that act as this network's DNS servers, in resolution order."""

    forwarder: IPv4Address | None = None
    """Upstream forwarder for the authoritative chain."""

    if TYPE_CHECKING:
        # static signature only: address fields also accept strings (runtime-coerced by pydantic)
        def __init__(
            self,
            *,
            records: list[DnsRecord] | None = None,
            nameservers: list[IPv4Address | str] | None = None,
            authoritative: list[str] | None = None,
            forwarder: IPv4Address | str | None = None,
        ) -> None: ...


class Network(_StrictModel):
    """A layer-2 segment with its addressing and egress posture."""

    name: str
    """Segment name, unique within the range."""

    cidr: IPv4Network
    """Subnet, e.g. `10.10.10.0/24`."""

    mode: Literal["isolated", "nat", "routed"]
    """Egress posture: `isolated` (no egress), `nat`, or `routed`."""

    dhcp: bool = False
    """Whether guests on this network get addresses via DHCP (default: static)."""

    dns: DnsConfig | None = None
    """DNS behavior on this network."""

    if TYPE_CHECKING:
        # static signature only: address fields also accept strings (runtime-coerced by pydantic)
        def __init__(
            self,
            *,
            name: str,
            cidr: IPv4Network | str,
            mode: Literal["isolated", "nat", "routed"],
            dhcp: bool = False,
            dns: DnsConfig | None = None,
        ) -> None: ...


class Interface(_StrictModel):
    """A guest's attachment to a network."""

    network: str
    """Name of a declared network."""

    ip: IPv4Address | None = None
    """Static address within the network's subnet; omitted means IPAM-allocated."""

    if TYPE_CHECKING:
        # static signature only: address fields also accept strings (runtime-coerced by pydantic)
        def __init__(
            self, *, network: str, ip: IPv4Address | str | None = None
        ) -> None: ...


class Os(_StrictModel):
    """Guest operating system."""

    type: Literal["linux", "windows"]
    """OS family."""

    distro: str | None = None
    """Linux distribution, e.g. `ubuntu-20.04`."""

    version: str | None = None
    """Windows version, e.g. `server-2019`."""


class Resources(_StrictModel):
    """Backend-neutral guest sizing."""

    cpus: int = Field(ge=1)
    """Virtual CPU count."""

    memory_mb: int = Field(ge=64)
    """Memory in MiB."""

    disk_gb: int | None = Field(default=None, ge=1)
    """Disk size in GiB, when the image default is not enough."""


class AclRule(_StrictModel):
    """One allow rule on a router: new connections `from` one network `to` another.

    Semantics are default-deny and stateful: anything not allowed is dropped, return traffic of allowed flows always passes. In typed construction the source field is spelled `from_` (the YAML surface keeps `from:`).
    """

    from_: str = Field(validation_alias="from", serialization_alias="from")
    """Source network name (`from:` in YAML; `from_=` in typed construction)."""

    to: str
    """Destination network name."""

    allow: list[str]
    """Allowed services as `proto/port` or `proto/lo-hi` entries, e.g. `tcp/5432`, `tcp/1-65535`; empty allows nothing."""

    @model_validator(mode="after")
    def _check_allow_entries(self) -> "AclRule":
        issues: list[Issue] = []
        for index, entry in enumerate(self.allow):
            match = _ALLOW_RULE.match(entry)
            if match is None:
                issues.append(
                    Issue(
                        code="invalid-allow-entry",
                        path=("allow", index),
                        message=f"ACL allow entry {entry!r} must be proto/port or proto/lo-hi, e.g. tcp/5432",
                    )
                )
                continue
            low = int(match.group(2))
            high = int(match.group(3)) if match.group(3) else low
            if not 0 < low <= high < 65536:
                issues.append(
                    Issue(
                        code="invalid-allow-entry",
                        path=("allow", index),
                        message=f"ACL allow entry {entry!r} has an invalid port range",
                    )
                )
        if issues:
            raise IssueError(issues)
        return self


class Router(_StrictModel):
    """A gateway guest joining two or more networks, carrying the inter-segment ACL."""

    name: str
    """Guest name, unique within the range."""

    os: Os | None = None
    """Operating system, when the router is a full declared guest."""

    image: str | None = None
    """Image reference; omitted means the backend's default router appliance."""

    resources: Resources | None = None
    """Sizing; omitted means backend defaults."""

    interfaces: list[Interface] = Field(min_length=2)
    """One attachment per joined network (at least two)."""

    acl: list[AclRule] = []
    """Inter-segment policy enforced on this router (default-deny, stateful)."""


class Host(_StrictModel):
    """A target guest."""

    name: str
    """Guest name, unique within the range."""

    hostname: str | None = None
    """In-guest hostname, when it differs from `name`."""

    fqdn: str | None = None
    """Fully qualified name, when the range's DNS should serve it."""

    os: Os
    """Operating system."""

    image: str
    """Image reference the guest boots from."""

    resources: Resources | None = None
    """Sizing; omitted means backend defaults."""

    interfaces: list[Interface] = Field(min_length=1)
    """Network attachments (explicit; v0.1 has no implicit attachment)."""


class Attacker(_StrictModel):
    """The agent's foothold: either a dedicated attack box or an existing host.

    Declare `host` to start on a declared host (assumed breach), or `interfaces` (plus optionally `name`, `image`, `resources`) to boot a dedicated attack box.
    """

    name: str = "attacker"
    """Attack box guest name (ignored when `host` is set)."""

    host: str | None = None
    """Name of a declared host to use as the foothold instead of a dedicated box."""

    image: str | None = None
    """Attack box image; omitted means the backend's standard attack image."""

    resources: Resources | None = None
    """Attack box sizing."""

    interfaces: list[Interface] | None = None
    """Attack box network attachments (required unless `host` is set)."""

    entry: Literal["external", "assumed-breach", "operator"]
    """How the attacker arrives: from outside, pre-positioned, or operator-driven."""

    egress: Literal["none", "open"] = "none"
    """Attacker-reachable egress from the range (default: none)."""

    @model_validator(mode="after")
    def _check_foothold(self) -> "Attacker":
        if self.host is not None:
            extras = [
                field
                for field in ("image", "resources", "interfaces")
                if getattr(self, field) is not None
            ]
            if extras:
                raise IssueError(
                    [
                        Issue(
                            code="attacker-foothold-conflict",
                            path=(),
                            message=f"attacker with host= must not also declare {', '.join(extras)}",
                            hint="declare either a foothold on an existing host or a dedicated attack box, not both",
                        )
                    ]
                )
        elif self.interfaces is None or not self.interfaces:
            raise IssueError(
                [
                    Issue(
                        code="attacker-no-foothold",
                        path=(),
                        message="attacker needs either host= or at least one interface",
                    )
                ]
            )
        return self


class RangeSpec(_StrictModel):
    """A complete v0.1 range definition."""

    meta: RangeMeta = Field(validation_alias="range", serialization_alias="range")
    """Identity and provenance (the `range:` section in YAML; `meta=` in typed construction)."""

    networks: list[Network] = Field(min_length=1)
    """Layer-2 segments."""

    routers: list[Router] = []
    """Gateway guests joining segments."""

    hosts: list[Host] = Field(min_length=1)
    """Target guests."""

    attacker: Attacker
    """The agent's foothold."""

    @model_validator(mode="after")
    def _check_references(self) -> "RangeSpec":
        issues = semantic_issues(self)
        if issues:
            raise IssueError(issues)
        return self


def semantic_issues(spec: RangeSpec) -> list[Issue]:
    """Run every cross-reference check on a structurally valid spec, collecting all findings.

    This is the single implementation of the semantic checks: `RangeSpec` validation calls it (raising if any issue is found, so a freshly constructed spec is always consistent), and `validate_range` calls it via that same validation to report every issue at once.

    Args:
        spec: A structurally valid range definition.

    Returns:
        Every semantic issue found, each with a path into the spec (empty when the spec is consistent).
    """
    issues: list[Issue] = []
    networks: dict[str, Network] = {}
    network_names = [network.name for network in spec.networks]
    for index, network in enumerate(spec.networks):
        if network.name in networks:
            issues.append(
                Issue(
                    code="duplicate-network-name",
                    path=("networks", index, "name"),
                    message=f"duplicate network name {network.name!r} (network names must be unique)",
                )
            )
        networks.setdefault(network.name, network)

    guests: list[tuple[tuple[PathElement, ...], str, list[Interface]]] = [
        (("hosts", i), host.name, host.interfaces) for i, host in enumerate(spec.hosts)
    ]
    guests += [
        (("routers", i), router.name, router.interfaces)
        for i, router in enumerate(spec.routers)
    ]
    if spec.attacker.host is None:
        guests.append(
            (("attacker",), spec.attacker.name, spec.attacker.interfaces or [])
        )
    seen_names: set[str] = set()
    for base, name, _ in guests:
        if name in seen_names:
            issues.append(
                Issue(
                    code="duplicate-guest-name",
                    path=base + ("name",),
                    message=f"guest name {name!r} is not unique (hosts, routers, and the attacker share one namespace)",
                )
            )
        seen_names.add(name)

    used_ips: dict[tuple[str, IPv4Address], str] = {}
    for base, name, interfaces in guests:
        attached: set[str] = set()
        for index, interface in enumerate(interfaces):
            path = base + ("interfaces", index)
            network_spec = networks.get(interface.network)
            if network_spec is None:
                issues.append(
                    Issue(
                        code="undeclared-network",
                        path=path + ("network",),
                        message=f"guest {name!r} attaches to undeclared network {interface.network!r}",
                        hint=did_you_mean(interface.network, network_names),
                    )
                )
                continue
            if interface.network in attached:
                issues.append(
                    Issue(
                        code="duplicate-attachment",
                        path=path + ("network",),
                        message=f"guest {name!r} attaches to network {interface.network!r} more than once",
                    )
                )
            attached.add(interface.network)
            if interface.ip is None:
                continue
            if interface.ip not in network_spec.cidr:
                issues.append(
                    Issue(
                        code="ip-outside-subnet",
                        path=path + ("ip",),
                        message=f"guest {name!r} address {interface.ip} is outside {network_spec.name!r} ({network_spec.cidr})",
                    )
                )
                continue
            if network_spec.cidr.num_addresses > 2 and interface.ip in (
                network_spec.cidr.network_address,
                network_spec.cidr.broadcast_address,
            ):
                issues.append(
                    Issue(
                        code="reserved-ip",
                        path=path + ("ip",),
                        message=f"guest {name!r} address {interface.ip} is the network or broadcast address of {network_spec.name!r} ({network_spec.cidr})",
                    )
                )
                continue
            claimed = used_ips.setdefault((interface.network, interface.ip), name)
            if claimed != name:
                issues.append(
                    Issue(
                        code="duplicate-ip",
                        path=path + ("ip",),
                        message=f"guests {claimed!r} and {name!r} both use {interface.ip} on {interface.network!r}",
                    )
                )

    for router_index, router in enumerate(spec.routers):
        router_networks = {interface.network for interface in router.interfaces}
        for rule_index, rule in enumerate(router.acl):
            rule_path: tuple[PathElement, ...] = (
                "routers",
                router_index,
                "acl",
                rule_index,
            )
            for key, endpoint in (("from", rule.from_), ("to", rule.to)):
                if endpoint not in networks:
                    issues.append(
                        Issue(
                            code="acl-undeclared-network",
                            path=rule_path + (key,),
                            message=f"router {router.name!r} ACL references undeclared network {endpoint!r}",
                            hint=did_you_mean(endpoint, network_names),
                        )
                    )
                elif endpoint not in router_networks:
                    issues.append(
                        Issue(
                            code="acl-unattached-network",
                            path=rule_path + (key,),
                            message=f"router {router.name!r} ACL references network {endpoint!r} it is not attached to",
                        )
                    )
            if rule.from_ == rule.to:
                issues.append(
                    Issue(
                        code="acl-same-segment",
                        path=rule_path,
                        message=f"router {router.name!r} ACL rule from/to are both {rule.to!r}: same-segment traffic does not traverse the router",
                    )
                )

    guest_networks = {
        name: {interface.network for interface in interfaces}
        for _, name, interfaces in guests
    }
    for network_index, network in enumerate(spec.networks):
        if network.dns is None or not network.dns.authoritative:
            continue
        for server_index, server in enumerate(network.dns.authoritative):
            path = ("networks", network_index, "dns", "authoritative", server_index)
            server_networks = guest_networks.get(server)
            if server_networks is None:
                issues.append(
                    Issue(
                        code="dns-undeclared-guest",
                        path=path,
                        message=f"network {network.name!r} dns.authoritative references undeclared guest {server!r}",
                        hint=did_you_mean(server, sorted(guest_networks)),
                    )
                )
            elif network.name not in server_networks:
                issues.append(
                    Issue(
                        code="dns-unattached-guest",
                        path=path,
                        message=f"network {network.name!r} dns.authoritative guest {server!r} is not attached to it",
                    )
                )

    host_names = [host.name for host in spec.hosts]
    if spec.attacker.host is not None and spec.attacker.host not in host_names:
        issues.append(
            Issue(
                code="undeclared-attacker-host",
                path=("attacker", "host"),
                message=f"attacker foothold references undeclared host {spec.attacker.host!r}",
                hint=did_you_mean(spec.attacker.host, host_names),
            )
        )
    return issues

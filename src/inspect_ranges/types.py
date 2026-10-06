"""Public types for `range.yaml` schema v0.1: the strict, runtime-consumed core of a range definition.

These models are the typed form of the sandbox configuration: `sandbox=("libvirt_range", RangeSpec(...))` and `sandbox=("libvirt_range", "range.yaml")` are equally supported, and both surfaces are governed by `schema_version`. Construction reads like the YAML (strings coerce to address types, literals take plain strings, nested dicts are accepted via `model_validate`); the one spelling divergence is `AclRule`'s `from_=` keyword for the YAML `from:`.

Address fields are dual-stack (`AnyIPAddress`/`AnyIPNetwork`) so the type surface never migrates, but IPv6 values are rejected by the `ipv6-not-realized` gate until each construct's realization lands (networking-v0.2 §4).

Models validate fully at construction (structural and cross-reference checks), and stay mutable for flexible programmatic construction. Validity is therefore a point-in-time property: every consumer boundary revalidates, so a spec mutated after construction is re-checked when it is handed to the sandbox, the compiler, or `revalidate_range`.

v0.1 deliberately covers only the five sections the runtime consumes — `range`, `networks`, `routers`, `hosts`, `attacker` — and rejects everything else loudly. Sections awaiting real design (`attack_path`, `goals`, `variables`, `defense`, `vulnerabilities`, guest configuration, ...) are excluded entirely; see `design/inspect-ranges/schema-v0.1-scope.md` for the deferral rationale.
"""

import re
from ipaddress import IPv4Address, IPv4Network, IPv6Address, IPv6Network, ip_network
from typing import TYPE_CHECKING, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from ._diagnostics import (
    Issue,
    IssueError,
    PathElement,
    ValidationReport,
    did_you_mean,
)

AnyIPAddress = IPv4Address | IPv6Address
"""Either address family. IPv6 values validate structurally but are rejected by the `ipv6-not-realized` gate until their realization lands (networking-v0.2 §4)."""

AnyIPNetwork = IPv4Network | IPv6Network
"""Either address family. IPv6 values validate structurally but are rejected by the `ipv6-not-realized` gate until their realization lands (networking-v0.2 §4)."""

__all__ = [
    "AclRule",
    "AnyIPAddress",
    "AnyIPNetwork",
    "Attacker",
    "DnsConfig",
    "DnsRecord",
    "EgressPolicy",
    "Host",
    "Interface",
    "Issue",
    "IssueError",
    "Network",
    "Os",
    "RangeMeta",
    "RangeSpec",
    "Resources",
    "Route",
    "Router",
    "ValidationReport",
    "parse_egress_entry",
    "semantic_issues",
]

_SERVICE_ENTRY = re.compile(r"^(tcp|udp)/(\d{1,5})(?:-(\d{1,5}))?$")


class _StrictModel(BaseModel):
    """Base for all schema models: unknown keys are errors, aliases are accepted."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True)


class RangeMeta(_StrictModel):
    """Identity of the range.

    Upstream provenance is a convention, not schema: record it in a `source.md` next to the `range.yaml`.
    """

    name: str
    """Short identifier, e.g. `vulhub-zabbix`."""

    schema_version: Literal["0.1", "0.2"] = "0.1"
    """Schema version this definition targets (omitted means `0.1`; `0.2` is landing incrementally per networking-v0.2)."""

    description: str
    """What the range is and why it exists."""


class DnsRecord(_StrictModel):
    """A name record served on a network."""

    name: str
    """Hostname to resolve."""

    ip: AnyIPAddress | None = None
    """Address, when not derivable from the named guest's interface."""

    if TYPE_CHECKING:
        # static signature only: address fields also accept strings (runtime-coerced by pydantic)
        def __init__(
            self, *, name: str, ip: AnyIPAddress | str | None = None
        ) -> None: ...


class DnsConfig(_StrictModel):
    """Per-network DNS, as a union of the shapes real ranges need.

    `records` serves name-based discovery on flat networks; `nameservers` points guests at external resolvers; `authoritative` names guests (e.g. domain controllers) that are the network's DNS servers, optionally chaining to `forwarder`.
    """

    records: list[DnsRecord] | None = None
    """Name records served by the range for this network."""

    nameservers: list[AnyIPAddress] | None = None
    """External resolvers handed to guests."""

    authoritative: list[str] | None = None
    """Guests that act as this network's DNS servers, in resolution order."""

    forwarder: AnyIPAddress | None = None
    """Upstream forwarder for the authoritative chain."""

    if TYPE_CHECKING:
        # static signature only: address fields also accept strings (runtime-coerced by pydantic)
        def __init__(
            self,
            *,
            records: list[DnsRecord] | None = None,
            nameservers: list[AnyIPAddress | str] | None = None,
            authoritative: list[str] | None = None,
            forwarder: AnyIPAddress | str | None = None,
        ) -> None: ...


_FQDN = re.compile(
    r"^(?=.{1,253}$)([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
)


def _service_issue(field: str, index: int, entry: str, service: str) -> Issue | None:
    if service == "icmp":
        return None
    if service.startswith("icmp"):
        return Issue(
            code="invalid-icmp-rule",
            path=(field, index),
            message=f"egress entry {entry!r}: icmp takes no port; write it as bare `icmp`",
        )
    match = _SERVICE_ENTRY.match(service)
    if match is None:
        return Issue(
            code="invalid-egress-entry",
            path=(field, index),
            message=f"egress entry {entry!r} service must be proto/port, proto/lo-hi, or icmp",
        )
    low = int(match.group(2))
    high = int(match.group(3)) if match.group(3) else low
    if not 0 < low <= high < 65536:
        return Issue(
            code="invalid-egress-entry",
            path=(field, index),
            message=f"egress entry {entry!r} has an invalid port range",
        )
    return None


def parse_egress_entry(
    entry: str,
) -> tuple[AnyIPNetwork | None, str | None, str | None]:
    """Split an egress allowlist entry into its target and service.

    Entries are `CIDR[:proto/port]` or `FQDN:proto/port`; a bare address is its `/32`. The service is returned unvalidated (callers validate; the compiler receives only validated specs).

    Returns:
        `(cidr, fqdn, service)` where exactly one of `cidr`/`fqdn` is set, or `(None, None, None)` when the entry parses as neither.
    """
    try:
        return ip_network(entry), None, None
    except ValueError:
        pass
    target, separator, service = entry.rpartition(":")
    if not separator:
        return None, None, None
    try:
        return ip_network(target), None, service
    except ValueError:
        pass
    if _FQDN.match(target):
        return None, target, service
    return None, None, None


class EgressPolicy(_StrictModel):
    """A scoped egress allowlist: exactly what may leave, nothing else.

    Entries are `CIDR[:proto/port]` (a bare address is its `/32`; omitting the service allows all traffic to the CIDR) or `FQDN:proto/port`. FQDN entries are in the vocabulary but gated by `egress-fqdn-not-realized` until their realization lands (networking-v0.2 §3).
    """

    allow: list[str]
    """Allowlist entries, e.g. `198.51.100.7:tcp/443`, `0.0.0.0/0:udp/123`; empty allows nothing."""

    @model_validator(mode="after")
    def _check_entries(self) -> "EgressPolicy":
        issues: list[Issue] = []
        for index, entry in enumerate(self.allow):
            cidr, fqdn, service = parse_egress_entry(entry)
            if cidr is None and fqdn is None:
                issues.append(
                    Issue(
                        code="invalid-egress-entry",
                        path=("allow", index),
                        message=f"egress entry {entry!r} must be CIDR[:proto/port] or FQDN:proto/port",
                    )
                )
                continue
            if service is not None:
                issue = _service_issue("allow", index, entry, service)
                if issue is not None:
                    issues.append(issue)
            if fqdn is not None:
                if service is None:
                    issues.append(
                        Issue(
                            code="invalid-egress-entry",
                            path=("allow", index),
                            message=f"egress entry {entry!r}: FQDN entries require a service, e.g. {entry}:tcp/443",
                        )
                    )
                issues.append(
                    Issue(
                        code="egress-fqdn-not-realized",
                        path=("allow", index),
                        message=f"egress entry {entry!r}: FQDN targets are not yet realized",
                        hint="use a CIDR for now; FQDN realization lands behind this gate (networking-v0.2 §3)",
                    )
                )
            if isinstance(cidr, IPv6Network):
                issues.append(_ipv6_gate(("allow", index), "egress entry target", cidr))
        if issues:
            raise IssueError(issues)
        return self


class Network(_StrictModel):
    """A layer-2 segment with its addressing and egress posture."""

    name: str
    """Segment name, unique within the range."""

    cidr: AnyIPNetwork
    """Subnet, e.g. `10.10.10.0/24` (IPv6 subnets are gated by `ipv6-not-realized` until realization lands)."""

    mode: Literal["isolated", "nat", "routed"]
    """Egress posture: `isolated` (no egress), `nat`, or `routed`."""

    dhcp: bool = False
    """Whether guests on this network get addresses via DHCP (default: static)."""

    dns: DnsConfig | None = None
    """DNS behavior on this network."""

    gateway: str | None = None
    """The router that is this network's default gateway; required only when more than one router attaches (a single attached router is elected implicitly)."""

    egress: EgressPolicy | None = None
    """Scoped egress allowlist; only meaningful with `mode: nat` (the hypervisor NATs exactly these flows out)."""

    @model_validator(mode="after")
    def _check_egress_mode(self) -> "Network":
        if self.egress is not None and self.mode != "nat":
            raise IssueError(
                [
                    Issue(
                        code="egress-requires-nat",
                        path=("egress",),
                        message=f"network {self.name!r} declares an egress allowlist but mode is {self.mode!r}",
                        hint="scoped egress is realized as hypervisor NAT; set mode: nat",
                    )
                ]
            )
        return self

    if TYPE_CHECKING:
        # static signature only: address fields also accept strings (runtime-coerced by pydantic)
        def __init__(
            self,
            *,
            name: str,
            cidr: AnyIPNetwork | str,
            mode: Literal["isolated", "nat", "routed"],
            dhcp: bool = False,
            dns: DnsConfig | None = None,
            gateway: str | None = None,
            egress: EgressPolicy | None = None,
        ) -> None: ...


class Interface(_StrictModel):
    """A guest's attachment to a network."""

    network: str
    """Name of a declared network."""

    ip: AnyIPAddress | None = None
    """Static address within the network's subnet; omitted means IPAM-allocated."""

    if TYPE_CHECKING:
        # static signature only: address fields also accept strings (runtime-coerced by pydantic)
        def __init__(
            self, *, network: str, ip: AnyIPAddress | str | None = None
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
    """One ordered rule on a router, carrying exactly one of `allow:` or `deny:`.

    Rules evaluate first-match in list order against new connections `from` one endpoint `to` another; anything no rule matches is dropped (default-deny), and return traffic of allowed flows always passes (stateful). Endpoints are a network name, a guest name (resolved to its allocated addresses at plan time), or a CIDR (`/32` for a literal host, `0.0.0.0/0` for any). `deny` exists for carve-outs inside a broader allow. In typed construction the source field is spelled `from_` (the YAML surface keeps `from:`).
    """

    from_: str = Field(validation_alias="from", serialization_alias="from")
    """Source endpoint: network name, guest name, or CIDR (`from:` in YAML; `from_=` in typed construction)."""

    to: str
    """Destination endpoint: network name, guest name, or CIDR."""

    allow: list[str] | None = None
    """Services to allow, as `proto/port`, `proto/lo-hi`, or `icmp` entries, e.g. `tcp/5432`, `tcp/1-65535`; empty allows nothing."""

    deny: list[str] | None = None
    """Services to drop at this point in the rule order (same entry syntax as `allow`)."""

    @model_validator(mode="after")
    def _check_entries(self) -> "AclRule":
        issues: list[Issue] = []
        if (self.allow is None) == (self.deny is None):
            issues.append(
                Issue(
                    code="invalid-deny-rule",
                    path=(),
                    message="ACL rule must carry exactly one of allow: or deny:",
                )
            )
        for field_name, entries in (("allow", self.allow), ("deny", self.deny)):
            for index, entry in enumerate(entries or []):
                if entry == "icmp":
                    continue
                if entry.startswith("icmp"):
                    issues.append(
                        Issue(
                            code="invalid-icmp-rule",
                            path=(field_name, index),
                            message=f"ACL entry {entry!r}: icmp takes no port; write it as bare `icmp`",
                        )
                    )
                    continue
                match = _SERVICE_ENTRY.match(entry)
                if match is None:
                    issues.append(
                        Issue(
                            code="invalid-allow-entry",
                            path=(field_name, index),
                            message=f"ACL {field_name} entry {entry!r} must be proto/port, proto/lo-hi, or icmp, e.g. tcp/5432",
                        )
                    )
                    continue
                low = int(match.group(2))
                high = int(match.group(3)) if match.group(3) else low
                if not 0 < low <= high < 65536:
                    issues.append(
                        Issue(
                            code="invalid-allow-entry",
                            path=(field_name, index),
                            message=f"ACL {field_name} entry {entry!r} has an invalid port range",
                        )
                    )
        if issues:
            raise IssueError(issues)
        return self


class Route(_StrictModel):
    """A static route on a router, for traffic to segments it reaches through another router."""

    to: AnyIPNetwork
    """Destination subnet."""

    via: AnyIPAddress
    """Next hop; must be an address inside one of the router's attached networks."""

    if TYPE_CHECKING:
        # static signature only: address fields also accept strings (runtime-coerced by pydantic)
        def __init__(
            self, *, to: AnyIPNetwork | str, via: AnyIPAddress | str
        ) -> None: ...


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

    routes: list[Route] = []
    """Static routes to segments reached through other routers."""

    acl: list[AclRule] = []
    """Inter-segment policy enforced on this router (default-deny, stateful; endpoints may be routed, not only attached)."""


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

    egress: Literal["none", "open"] | EgressPolicy = "none"
    """Attacker-reachable egress from the range: `none` (default), `open`, or a scoped allowlist. Attacker egress composes ahead of network egress: `none` drops the attacker's flows even on a network with an allowlist."""

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
        errors = [issue for issue in semantic_issues(self) if issue.severity == "error"]
        if errors:
            raise IssueError(errors)
        return self


EndpointKind = Literal["network", "guest", "cidr", "unknown"]
"""How an ACL endpoint resolved: a declared network, a declared guest, a CIDR literal, or nothing."""


def endpoint_kind(
    endpoint: str,
    networks: dict[str, Network],
    guest_networks: dict[str, set[str]],
) -> tuple[EndpointKind, AnyIPNetwork | None]:
    """Classify an ACL endpoint against the declared names, falling back to CIDR parsing.

    Networks and guests share one namespace (`name-collision` enforces disjointness), so resolution order cannot be ambiguous. A bare address parses as its `/32` (or `/128`) network.

    Args:
        endpoint: The `from`/`to` value of an ACL rule.
        networks: Declared networks by name.
        guest_networks: Each guest's attached network names, by guest name.

    Returns:
        The kind, plus the parsed network when the endpoint is a CIDR.
    """
    if endpoint in networks:
        return "network", None
    if endpoint in guest_networks:
        return "guest", None
    try:
        return "cidr", ip_network(endpoint)
    except ValueError:
        return "unknown", None


def _ipv6_gate(
    path: tuple[PathElement, ...], label: str, value: IPv6Address | IPv6Network
) -> Issue:
    return Issue(
        code="ipv6-not-realized",
        path=path,
        message=f"{label} {value} is IPv6, which is not yet realized",
        hint="IPv6 lands per construct behind this gate (networking-v0.2 §4); use IPv4 for now",
    )


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
        if isinstance(network.cidr, IPv6Network):
            issues.append(
                _ipv6_gate(
                    ("networks", index, "cidr"),
                    f"network {network.name!r} cidr",
                    network.cidr,
                )
            )
        if network.dns is not None:
            if isinstance(network.dns.forwarder, IPv6Address):
                issues.append(
                    _ipv6_gate(
                        ("networks", index, "dns", "forwarder"),
                        f"network {network.name!r} dns forwarder",
                        network.dns.forwarder,
                    )
                )
            for ns_index, nameserver in enumerate(network.dns.nameservers or []):
                if isinstance(nameserver, IPv6Address):
                    issues.append(
                        _ipv6_gate(
                            ("networks", index, "dns", "nameservers", ns_index),
                            f"network {network.name!r} dns nameserver",
                            nameserver,
                        )
                    )
            for record_index, record in enumerate(network.dns.records or []):
                if isinstance(record.ip, IPv6Address):
                    issues.append(
                        _ipv6_gate(
                            ("networks", index, "dns", "records", record_index, "ip"),
                            f"dns record {record.name!r}",
                            record.ip,
                        )
                    )

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
        if name in networks:
            issues.append(
                Issue(
                    code="name-collision",
                    path=base + ("name",),
                    message=f"guest {name!r} collides with network {name!r}: networks and guests share one namespace",
                    hint="rename the guest or the network",
                )
            )

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
            if isinstance(interface.ip, IPv6Address):
                issues.append(
                    _ipv6_gate(path + ("ip",), f"guest {name!r} address", interface.ip)
                )
                continue
            if isinstance(network_spec.cidr, IPv6Network):
                continue  # gated at the network; family-dependent checks don't apply
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

    guest_networks = {
        name: {interface.network for interface in interfaces}
        for _, name, interfaces in guests
    }

    # '.local' zones are reserved for mDNS: Linux stub resolvers (systemd-resolved)
    # never send them to unicast DNS, so range-served or AD zones under .local
    # silently fail to resolve on Linux guests without resolver domain routing
    for network_index, network in enumerate(spec.networks):
        if network.dns is None:
            continue
        for record_index, record in enumerate(network.dns.records or []):
            if record.name.endswith(".local"):
                issues.append(
                    Issue(
                        code="dot-local-zone",
                        severity="warning",
                        path=(
                            "networks",
                            network_index,
                            "dns",
                            "records",
                            record_index,
                            "name",
                        ),
                        message=f"dns record {record.name!r} is under '.local', which Linux stub resolvers reserve for mDNS and never send to unicast DNS",
                        hint="prefer another TLD, or configure Linux guests' resolver domain routing",
                    )
                )
    for host_index, host in enumerate(spec.hosts):
        if host.fqdn is not None and host.fqdn.endswith(".local"):
            issues.append(
                Issue(
                    code="dot-local-zone",
                    severity="warning",
                    path=("hosts", host_index, "fqdn"),
                    message=f"host fqdn {host.fqdn!r} is under '.local', which Linux stub resolvers reserve for mDNS and never send to unicast DNS",
                    hint="Windows guests resolve it; Linux guests need resolver domain routing (see the netsvc spike findings)",
                )
            )

    # dns records without an explicit ip must resolve to a guest on the network
    for network_index, network in enumerate(spec.networks):
        if network.dns is None:
            continue
        for record_index, record in enumerate(network.dns.records or []):
            if record.ip is not None:
                continue
            if network.name not in guest_networks.get(record.name, set()):
                issues.append(
                    Issue(
                        code="dns-record-unresolvable",
                        path=(
                            "networks",
                            network_index,
                            "dns",
                            "records",
                            record_index,
                        ),
                        message=f"dns record {record.name!r} has no ip and names no guest attached to {network.name!r}",
                        hint=did_you_mean(record.name, sorted(guest_networks))
                        or "give the record an explicit ip, or name an attached guest",
                    )
                )

    # routing: static-route validity and per-router reachability (attached + routed)
    reachable: dict[str, set[str]] = {}
    for router_index, router in enumerate(spec.routers):
        router_networks = {interface.network for interface in router.interfaces}
        attached_subnets = [
            networks[name].cidr
            for name in router_networks
            if name in networks and isinstance(networks[name].cidr, IPv4Network)
        ]
        routed: set[str] = set()
        for route_index, route in enumerate(router.routes):
            route_path: tuple[PathElement, ...] = (
                "routers",
                router_index,
                "routes",
                route_index,
            )
            if isinstance(route.to, IPv6Network) or isinstance(route.via, IPv6Address):
                if isinstance(route.to, IPv6Network):
                    issues.append(
                        _ipv6_gate(
                            route_path + ("to",),
                            f"router {router.name!r} route destination",
                            route.to,
                        )
                    )
                if isinstance(route.via, IPv6Address):
                    issues.append(
                        _ipv6_gate(
                            route_path + ("via",),
                            f"router {router.name!r} route next hop",
                            route.via,
                        )
                    )
                continue
            if not any(route.via in subnet for subnet in attached_subnets):
                issues.append(
                    Issue(
                        code="unreachable-route",
                        path=route_path + ("via",),
                        message=f"router {router.name!r} route next hop {route.via} is not inside any attached network",
                        hint="the next hop must be an address on a network this router attaches to",
                    )
                )
            for network_name, network in networks.items():
                if isinstance(network.cidr, IPv4Network) and network.cidr.subnet_of(
                    route.to
                ):
                    routed.add(network_name)
        reachable[router.name] = router_networks | routed

    # gateway election: implicit with one attached router, declared with more
    for network_index, network in enumerate(spec.networks):
        attached_routers = [
            router.name
            for router in spec.routers
            if any(interface.network == network.name for interface in router.interfaces)
        ]
        if network.egress is not None and attached_routers:
            issues.append(
                Issue(
                    code="egress-with-router-not-realized",
                    path=("networks", network_index, "egress"),
                    message=f"network {network.name!r} declares an egress allowlist but attaches a router; that combination is not yet realized",
                    hint="scoped egress is realized as hypervisor NAT on routerless networks for now (networking-v0.2 §3)",
                )
            )
        if network.gateway is not None:
            if network.gateway not in attached_routers:
                issues.append(
                    Issue(
                        code="undeclared-gateway",
                        path=("networks", network_index, "gateway"),
                        message=f"network {network.name!r} gateway {network.gateway!r} is not a router attached to it",
                        hint=did_you_mean(network.gateway, attached_routers)
                        or (
                            f"attached routers: {', '.join(attached_routers)}"
                            if attached_routers
                            else "no router attaches to this network"
                        ),
                    )
                )
        elif len(attached_routers) > 1:
            issues.append(
                Issue(
                    code="ambiguous-gateway",
                    path=("networks", network_index),
                    message=f"network {network.name!r} attaches more than one router ({', '.join(attached_routers)}) and declares no gateway",
                    hint="set gateway: to one of the attached routers",
                )
            )

    for router_index, router in enumerate(spec.routers):
        router_reachable = reachable[router.name]
        for rule_index, rule in enumerate(router.acl):
            rule_path: tuple[PathElement, ...] = (
                "routers",
                router_index,
                "acl",
                rule_index,
            )
            for key, endpoint in (("from", rule.from_), ("to", rule.to)):
                kind, cidr = endpoint_kind(endpoint, networks, guest_networks)
                if kind == "unknown":
                    if "/" in endpoint:
                        issues.append(
                            Issue(
                                code="acl-endpoint-unknown",
                                path=rule_path + (key,),
                                message=f"router {router.name!r} ACL endpoint {endpoint!r} is not a valid CIDR",
                                hint="use the network address (host bits must be zero), e.g. 10.0.0.0/24",
                            )
                        )
                    else:
                        issues.append(
                            Issue(
                                code="acl-endpoint-unknown",
                                path=rule_path + (key,),
                                message=f"router {router.name!r} ACL endpoint {endpoint!r} matches no declared network, guest, or CIDR",
                                hint=did_you_mean(
                                    endpoint, network_names + sorted(guest_networks)
                                ),
                            )
                        )
                elif kind == "cidr" and isinstance(cidr, IPv6Network):
                    issues.append(
                        _ipv6_gate(
                            rule_path + (key,),
                            f"router {router.name!r} ACL endpoint",
                            cidr,
                        )
                    )
                elif kind == "network" and endpoint not in router_reachable:
                    issues.append(
                        Issue(
                            code="acl-unattached-network",
                            path=rule_path + (key,),
                            message=f"router {router.name!r} ACL references network {endpoint!r} it neither attaches nor routes to",
                        )
                    )
                elif kind == "guest" and not (
                    guest_networks[endpoint] & router_reachable
                ):
                    issues.append(
                        Issue(
                            code="acl-unattached-network",
                            path=rule_path + (key,),
                            message=f"router {router.name!r} ACL references guest {endpoint!r}, which is on no network this router attaches or routes to",
                        )
                    )
            if rule.from_ == rule.to:
                issues.append(
                    Issue(
                        code="acl-same-segment",
                        path=rule_path,
                        message=f"router {router.name!r} ACL rule from/to are both {rule.to!r}: traffic between identical endpoints does not traverse the router",
                    )
                )

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

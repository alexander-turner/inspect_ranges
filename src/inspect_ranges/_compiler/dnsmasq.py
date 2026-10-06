"""Per-network dnsmasq rendering: DHCP reservations and range-served DNS, from the allocation.

Networks with `dhcp: true` or `dns.records` get a dnsmasq instance in the range netns, bound to the bridge on the hypervisor address the allocator reserved. DHCP is reservation-only (`dhcp-range=...,static`): every lease comes from the allocation by MAC, so DHCP addressing is as deterministic as static. DNS serves exactly the declared records (`no-hosts`, `no-resolv`: nothing leaks from the hypervisor's own resolver or hosts file); a record without an explicit `ip` resolves to the named guest's address on that network. Records networks carry a derived search domain (`<network>.internal`, handed to guests via DHCP or the generated netplan), because stub resolvers like systemd-resolved do not send single-label names to DNS without one; single-label records are registered under both the bare name and the search domain.

`resolvers_for` is the other half: which resolver addresses the generated guest config hands each network's guests — `dns.authoritative` guests first (in declared order, the AD pattern goad-forest proved), then the range's own service when it serves records, then any explicit external `nameservers`. The `forwarder` field is consumed by guest provisioning (it is the authoritative server's upstream, not network realization).
"""

from ipaddress import IPv4Address

from ..types import RangeSpec
from .allocate import Allocation
from .egress import bridge_name
from .routing import elect_gateways


def render_dnsmasq_conf(
    spec: RangeSpec, allocation: Allocation, network_name: str
) -> str | None:
    """Render the dnsmasq configuration for one network, or `None` when it needs no service.

    Args:
        spec: The validated range definition.
        allocation: The range's allocation (reservations, record targets, the service address).
        network_name: Which network to render.

    Returns:
        A dnsmasq.conf, or `None` for networks with neither `dhcp` nor `dns.records`.
    """
    network = next(network for network in spec.networks if network.name == network_name)
    serves_dns = network.dns is not None and network.dns.records is not None
    if not (network.dhcp or serves_dns):
        return None

    lines = [
        f"interface={bridge_name(network.name)}",
        "bind-interfaces",
        "no-resolv",
        "no-hosts",
    ]
    if serves_dns:
        lines.append(f"domain={search_domain(network_name)}")
    else:
        lines.append("port=0")

    if network.dhcp:
        lines.append(f"dhcp-range={network.cidr.network_address},static")
        for guest in allocation.guests:
            for interface in guest.interfaces:
                if interface.network == network.name:
                    lines.append(
                        f"dhcp-host={interface.mac},{interface.ip},{guest.name}"
                    )
        gateway = elect_gateways(spec, allocation).get(network.name)
        if gateway is not None:
            lines.append(f"dhcp-option=option:router,{gateway}")
        resolvers = resolvers_for(spec, allocation, network.name)
        if resolvers:
            joined = ",".join(str(address) for address in resolvers)
            lines.append(f"dhcp-option=option:dns-server,{joined}")
        if serves_dns:
            lines.append(
                f"dhcp-option=option:domain-search,{search_domain(network.name)}"
            )

    if serves_dns and network.dns is not None:
        for record in network.dns.records or []:
            ip = record.ip
            if ip is None:
                ip = _guest_address(allocation, record.name, network.name)
            names = record.name
            if "." not in record.name:
                names = f"{record.name},{record.name}.{search_domain(network.name)}"
            lines.append(f"host-record={names},{ip}")

    return "\n".join(lines) + "\n"


def resolvers_for(
    spec: RangeSpec, allocation: Allocation, network_name: str
) -> list[IPv4Address]:
    """Return the resolver addresses the generated guest config hands this network's guests.

    Order: `dns.authoritative` guests (declared order), the range's own DNS service when it serves records, then explicit `nameservers`.
    """
    network = next(network for network in spec.networks if network.name == network_name)
    if network.dns is None:
        return []
    resolvers: list[IPv4Address] = []
    for server in network.dns.authoritative or []:
        resolvers.append(_guest_address(allocation, server, network_name))
    if network.dns.records is not None:
        resolvers.append(allocation.hypervisor_addresses[network_name])
    for nameserver in network.dns.nameservers or []:
        assert isinstance(nameserver, IPv4Address)  # IPv6 gated upstream
        resolvers.append(nameserver)
    return resolvers


def search_domain(network_name: str) -> str:
    """The derived search domain for a records-serving network, handed to its guests."""
    return f"{network_name}.internal"


def _guest_address(
    allocation: Allocation, guest_name: str, network_name: str
) -> IPv4Address:
    guest = allocation.guest(guest_name)
    return next(
        interface.ip
        for interface in guest.interfaces
        if interface.network == network_name
    )

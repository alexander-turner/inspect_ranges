"""Expected reachability from the foothold, computed from the compiler's own structures.

The model reuses what the compiler already resolved rather than reimplementing ACL semantics: addresses come from `allocate()` (the same deterministic allocation `render_router_nftables` resolves guest endpoints against), endpoints classify through `types.endpoint_kind` (the one classifier the nftables renderer uses), and rule evaluation mirrors the renderer's documented contract exactly: an empty `acl` is a plain router (policy accept), any declared rule flips to default-drop with first-match evaluation in declaration order (`_compiler/nftables.py`).

Scope is deliberate: a destination counts as expected-reachable when it shares a segment with the foothold (plain L2, no filter in the path) or when a single router attached to both segments allows at least one service from the foothold endpoint to it. Multi-hop paths (static `routes` through a second router) are not computed; a destination the model cannot see stays out of the set, which errs quiet, never wrong, for the detector built on top.
"""

from ipaddress import IPv4Address, IPv4Network

from .._compiler.allocate import GuestAllocation, allocate
from ..types import Network, RangeSpec, Router, endpoint_kind

__all__ = ["expected_reachable", "range_networks"]


def range_networks(spec: RangeSpec) -> list[IPv4Network]:
    """Every declared network CIDR (IPv4; validation gates IPv6 upstream).

    Args:
        spec: The validated range definition.

    Returns:
        The declared subnets, in declaration order.
    """
    return [
        network.cidr
        for network in spec.networks
        if isinstance(network.cidr, IPv4Network)
    ]


def expected_reachable(spec: RangeSpec) -> frozenset[IPv4Address]:
    """Guest addresses the spec declares reachable from the foothold under its ACLs.

    Args:
        spec: The validated range definition.

    Returns:
        Every address of every other guest the foothold shares a segment with, plus every cross-segment address a single attached router's ACL admits (any allowed service counts; see the module docstring for the deliberate single-hop scope).
    """
    allocation = allocate(spec)
    foothold = allocation.guest(spec.foothold_guest)
    foothold_networks = {interface.network for interface in foothold.interfaces}
    networks = {network.name: network for network in spec.networks}
    guest_networks = {
        guest.name: {interface.network for interface in guest.interfaces}
        for guest in allocation.guests
    }
    reachable: set[IPv4Address] = set()
    for guest in allocation.guests:
        if guest.name == foothold.name:
            continue
        for interface in guest.interfaces:
            if interface.network in foothold_networks:
                reachable.add(interface.ip)
                continue
            if any(
                _router_admits(
                    router,
                    foothold,
                    destination=guest,
                    destination_ip=interface.ip,
                    destination_network=interface.network,
                    networks=networks,
                    guest_networks=guest_networks,
                )
                for router in spec.routers
            ):
                reachable.add(interface.ip)
    return frozenset(reachable)


def _router_admits(
    router: Router,
    foothold: GuestAllocation,
    *,
    destination: GuestAllocation,
    destination_ip: IPv4Address,
    destination_network: str,
    networks: dict[str, Network],
    guest_networks: dict[str, set[str]],
) -> bool:
    """Whether one router joins the foothold to the destination and its ACL admits any service."""
    router_networks = {interface.network for interface in router.interfaces}
    source_networks = {
        interface.network
        for interface in foothold.interfaces
        if interface.network in router_networks
    }
    if not source_networks or destination_network not in router_networks:
        return False
    if not router.acl:
        # no declared ACL is a plain router: policy accept (nftables.py)
        return True
    source_ips = [
        interface.ip
        for interface in foothold.interfaces
        if interface.network in source_networks
    ]
    denied: list[tuple[str, int, int]] = []
    for rule in router.acl:
        if not _endpoint_matches(
            rule.from_,
            networks,
            guest_networks,
            guest_name=foothold.name,
            network_names=source_networks,
            addresses=source_ips,
        ):
            continue
        if not _endpoint_matches(
            rule.to,
            networks,
            guest_networks,
            guest_name=destination.name,
            network_names={destination_network},
            addresses=[destination_ip],
        ):
            continue
        if rule.allow is not None:
            for entry in rule.allow:
                if not _covered(_service(entry), denied):
                    return True
        else:
            denied.extend(_service(entry) for entry in rule.deny or [])
    return False


def _endpoint_matches(
    endpoint: str,
    networks: dict[str, Network],
    guest_networks: dict[str, set[str]],
    *,
    guest_name: str,
    network_names: set[str],
    addresses: list[IPv4Address],
) -> bool:
    """Whether an ACL endpoint covers the given guest-side identity, classified by `endpoint_kind` exactly as the renderer classifies it."""
    kind, cidr = endpoint_kind(endpoint, networks, guest_networks)
    if kind == "network":
        return endpoint in network_names
    if kind == "guest":
        return endpoint == guest_name
    if kind == "cidr" and cidr is not None:
        return any(address in cidr for address in addresses)
    return False


def _service(entry: str) -> tuple[str, int, int]:
    """A validated ACL service entry as `(proto, low, high)` (`icmp` is `("icmp", 0, 0)`); the grammar is enforced by `AclRule` validation."""
    if entry == "icmp":
        return ("icmp", 0, 0)
    proto, _, ports = entry.partition("/")
    low, _, high = ports.partition("-")
    return (proto, int(low), int(high or low))


def _covered(service: tuple[str, int, int], denied: list[tuple[str, int, int]]) -> bool:
    """Whether a single earlier deny entry fully shadows this allow entry (first-match: a deny line preceding the allow drops exactly what it matches; coverage split across several deny entries is deliberately not composed, erring on the reachable side)."""
    proto, low, high = service
    return any(
        deny_proto == proto and deny_low <= low and high <= deny_high
        for deny_proto, deny_low, deny_high in denied
    )

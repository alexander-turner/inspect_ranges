"""Expected reachability from the foothold, computed from the compiler's own structures.

The model reuses what the compiler already resolved rather than reimplementing ACL semantics: addresses come from `allocate()` (the same deterministic allocation `render_router_nftables` resolves guest endpoints against), and rule evaluation is `_compiler/acl.py`'s `acl_admits`, the shared statement of the rendered contract (an empty `acl` is a plain router with policy accept; any declared rule flips to default-drop with first-match evaluation in declaration order), so this model cannot drift from what the renderer emits.

Scope is deliberate: a destination counts as expected-reachable when it shares a segment with the foothold (plain L2, no filter in the path) or when a single router attached to both segments allows at least one service from the foothold endpoint to it. Multi-hop paths (static `routes` through a second router) are not computed; a destination the model cannot see stays out of the set, which errs quiet, never wrong, for the detector built on top.
"""

from ipaddress import IPv4Address, IPv4Network

from .._compiler.acl import FlowEndpoint, acl_admits
from .._compiler.allocate import GuestAllocation, allocate
from ..types import Network, RangeSpec, Router

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
    """Whether one router joins the foothold to the destination and its ACL admits any service (`acl_admits`, the shared evaluator)."""
    router_networks = {interface.network for interface in router.interfaces}
    source_networks = {
        interface.network
        for interface in foothold.interfaces
        if interface.network in router_networks
    }
    if not source_networks or destination_network not in router_networks:
        return False
    source = FlowEndpoint(
        guest=foothold.name,
        networks=frozenset(source_networks),
        addresses=tuple(
            interface.ip
            for interface in foothold.interfaces
            if interface.network in source_networks
        ),
    )
    return acl_admits(
        router.acl,
        source=source,
        destination=FlowEndpoint(
            guest=destination.name,
            networks=frozenset({destination_network}),
            addresses=(destination_ip,),
        ),
        networks=networks,
        guest_networks=guest_networks,
    )

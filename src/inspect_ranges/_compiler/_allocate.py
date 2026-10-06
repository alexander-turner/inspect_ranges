"""Deterministic allocation: every address, MAC, and vsock CID assigned from the spec alone.

The same spec always yields the same allocation (stable iteration order, content-derived MACs), which is what makes generated artifacts reproducible and lets ACL rules reference guests by name: `render_router_nftables` resolves guest endpoints against this allocation.

Address policy per network: explicit `ip:` values are claimed first (cross-validated unique by the schema); routers then allocate from the first usable address (so the single-router case lands on `.1`, the conventional gateway), the attacker follows the routers, and hosts allocate from offset 10 (`.10` on a /24; small subnets fall back to the next free address). The allocator refuses IPv6 (gated upstream by `ipv6-not-realized`).
"""

import hashlib
from ipaddress import IPv4Address, IPv4Network
from typing import Literal

from pydantic import BaseModel

from ..types import Interface, RangeSpec

GuestKind = Literal["host", "router", "attacker"]


class InterfaceAllocation(BaseModel):
    """One guest NIC: its network, resolved address, and generated MAC."""

    network: str
    """The attached network's name."""

    ip: IPv4Address
    """The interface address (explicit from the spec, or allocated)."""

    mac: str
    """Deterministic locally-administered MAC (`52:54:00:` + content hash)."""


class GuestAllocation(BaseModel):
    """One guest's resolved identity: interfaces plus its vsock control-channel CID."""

    name: str
    """Guest name."""

    kind: GuestKind
    """Whether the guest is a host, a router, or the attacker."""

    cid: int
    """vsock context id for the control plane (allocated from 3 upward)."""

    interfaces: list[InterfaceAllocation]
    """Resolved attachments, in spec order."""


class Allocation(BaseModel):
    """The deterministic allocation for a whole range."""

    guests: list[GuestAllocation]
    """Every guest (hosts, routers, the attacker when it is a dedicated box), in allocation order."""

    def guest(self, name: str) -> GuestAllocation:
        """Return a guest's allocation by name.

        Raises:
            KeyError: No guest with that name.
        """
        for guest in self.guests:
            if guest.name == name:
                return guest
        raise KeyError(name)

    def addresses(self, name: str) -> list[IPv4Address]:
        """Return every address allocated to a guest, in interface order."""
        return [interface.ip for interface in self.guest(name).interfaces]


def allocate(spec: RangeSpec) -> Allocation:
    """Compute the deterministic allocation for a validated spec.

    Args:
        spec: A validated range definition (IPv6 values are excluded by validation).

    Returns:
        Addresses, MACs, and CIDs for every guest.

    Raises:
        ValueError: The spec contains IPv6 values (which validation gates) or a subnet is exhausted.
    """
    subnets: dict[str, IPv4Network] = {}
    claimed: dict[str, set[IPv4Address]] = {}
    for network in spec.networks:
        if not isinstance(network.cidr, IPv4Network):
            raise ValueError(f"network {network.name!r} is IPv6 (gated upstream)")
        subnets[network.name] = network.cidr
        claimed[network.name] = set()

    ordered: list[tuple[GuestKind, str, list[Interface]]] = []
    for router in spec.routers:
        ordered.append(("router", router.name, router.interfaces))
    if spec.attacker.host is None:
        ordered.append(("attacker", spec.attacker.name, spec.attacker.interfaces or []))
    for host in spec.hosts:
        ordered.append(("host", host.name, host.interfaces))

    for _, _, interfaces in ordered:
        for interface in interfaces:
            if interface.ip is not None:
                if not isinstance(interface.ip, IPv4Address):
                    raise ValueError(f"{interface.ip} is IPv6 (gated upstream)")
                claimed[interface.network].add(interface.ip)

    # CIDs follow spec declaration order (hosts, routers, attacker), independent of
    # the address-allocation order below, so adding a router never renumbers hosts.
    cid_order = [host.name for host in spec.hosts]
    cid_order += [router.name for router in spec.routers]
    if spec.attacker.host is None:
        cid_order.append(spec.attacker.name)
    cids = {name: 3 + index for index, name in enumerate(cid_order)}

    guests: list[GuestAllocation] = []
    for kind, name, interfaces in ordered:
        allocations: list[InterfaceAllocation] = []
        for interface in interfaces:
            subnet = subnets[interface.network]
            if interface.ip is not None:
                assert isinstance(interface.ip, IPv4Address)
                ip = interface.ip
            else:
                start = 10 if kind == "host" and subnet.num_addresses >= 16 else 1
                ip = _next_free(subnet, start, claimed[interface.network])
                claimed[interface.network].add(ip)
            allocations.append(
                InterfaceAllocation(
                    network=interface.network,
                    ip=ip,
                    mac=_mac(spec.meta.name, name, interface.network),
                )
            )
        guests.append(
            GuestAllocation(
                name=name, kind=kind, cid=cids[name], interfaces=allocations
            )
        )

    return Allocation(guests=sorted(guests, key=lambda guest: guest.cid))


def _next_free(
    subnet: IPv4Network, start_offset: int, used: set[IPv4Address]
) -> IPv4Address:
    for offset in range(start_offset, subnet.num_addresses - 1):
        candidate = subnet.network_address + offset
        if candidate not in used:
            return candidate
    raise ValueError(f"subnet {subnet} is exhausted")


def _mac(range_name: str, guest: str, network: str) -> str:
    digest = hashlib.sha256(f"{range_name}:{guest}:{network}".encode()).digest()
    return "52:54:00:" + ":".join(f"{byte:02x}" for byte in digest[:3])

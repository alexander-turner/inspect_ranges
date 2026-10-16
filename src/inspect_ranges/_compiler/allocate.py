"""Deterministic allocation: every address, MAC, and vsock CID assigned from the spec alone.

The same spec always yields the same allocation (stable iteration order, content-derived MACs), which is what makes generated artifacts reproducible and lets ACL rules reference guests by name: `render_router_nftables` resolves guest endpoints against this allocation.

Address policy per network: explicit `ip:` values are claimed first (cross-validated unique by the schema); routers then allocate from the first usable address (so the single-router case lands on `.1`, the conventional gateway), the attacker follows the routers, and hosts allocate from offset 10 (`.10` on a /24; small subnets fall back to the next free address). The allocator refuses IPv6 (gated upstream by `ipv6-not-realized`).
"""

import hashlib
from ipaddress import IPv4Address, IPv4Network
from itertools import chain
from typing import Literal

from pydantic import BaseModel

from .._diagnostics import Issue, IssueError
from ..types import Interface, RangeSpec


class SubnetExhaustedError(ValueError):
    """A subnet has no free address for the requested reservation (internal; `allocate` translates it into a positioned `IssueError`)."""

    def __init__(self, subnet: IPv4Network) -> None:
        self.subnet = subnet
        super().__init__(f"subnet {subnet} is exhausted")


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


class ProbeEndpoint(BaseModel):
    """One network's declared probe endpoint: the clamped veth's identity (challenge-prober spike A2).

    The reserved address and declared MAC are what make probe traffic attributable in pcap by spec, so corroboration excludes probe flows by identity rather than heuristics.
    """

    device: str
    """The veth device holding the probe address in the range netns (`pr-<network>`)."""

    peer: str
    """The bridge-attached peer device (`prb-<network>`)."""

    ip: IPv4Address
    """Reserved probe address (allocated from the top of the subnet, downward)."""

    mac: str
    """Declared locally-administered MAC (`02:50:00:` + allocation index)."""


class Allocation(BaseModel):
    """The deterministic allocation for a whole range."""

    guests: list[GuestAllocation]
    """Every guest (hosts, routers, the attacker when it is a dedicated box), in allocation order."""

    hypervisor_addresses: dict[str, IPv4Address] = {}
    """Hypervisor-side bridge address per network that needs one: routerless `mode: nat`/`routed` networks (the gateway) and `dhcp`/range-served-DNS networks (the dnsmasq service address). One address serves all roles on a network."""

    probe_endpoints: dict[str, ProbeEndpoint] = {}
    """Declared probe endpoint per network a challenge's `active-prober` observer requires (requested through `PlanOptions.probe_segments`)."""

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


def allocate(
    spec: RangeSpec,
    cid_base: int = 3,
    probe_networks: frozenset[str] = frozenset(),
) -> Allocation:
    """Compute the deterministic allocation for a validated spec.

    Args:
        spec: A validated range definition (IPv6 values are excluded by validation).
        cid_base: First vsock CID; guests number upward from it in declaration order (a plan-time input, partitioned per host since CIDs are kernel-global).
        probe_networks: Networks that get a declared probe endpoint (reserved top-down, so guest allocation from the bottom never collides); unknown names raise.

    Returns:
        Addresses, MACs, and CIDs for every guest, plus hypervisor and probe reservations.

    Raises:
        IssueError: A subnet has no free address for a guest, hypervisor, or probe reservation (`subnet-exhausted`, positioned at the network).
        ValueError: The spec contains IPv6 values (which validation gates) or a probe network is not declared.
    """
    if cid_base < 3:
        raise ValueError(
            f"cid_base must be at least 3 (0-2 are reserved vsock CIDs), got {cid_base}"
        )
    subnets: dict[str, IPv4Network] = {}
    claimed: dict[str, set[IPv4Address]] = {}
    network_index = {network.name: i for i, network in enumerate(spec.networks)}

    def _exhausted(network_name: str, consumer: str) -> IssueError:
        return IssueError(
            [
                Issue(
                    code="subnet-exhausted",
                    path=("networks", network_index[network_name], "cidr"),
                    message=f"network {network_name!r} ({subnets[network_name]}) has no free address for {consumer}",
                    hint="widen the cidr or reduce what this network must hold",
                )
            ]
        )

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

    # some networks need the hypervisor present on the bridge, with an address
    # reserved ahead of guest allocation: routerless nat/routed networks (the
    # bridge is the gateway) and dhcp or range-served-dns networks (the bridge
    # hosts the dnsmasq service)
    router_attached = {
        interface.network for router in spec.routers for interface in router.interfaces
    }
    hypervisor_addresses: dict[str, IPv4Address] = {}
    for network in spec.networks:
        needs_gateway = (
            network.mode in ("nat", "routed") and network.name not in router_attached
        )
        needs_service = network.dhcp or (
            network.dns is not None and network.dns.records is not None
        )
        if needs_gateway or needs_service:
            try:
                address = _next_free(subnets[network.name], 1, claimed[network.name])
            except SubnetExhaustedError:
                raise _exhausted(network.name, "the hypervisor address") from None
            claimed[network.name].add(address)
            hypervisor_addresses[network.name] = address

    # probe endpoints reserve from the TOP of the subnet, downward, before any
    # implicit guest allocation (which climbs from the bottom), so the two can
    # never collide and the probe address is stable under guest growth
    unknown = probe_networks - set(subnets)
    if unknown:
        raise ValueError(f"probe networks not declared: {sorted(unknown)}")
    probe_endpoints: dict[str, ProbeEndpoint] = {}
    for index, name in enumerate(sorted(probe_networks)):
        try:
            address = _next_free_descending(subnets[name], claimed[name])
        except SubnetExhaustedError:
            raise _exhausted(name, "the probe endpoint") from None
        claimed[name].add(address)
        probe_endpoints[name] = ProbeEndpoint(
            device=f"pr-{name}"[:15],
            peer=f"prb-{name}"[:15],
            ip=address,
            mac=f"02:50:00:00:00:{index:02x}",
        )

    # CIDs follow spec declaration order (hosts, routers, attacker), independent of
    # the address-allocation order below, so adding a router never renumbers hosts.
    cid_order = [host.name for host in spec.hosts]
    cid_order += [router.name for router in spec.routers]
    if spec.attacker.host is None:
        cid_order.append(spec.attacker.name)
    cids = {name: cid_base + index for index, name in enumerate(cid_order)}

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
                try:
                    ip = _next_free(subnet, start, claimed[interface.network])
                except SubnetExhaustedError:
                    raise _exhausted(interface.network, f"guest {name!r}") from None
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

    return Allocation(
        guests=sorted(guests, key=lambda guest: guest.cid),
        hypervisor_addresses=hypervisor_addresses,
        probe_endpoints=probe_endpoints,
    )


def _next_free(
    subnet: IPv4Network, start_offset: int, used: set[IPv4Address]
) -> IPv4Address:
    # The preferred region first (hosts start at offset 10 on roomy subnets),
    # then fall back to the free addresses below it, per the module policy:
    # small or crowded subnets use the next free address rather than refusing
    # while capacity remains.
    offsets = chain(
        range(start_offset, subnet.num_addresses - 1), range(1, start_offset)
    )
    for offset in offsets:
        candidate = subnet.network_address + offset
        if candidate not in used:
            return candidate
    raise SubnetExhaustedError(subnet)


def _next_free_descending(subnet: IPv4Network, used: set[IPv4Address]) -> IPv4Address:
    for offset in range(subnet.num_addresses - 2, 0, -1):
        candidate = subnet.network_address + offset
        if candidate not in used:
            return candidate
    raise SubnetExhaustedError(subnet)


def _mac(range_name: str, guest: str, network: str) -> str:
    digest = hashlib.sha256(f"{range_name}:{guest}:{network}".encode()).digest()
    return "52:54:00:" + ":".join(f"{byte:02x}" for byte in digest[:3])

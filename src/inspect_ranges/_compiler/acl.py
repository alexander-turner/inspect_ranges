"""The single statement of ACL rule-evaluation semantics: does this ACL admit a flow.

The contract, exactly what `render_router_nftables` renders (networking-v0.2 §ACL):

- An EMPTY `acl` is a plain router (the KYPO/CyRIS routing-only shape): the forward chain's policy is accept, so every flow is admitted.

- Any declared rule flips the router to default-drop allowlisting with first-match evaluation in declaration order: a flow is admitted only when an `allow` entry matches it before any `deny` entry does, so a `deny` entry shadows later allows exactly by its position and its proto/port coverage.

- Return traffic is implied: the rendered chain accepts `ct state established,related` ahead of every rule, so admitting a flow admits its replies. The evaluator therefore models forward-direction initiation only.

- Endpoints classify through `types.endpoint_kind`, the one classifier the renderer uses: a declared network name, a declared guest name, or a CIDR (`0.0.0.0/0` covers everything; a bare address is its `/32`).

Both consumers plug in here, so a semantic change lands in both or in neither: `render_router_nftables` emits one nftables rule per `acl_entries` element (the flattened first-match stream, verdict included), and the scanner reachability model (`_scanners/reachability.py`) asks `acl_admits` directly.
"""

from collections.abc import Sequence
from ipaddress import IPv4Address
from typing import NamedTuple

from ..types import AclRule, Network, endpoint_kind

__all__ = [
    "AclEntry",
    "FlowEndpoint",
    "Service",
    "acl_admits",
    "acl_entries",
    "endpoint_covers",
    "parse_service",
]


class Service(NamedTuple):
    """One ACL service entry as a protocol and inclusive port range (`icmp` is `("icmp", 0, 0)`)."""

    proto: str
    low: int
    high: int

    def covers(self, other: "Service") -> bool:
        """Whether this entry fully covers `other` (same protocol, port range containment)."""
        return (
            self.proto == other.proto
            and self.low <= other.low
            and other.high <= self.high
        )


def parse_service(entry: str) -> Service:
    """A validated ACL service entry (`icmp`, `tcp/22`, `udp/53-99`) as a `Service`; the grammar is enforced by `AclRule` validation."""
    if entry == "icmp":
        return Service("icmp", 0, 0)
    proto, _, ports = entry.partition("/")
    low, _, high = ports.partition("-")
    return Service(proto, int(low), int(high or low))


class AclEntry(NamedTuple):
    """One flattened first-match step: a rule's endpoints paired with a single service entry and its verdict."""

    source: str
    """The rule's `from` endpoint."""

    destination: str
    """The rule's `to` endpoint."""

    raw: str
    """The service entry exactly as declared (what the renderer's `service_match` consumes)."""

    service: Service
    """The parsed service entry."""

    allowed: bool
    """`True` for an `allow` entry (renders `accept`), `False` for a `deny` entry (renders `drop`)."""


def acl_entries(acl: Sequence[AclRule]) -> list[AclEntry]:
    """Flatten an ACL into its first-match evaluation stream: one entry per declared service, in declaration order."""
    entries: list[AclEntry] = []
    for rule in acl:
        allowed = rule.allow is not None
        for raw in rule.allow if rule.allow is not None else rule.deny or []:
            entries.append(
                AclEntry(rule.from_, rule.to, raw, parse_service(raw), allowed)
            )
    return entries


class FlowEndpoint(NamedTuple):
    """One side of a concrete flow: the guest's name, the network names it holds on that side, and its addresses there."""

    guest: str
    """The guest's declared name."""

    networks: frozenset[str]
    """The network names this side of the flow traverses."""

    addresses: tuple[IPv4Address, ...]
    """The guest's addresses on those networks."""


def endpoint_covers(
    endpoint: str,
    flow: FlowEndpoint,
    *,
    networks: dict[str, Network],
    guest_networks: dict[str, set[str]],
) -> bool:
    """Whether an ACL endpoint covers one side of a flow, classified by `endpoint_kind` exactly as the renderer classifies it.

    An endpoint `endpoint_kind` reads as unknown covers nothing (validation refuses such specs upstream; the evaluator stays quiet rather than guessing).
    """
    kind, cidr = endpoint_kind(endpoint, networks, guest_networks)
    if kind == "network":
        return endpoint in flow.networks
    if kind == "guest":
        return endpoint == flow.guest
    if kind == "cidr" and cidr is not None:
        return any(address in cidr for address in flow.addresses)
    return False


def acl_admits(
    acl: Sequence[AclRule],
    *,
    source: FlowEndpoint,
    destination: FlowEndpoint,
    networks: dict[str, Network],
    guest_networks: dict[str, set[str]],
    service: Service | None = None,
) -> bool:
    """Whether the ACL admits a flow from `source` to `destination`, under the contract in the module docstring.

    Args:
        acl: The router's declared rules (empty admits everything: a plain router).
        source: The flow's source identity.
        destination: The flow's destination identity.
        networks: Declared networks by name (for `endpoint_kind`).
        guest_networks: Each guest's attached network names, by guest name (for `endpoint_kind`).
        service: The concrete service to test, decided by the first entry that covers it. `None` asks whether ANY allow entry admits something, which errs on the admitted side: an allow entry counts unless a single earlier deny entry fully covers it (coverage split across several deny entries is deliberately not composed).

    Returns:
        `True` when the flow is admitted.
    """
    if not acl:
        return True  # plain router: policy accept
    denied: list[Service] = []
    for entry in acl_entries(acl):
        if not endpoint_covers(
            entry.source, source, networks=networks, guest_networks=guest_networks
        ):
            continue
        if not endpoint_covers(
            entry.destination,
            destination,
            networks=networks,
            guest_networks=guest_networks,
        ):
            continue
        if service is not None:
            if entry.service.covers(service):
                return entry.allowed
        elif entry.allowed:
            if not any(deny.covers(entry.service) for deny in denied):
                return True
        else:
            denied.append(entry.service)
    return False

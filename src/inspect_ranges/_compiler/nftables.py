"""Render a router guest's nftables ruleset from its ordered ACL.

The rule-evaluation semantics (plain router accepts, declared rules flip to default-drop first-match with `established,related` accepted ahead of them) are stated once in `acl.py`; this module renders that contract, emitting one nftables rule per `acl_entries` element. Endpoint forms compile as: network name → interface match (`iifname`/`oifname` against the router's deterministic NIC names, `eth0..n` in interface declaration order, applied by the generated guest network config via MAC match); guest name → address-set match over the guest's allocated addresses; CIDR → address match (`0.0.0.0/0` compiles to no match at all).
"""

from ..types import RangeSpec, Router, endpoint_kind
from .acl import acl_entries
from .allocate import Allocation


def router_nic_names(router: Router) -> dict[str, str]:
    """Map a router's attached network names to its deterministic NIC names (`eth{index}`)."""
    return {
        interface.network: f"eth{index}"
        for index, interface in enumerate(router.interfaces)
    }


def render_router_nftables(
    spec: RangeSpec, router_name: str, allocation: Allocation
) -> str:
    """Render the complete nftables ruleset for one router guest.

    Args:
        spec: The validated range definition.
        router_name: Which router's ACL to render.
        allocation: The range's allocation (resolves guest endpoints to addresses).

    Returns:
        An `nft -f`-loadable ruleset.

    Raises:
        KeyError: No router with that name.
    """
    router = next(router for router in spec.routers if router.name == router_name)
    nics = router_nic_names(router)
    if not router.acl:
        # no declared ACL means a PLAIN router (the KYPO/CyRIS shape: routing,
        # no filtering); declaring any rule flips to default-drop allowlisting
        lines = [
            "table inet fw {",
            "  chain forward {",
            "    type filter hook forward priority 0; policy accept;",
            "  }",
            "}",
        ]
        return "\n".join(lines) + "\n"
    lines = [
        "table inet fw {",
        "  chain forward {",
        "    type filter hook forward priority 0; policy drop;",
        "    ct state established,related accept",
    ]
    for entry in acl_entries(router.acl):
        source = _endpoint_match(spec, entry.source, "src", nics, allocation)
        dest = _endpoint_match(spec, entry.destination, "dst", nics, allocation)
        verdict = "accept" if entry.allowed else "drop"
        matches = [match for match in (source, dest, service_match(entry.raw)) if match]
        lines.append("    " + " ".join(matches + [verdict]))
    lines += ["  }", "}"]
    return "\n".join(lines) + "\n"


def _endpoint_match(
    spec: RangeSpec,
    endpoint: str,
    side: str,
    nics: dict[str, str],
    allocation: Allocation,
) -> str:
    networks = {network.name: network for network in spec.networks}
    guest_networks: dict[str, set[str]] = {
        guest.name: {interface.network for interface in guest.interfaces}
        for guest in allocation.guests
    }
    kind, cidr = endpoint_kind(endpoint, networks, guest_networks)
    if kind == "network":
        if endpoint in nics:
            keyword = "iifname" if side == "src" else "oifname"
            return f'{keyword} "{nics[endpoint]}"'
        # a network the router reaches via routes (slice 3): match its subnet instead
        keyword = "ip saddr" if side == "src" else "ip daddr"
        return f"{keyword} {networks[endpoint].cidr}"
    if kind == "guest":
        addresses = allocation.addresses(endpoint)
        keyword = "ip saddr" if side == "src" else "ip daddr"
        if len(addresses) == 1:
            return f"{keyword} {addresses[0]}"
        return f"{keyword} {{ {', '.join(str(address) for address in addresses)} }}"
    if kind == "cidr" and cidr is not None:
        if str(cidr) == "0.0.0.0/0":
            return ""
        keyword = "ip saddr" if side == "src" else "ip daddr"
        return f"{keyword} {cidr}"
    raise ValueError(
        f"unresolvable ACL endpoint {endpoint!r} (validation should have caught this)"
    )


def service_match(entry: str) -> str:
    if entry == "icmp":
        return "meta l4proto icmp"
    proto, _, ports = entry.partition("/")
    return f"{proto} dport {ports}"

"""Render a router guest's nftables ruleset from its ordered ACL.

The ruleset is default-deny and stateful: policy `drop` on the forward hook, `established,related` accepted first, then the spec's rules in declaration order (first-match, so `deny` carve-outs work by preceding broader allows). Endpoint forms compile as: network name → interface match (`iifname`/`oifname` against the router's deterministic NIC names, `eth0..n` in interface declaration order, applied by the generated guest network config via MAC match); guest name → address-set match over the guest's allocated addresses; CIDR → address match (`0.0.0.0/0` compiles to no match at all).
"""

from ..types import AclRule, RangeSpec, Router, endpoint_kind
from ._allocate import Allocation


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
    lines = [
        "table inet fw {",
        "  chain forward {",
        "    type filter hook forward priority 0; policy drop;",
        "    ct state established,related accept",
    ]
    for rule in router.acl:
        lines += [f"    {line}" for line in _render_rule(spec, rule, nics, allocation)]
    lines += ["  }", "}"]
    return "\n".join(lines) + "\n"


def _render_rule(
    spec: RangeSpec, rule: AclRule, nics: dict[str, str], allocation: Allocation
) -> list[str]:
    source = _endpoint_match(spec, rule.from_, "src", nics, allocation)
    dest = _endpoint_match(spec, rule.to, "dst", nics, allocation)
    verdict = "accept" if rule.allow is not None else "drop"
    rendered: list[str] = []
    for entry in rule.allow if rule.allow is not None else rule.deny or []:
        matches = [match for match in (source, dest, _service_match(entry)) if match]
        rendered.append(" ".join(matches + [verdict]))
    return rendered


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


def _service_match(entry: str) -> str:
    if entry == "icmp":
        return "meta l4proto icmp"
    proto, _, ports = entry.partition("/")
    return f"{proto} dport {ports}"

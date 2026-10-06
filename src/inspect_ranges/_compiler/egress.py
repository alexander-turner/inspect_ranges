"""Hypervisor-side egress realization: NAT exactly the allowlist out of the range netns, drop everything else.

Scoped egress is enforced where the agent cannot reach it: in the range container's network namespace, not on any guest. The forward chain stays default-deny with stateful returns; each `mode: nat` network's allowlist entries become accepts from its bridge to the uplink, and the attacker's own egress policy composes ahead of network policy (an explicit drop for `none`, so a network allowlist never grants the attacker a path; its own entries for a scoped policy). A masquerade rule NATs whatever the filter admitted.

Realization scope (networking-v0.2 §3): routerless `mode: nat` networks; validation gates the router-attached combination (`egress-with-router-not-realized`) and FQDN entries (`egress-fqdn-not-realized`) before this stage runs.
"""

from ipaddress import IPv4Address

from ..types import EgressPolicy, RangeSpec, parse_egress_entry
from .allocate import Allocation
from .nftables import service_match  # shared entry→match rendering


def bridge_name(network: str) -> str:
    """The range-netns bridge device for a network (shared convention with the realization glue)."""
    return f"br-{network}"[:15]


def render_egress_nftables(
    spec: RangeSpec, allocation: Allocation, uplink: str = "eth0"
) -> str:
    """Render the range-netns ruleset: forward invariants, the egress allowlist, and NAT.

    Args:
        spec: The validated range definition.
        allocation: The range's allocation (resolves the attacker's addresses for its override rules).
        uplink: The netns interface egress leaves through.

    Returns:
        An `nft -f`-loadable ruleset (also correct for ranges with no egress at all: default-deny forward, no NAT table).
    """
    rules: list[str] = []

    attacker_name = spec.attacker.host or spec.attacker.name
    attacker_match = _address_match(allocation.addresses(attacker_name), "saddr")
    if spec.attacker.egress == "none":
        rules.append(f'{attacker_match} oifname "{uplink}" drop')
    elif spec.attacker.egress == "open":
        rules.append(f'{attacker_match} oifname "{uplink}" accept')
    else:
        rules += _entry_rules(spec.attacker.egress, attacker_match, uplink)

    has_egress = isinstance(spec.attacker.egress, EgressPolicy) or (
        spec.attacker.egress == "open"
    )
    for network in spec.networks:
        if network.egress is None:
            continue
        has_egress = True
        source = f'iifname "{bridge_name(network.name)}"'
        rules += _entry_rules(network.egress, source, uplink)

    lines = [
        "flush ruleset",
        "table inet rangehost {",
        "  chain forward {",
        "    type filter hook forward priority 0; policy drop;",
        "    ct state established,related accept",
        *[f"    {rule}" for rule in rules],
        "  }",
        "}",
    ]
    if has_egress:
        lines += [
            "table ip rangenat {",
            "  chain postrouting {",
            "    type nat hook postrouting priority srcnat; policy accept;",
            f'    oifname "{uplink}" masquerade',
            "  }",
            "}",
        ]
    return "\n".join(lines) + "\n"


def _entry_rules(policy: EgressPolicy, source: str, uplink: str) -> list[str]:
    rules: list[str] = []
    for entry in policy.allow:
        cidr, fqdn, service = parse_egress_entry(entry)
        if fqdn is not None or cidr is None:
            raise ValueError(
                f"egress entry {entry!r} is not realizable (validation should have gated it)"
            )
        matches = [source, f'oifname "{uplink}"']
        if str(cidr) != "0.0.0.0/0":
            matches.append(f"ip daddr {cidr}")
        if service is not None:
            matches.append(service_match(service))
        rules.append(" ".join(matches + ["accept"]))
    return rules


def _address_match(addresses: list[IPv4Address], keyword: str) -> str:
    rendered = [str(address) for address in addresses]
    if len(rendered) == 1:
        return f"ip {keyword} {rendered[0]}"
    return f"ip {keyword} {{ {', '.join(rendered)} }}"

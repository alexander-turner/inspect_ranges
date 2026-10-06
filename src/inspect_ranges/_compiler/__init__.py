"""The range compiler: spec → deterministic allocation → rendered artifacts.

This package grows stage by stage with the networking v0.2 slices (see `design/inspect-ranges/networking-v0.2.md` §9). Current stages: `allocate` (deterministic per-guest addressing, MACs, and vsock CIDs — the plan-time resolution ACL v2's guest endpoints require), `render_router_nftables` (a router's ordered, default-deny, stateful ruleset), `elect_gateways` (each network's default-gateway address, router or hypervisor NAT), and `render_egress_nftables` (the range-netns invariants plus the scoped-egress allowlist and NAT).
"""

from .allocate import Allocation, GuestAllocation, InterfaceAllocation, allocate
from .egress import bridge_name, render_egress_nftables
from .nftables import render_router_nftables
from .routing import elect_gateways

__all__ = [
    "Allocation",
    "GuestAllocation",
    "InterfaceAllocation",
    "allocate",
    "bridge_name",
    "elect_gateways",
    "render_egress_nftables",
    "render_router_nftables",
]

"""The range compiler: spec → deterministic allocation → rendered artifacts.

This package grows stage by stage with the networking v0.2 slices (see `design/inspect-ranges/networking-v0.2.md` §9). Current stages: `allocate` (deterministic per-guest addressing, MACs, and vsock CIDs — the plan-time resolution ACL v2's guest endpoints require), `render_router_nftables` (a router's ordered, default-deny, stateful ruleset), `elect_gateways` (each network's default-gateway address, router or hypervisor NAT), and `render_egress_nftables` (the range-netns invariants plus the scoped-egress allowlist and NAT).
"""

from .allocate import Allocation, GuestAllocation, InterfaceAllocation, allocate
from .dnsmasq import render_dnsmasq_conf, resolvers_for, search_domain
from .egress import bridge_name, render_egress_nftables
from .nftables import render_router_nftables
from .plan import ImageRef, PlanOptions, ResolvedPlan, plan_json, resolve_plan
from .render import render_bundle
from .routing import elect_gateways

__all__ = [
    "Allocation",
    "GuestAllocation",
    "ImageRef",
    "PlanOptions",
    "ResolvedPlan",
    "InterfaceAllocation",
    "allocate",
    "bridge_name",
    "elect_gateways",
    "plan_json",
    "render_bundle",
    "render_dnsmasq_conf",
    "render_egress_nftables",
    "render_router_nftables",
    "resolvers_for",
    "resolve_plan",
    "search_domain",
]

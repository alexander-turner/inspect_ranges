"""The range compiler: spec → deterministic allocation → rendered artifacts.

This package grows stage by stage with the networking v0.2 slices (see `design/inspect-ranges/networking-v0.2.md` §9). Current stages: `allocate` (deterministic per-guest addressing, MACs, and vsock CIDs — the plan-time resolution ACL v2's guest endpoints require) and `render_router_nftables` (a router's ordered, default-deny, stateful ruleset).
"""

from ._allocate import Allocation, GuestAllocation, InterfaceAllocation, allocate
from ._nftables import render_router_nftables

__all__ = [
    "Allocation",
    "GuestAllocation",
    "InterfaceAllocation",
    "allocate",
    "render_router_nftables",
]

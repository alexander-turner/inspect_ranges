"""Shared network-identity rules for evidence scans: one source of truth for compare() and corroborate().

The two scans over the same capture must apply identical identity rules, or they disagree and manufacture false contradictions: a flow `compare` counted that `corroborate` excludes reads as a contradiction and invalidates the sample. Both the guest-address lookup and the probe-frame exclusion live here so they cannot drift.
"""

from ipaddress import IPv4Address

from .._compiler.plan import ResolvedPlan

__all__ = ["PROBE_MAC_PREFIX", "guest_segment_ip"]

PROBE_MAC_PREFIX = b"\x02\x50"
"""The declared probe-endpoint MAC convention (`02:50:`, the prober spike): frames with this source MAC are excluded from agent-traffic reasoning by spec, in EVERY scan. Plans without probe endpoints are unaffected (nothing carries the prefix)."""


def guest_segment_ip(plan: ResolvedPlan, guest: str, segment: str) -> IPv4Address:
    """The guest's interface address ON the declared segment.

    Source binding must watch the right NIC of a multi-homed guest; the declared segment picks it.

    Raises:
        KeyError: `guest` has no interface on `segment`.
    """
    for planned in plan.guests:
        if planned.name != guest:
            continue
        for interface in planned.interfaces:
            if interface.network == segment:
                return interface.ip
    raise KeyError(f"guest {guest!r} has no interface on segment {segment!r}")

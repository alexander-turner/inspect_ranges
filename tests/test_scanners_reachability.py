"""`expected_reachable`: the config-aware model behind the reachability detectors.

Table-driven over one two-segment fixture whose router ACL varies per case; the semantics pinned here are the nftables renderer's documented contract (plain router accepts, declared rules flip to default-drop first-match), evaluated over the compiler's own allocation and endpoint classification.
"""

from ipaddress import IPv4Address, IPv4Network

import pytest
from inspect_ranges._scanners.reachability import expected_reachable, range_networks
from inspect_ranges.types import (
    AclRule,
    Attacker,
    Host,
    Interface,
    Network,
    Os,
    RangeMeta,
    RangeSpec,
    Route,
    Router,
)

WEB = IPv4Address("10.80.10.10")
DB = IPv4Address("10.80.20.10")
ROUTER_DMZ = IPv4Address("10.80.10.1")
ROUTER_CORE = IPv4Address("10.80.20.1")


def two_segment_spec(acl: list[AclRule], foothold_host: str | None = None) -> RangeSpec:
    """A dmz/core pair joined by one router, with the ACL under test."""
    return RangeSpec(
        meta=RangeMeta(name="reach-unit", description="reachability fixture"),
        networks=[
            Network(name="dmz", cidr="10.80.10.0/24", mode="isolated"),
            Network(name="core", cidr="10.80.20.0/24", mode="isolated"),
        ],
        routers=[
            Router(
                name="fw",
                interfaces=[
                    Interface(network="dmz", ip="10.80.10.1"),
                    Interface(network="core", ip="10.80.20.1"),
                ],
                acl=acl,
            )
        ],
        hosts=[
            Host(
                name="web",
                os=Os(type="linux"),
                image="img",
                interfaces=[Interface(network="dmz", ip="10.80.10.10")],
            ),
            Host(
                name="db",
                os=Os(type="linux"),
                image="img",
                interfaces=[Interface(network="core", ip="10.80.20.10")],
            ),
        ],
        attacker=(
            Attacker(host=foothold_host, entry="assumed-breach")
            if foothold_host
            else Attacker(interfaces=[Interface(network="dmz")], entry="external")
        ),
    )


@pytest.mark.parametrize(
    ("acl", "db_reachable"),
    [
        # a plain router (no declared ACL) is policy accept
        ([], True),
        # network-name endpoints, allowed service
        ([AclRule(from_="dmz", to="core", allow=["tcp/5432"])], True),
        # guest-name endpoints resolve through the allocation
        ([AclRule(from_="attacker", to="db", allow=["tcp/5432"])], True),
        # CIDR endpoints match the allocated addresses
        (
            [AclRule(from_="10.80.10.0/24", to="10.80.20.10/32", allow=["icmp"])],
            True,
        ),
        # first-match: a deny carve-out for the same service precedes the allow
        (
            [
                AclRule(from_="dmz", to="core", deny=["tcp/5432"]),
                AclRule(from_="dmz", to="core", allow=["tcp/5432"]),
            ],
            False,
        ),
        # a deny for a different service does not shadow the allow
        (
            [
                AclRule(from_="dmz", to="core", deny=["tcp/80"]),
                AclRule(from_="dmz", to="core", allow=["tcp/5432"]),
            ],
            True,
        ),
        # a deny range covering the allowed port shadows it
        (
            [
                AclRule(from_="dmz", to="core", deny=["tcp/1-65535"]),
                AclRule(from_="dmz", to="core", allow=["tcp/5432"]),
            ],
            False,
        ),
        # declared rules flip to default-drop: a reverse-direction allow is no path
        ([AclRule(from_="core", to="dmz", allow=["tcp/22"])], False),
        # a rule sourced at another guest never admits the foothold
        ([AclRule(from_="web", to="core", allow=["tcp/22"])], False),
    ],
)
def test_cross_segment_reachability_follows_the_acl(
    acl: list[AclRule], db_reachable: bool
) -> None:
    spec = two_segment_spec(acl)
    reachable = expected_reachable(spec)
    # the same-segment host and the router's near interface are always L2-reachable
    assert WEB in reachable
    assert ROUTER_DMZ in reachable
    assert (DB in reachable) is db_reachable


def test_foothold_on_host_excludes_itself() -> None:
    spec = two_segment_spec([], foothold_host="web")
    reachable = expected_reachable(spec)
    assert WEB not in reachable
    assert DB in reachable  # plain router from web's segment


def test_multi_hop_destinations_stay_out_of_the_set() -> None:
    """The deliberate single-hop scope: a destination behind a second router is not computed (quiet, never wrong)."""
    spec = RangeSpec(
        meta=RangeMeta(name="chain-unit", description="two-router chain"),
        networks=[
            Network(name="dmz", cidr="10.80.10.0/24", mode="isolated"),
            Network(name="core", cidr="10.80.20.0/24", mode="isolated", gateway="r1"),
            Network(name="vault", cidr="10.80.30.0/24", mode="isolated"),
        ],
        routers=[
            Router(
                name="r1",
                interfaces=[
                    Interface(network="dmz", ip="10.80.10.1"),
                    Interface(network="core", ip="10.80.20.1"),
                ],
                routes=[Route(to="10.80.30.0/24", via="10.80.20.2")],
            ),
            Router(
                name="r2",
                interfaces=[
                    Interface(network="core", ip="10.80.20.2"),
                    Interface(network="vault", ip="10.80.30.1"),
                ],
            ),
        ],
        hosts=[
            Host(
                name="safe",
                os=Os(type="linux"),
                image="img",
                interfaces=[Interface(network="vault", ip="10.80.30.10")],
            )
        ],
        attacker=Attacker(interfaces=[Interface(network="dmz")], entry="external"),
    )
    reachable = expected_reachable(spec)
    assert IPv4Address("10.80.30.10") not in reachable
    assert IPv4Address("10.80.20.2") in reachable  # one hop through r1 (plain)


def test_range_networks_lists_the_declared_subnets() -> None:
    spec = two_segment_spec([])
    assert range_networks(spec) == [
        IPv4Network("10.80.10.0/24"),
        IPv4Network("10.80.20.0/24"),
    ]

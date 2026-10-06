from ipaddress import IPv4Address

from inspect_ranges._compiler import allocate, render_router_nftables
from inspect_ranges.types import (
    AclRule,
    Attacker,
    Host,
    Interface,
    Network,
    Os,
    RangeMeta,
    RangeSpec,
    Router,
)


def two_segment_spec() -> RangeSpec:
    return RangeSpec(
        meta=RangeMeta(name="acl-v2-unit", description="compiler unit fixture"),
        networks=[
            Network(name="dmz", cidr="10.80.10.0/24", mode="isolated"),
            Network(name="internal", cidr="10.80.20.0/24", mode="isolated"),
        ],
        routers=[
            Router(
                name="router",
                interfaces=[
                    Interface(network="dmz"),
                    Interface(network="internal"),
                ],
                acl=[
                    AclRule(from_="dmz", to="db", deny=["tcp/22"]),
                    AclRule(
                        from_="dmz", to="internal", allow=["tcp/22", "tcp/5432", "icmp"]
                    ),
                    AclRule(from_="10.80.10.10/32", to="internal", allow=["tcp/80-90"]),
                    AclRule(from_="0.0.0.0/0", to="dmz", allow=["tcp/443"]),
                ],
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
                interfaces=[Interface(network="internal")],
            ),
        ],
        attacker=Attacker(interfaces=[Interface(network="dmz")], entry="external"),
    )


def test_allocation_is_deterministic_and_conventional() -> None:
    spec = two_segment_spec()
    first = allocate(spec)
    second = allocate(spec)
    assert first == second
    # router takes the first usable address on each attached network
    assert first.addresses("router") == [
        IPv4Address("10.80.10.1"),
        IPv4Address("10.80.20.1"),
    ]
    # attacker follows the routers; explicit host IPs are honored; hosts start at .10
    assert first.addresses("attacker") == [IPv4Address("10.80.10.2")]
    assert first.addresses("web") == [IPv4Address("10.80.10.10")]
    assert first.addresses("db") == [IPv4Address("10.80.20.10")]
    # CIDs follow spec declaration order: hosts, routers, attacker
    assert [(guest.name, guest.cid) for guest in first.guests] == [
        ("web", 3),
        ("db", 4),
        ("router", 5),
        ("attacker", 6),
    ]


def test_allocator_skips_explicitly_claimed_addresses() -> None:
    spec = two_segment_spec()
    spec.hosts[0].interfaces[0] = Interface(network="dmz", ip="10.80.10.1")
    allocation = allocate(spec)
    # the host claimed .1, so the router moves to the next free address
    assert allocation.addresses("router")[0] == IPv4Address("10.80.10.2")
    assert allocation.addresses("attacker") == [IPv4Address("10.80.10.3")]


def test_mac_addresses_are_stable_and_distinct() -> None:
    allocation = allocate(two_segment_spec())
    macs = [
        interface.mac for guest in allocation.guests for interface in guest.interfaces
    ]
    assert len(set(macs)) == len(macs)
    assert all(mac.startswith("52:54:00:") for mac in macs)


def test_router_ruleset_renders_in_rule_order() -> None:
    spec = two_segment_spec()
    ruleset = render_router_nftables(spec, "router", allocate(spec))
    lines = [line.strip() for line in ruleset.splitlines()]
    assert lines[2] == "type filter hook forward priority 0; policy drop;"
    assert lines[3] == "ct state established,related accept"
    assert lines[4:9] == [
        # deny carve-out first (guest endpoint resolved to db's allocated address)
        'iifname "eth0" ip daddr 10.80.20.10 tcp dport 22 drop',
        # then the broader allow, one line per entry
        'iifname "eth0" oifname "eth1" tcp dport 22 accept',
        'iifname "eth0" oifname "eth1" tcp dport 5432 accept',
        'iifname "eth0" oifname "eth1" meta l4proto icmp accept',
        # CIDR endpoint with a port range
        'ip saddr 10.80.10.10/32 oifname "eth1" tcp dport 80-90 accept',
    ]
    # 0.0.0.0/0 compiles to no source match at all
    assert lines[9] == 'oifname "eth0" tcp dport 443 accept'

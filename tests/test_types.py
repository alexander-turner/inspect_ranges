import pytest
from inspect_ranges import revalidate_range
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
from pydantic import ValidationError


def dmz_pivot() -> RangeSpec:
    """The overview's dmz-pivot example as typed construction (reads like the YAML)."""
    return RangeSpec(
        meta=RangeMeta(name="dmz-pivot", description="typed construction"),
        networks=[
            Network(name="dmz", cidr="10.80.10.0/24", mode="isolated"),
            Network(name="internal", cidr="10.80.20.0/24", mode="isolated"),
        ],
        routers=[
            Router(
                name="router",
                interfaces=[
                    Interface(network="dmz", ip="10.80.10.1"),
                    Interface(network="internal", ip="10.80.20.1"),
                ],
                acl=[AclRule(from_="dmz", to="internal", allow=["tcp/5432"])],
            )
        ],
        hosts=[
            Host(
                name="web",
                os=Os(type="linux"),
                image="acme/web-golden",
                interfaces=[Interface(network="dmz", ip="10.80.10.10")],
            ),
            Host(
                name="db",
                os=Os(type="linux"),
                image="acme/db-golden",
                interfaces=[Interface(network="internal")],
            ),
        ],
        attacker=Attacker(interfaces=[Interface(network="dmz")], entry="external"),
    )


def test_typed_construction_coerces_and_validates() -> None:
    spec = dmz_pivot()
    assert str(spec.networks[0].cidr) == "10.80.10.0/24"
    assert spec.routers[0].acl[0].from_ == "dmz"
    assert spec.attacker.egress == "none"


def test_revalidate_range_passes_through_a_consistent_spec() -> None:
    spec = dmz_pivot()
    checked = revalidate_range(spec)
    assert checked == spec
    assert checked is not spec


def test_revalidate_range_catches_post_construction_mutation() -> None:
    spec = dmz_pivot()
    spec.hosts.append(
        Host(
            name="web",  # duplicate guest name
            os=Os(type="linux"),
            image="img",
            interfaces=[Interface(network="dmx")],  # undeclared network
        )
    )
    with pytest.raises(ValidationError) as excinfo:
        revalidate_range(spec)
    message = str(excinfo.value)
    assert "is not unique" in message
    assert "undeclared network 'dmx'" in message

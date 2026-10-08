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


def test_guest_content_typed_construction() -> None:
    """Guest content constructs and validates through the typed surface."""
    from inspect_ranges.types import (
        ActiveDirectory,
        AdAcl,
        AdDomain,
        AdUser,
        Defense,
        Service,
        Telemetry,
        User,
        Vulnerability,
    )

    spec = dmz_pivot().model_copy(deep=True)
    spec.hosts[0].users = [User(name="alice", password="bacon")]
    spec.hosts[0].services = [Service(name="httpd", port=80)]
    spec.hosts[0].vulnerabilities = [
        Vulnerability(id="weak-thing", service="httpd", description="seeded")
    ]
    spec.defense = Defense(
        tier="D2", telemetry=[Telemetry(source="web", collector="agent", sink="db")]
    )
    spec.active_directory = ActiveDirectory(
        forest="corp.example",
        domains=[
            AdDomain(
                name="corp.example",
                netbios="CORP",
                dc="web",
                users=[AdUser(name="svc", spns=["HTTP/web.corp.example"])],
                acls=[AdAcl(principal="a", right="GenericAll", target="b")],
            )
        ],
    )
    checked = revalidate_range(spec)
    assert checked.active_directory is not None
    assert checked.active_directory.domains[0].acls[0].right == "GenericAll"


def test_unresolved_reference_to_declared_variable_is_rejected() -> None:
    """References resolve only on the YAML path; a typed spec carrying `{{name}}` for a declared variable is a construction mistake, while braces naming nothing declared stay legal scenario content."""
    from inspect_ranges.types import DataFile, User, Variable

    spec = dmz_pivot()
    spec.variables = {"admin_password": Variable(default="hunter2")}
    spec.hosts[0].users = [User(name="admin", password="{{admin_password}}")]
    with pytest.raises(ValidationError, match="unresolved reference"):
        revalidate_range(spec)

    spec.hosts[0].users = [User(name="admin", password="hunter2")]
    spec.hosts[0].data = [
        DataFile(path="/srv/app/payload.txt", contents="{{secret_key}} and {{7*7}}")
    ]
    revalidate_range(spec)


def test_ipv6_values_are_gated() -> None:
    # the dual-stack types accept IPv6 structurally (the Network constructs),
    # but the spec-level gate rejects it until realization lands
    v6 = Network(name="lab", cidr="fd00::/8", mode="isolated")
    assert str(v6.cidr) == "fd00::/8"
    spec = dmz_pivot()
    spec.networks[0] = Network(name="dmz", cidr="fd00::/8", mode="isolated")
    with pytest.raises(ValidationError, match="not yet realized"):
        revalidate_range(spec)


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


def test_range_spec_hash_tracks_content() -> None:
    """Specs work as cache keys (Inspect hashes sandbox configs): equal content hashes equal, mutation changes the hash."""
    from inspect_ranges.types import Variable

    a = dmz_pivot()
    b = dmz_pivot()
    assert hash(a) == hash(b)
    assert {a: "cached"}[b] == "cached"
    # pydantic equality ignores dict insertion order; the hash must too
    a.variables = {"x": Variable(default=1), "y": Variable(default=2)}
    b.variables = {"y": Variable(default=2), "x": Variable(default=1)}
    assert a == b
    assert hash(a) == hash(b)
    b.hosts[0].hostname = "renamed"
    assert hash(a) != hash(b)

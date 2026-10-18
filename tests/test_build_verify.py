"""The verification engine's pure core: ss/dpkg parsing and declaration evaluation against synthetic `GuestFacts`, no guest required."""

import pytest
from inspect_ranges._build.verify import (
    DeclarationResult,
    GuestFacts,
    evaluate_host,
    parse_packages,
    parse_pid_packages,
    parse_ss,
    version_matches,
)
from inspect_ranges.types import Host, Interface, Os, Service, Vulnerability

SS_TCP = (
    'LISTEN 0      511          0.0.0.0:80        0.0.0.0:*    users:(("nginx",pid=615,fd=6))\n'
    'LISTEN 0      70         127.0.0.1:33060     0.0.0.0:*    users:(("mysqld",pid=702,fd=21))\n'
    "LISTEN 0      151            [::]:3306          [::]:*\n"
)
SS_UDP = 'UNCONN 0      0            0.0.0.0:38358     0.0.0.0:*    users:(("systemd-timesyn",pid=488,fd=16))\n'
DPKG = "nginx-core\t1.18.0-6ubuntu14.4\nmysql-server-8.0\t8.0.39-0ubuntu0.20.04.1\nzabbix-frontend-php\t1:3.0.3+dfsg-1\n"
ATTRIB = "pid 615 pkg nginx-core: /usr/sbin/nginx\npid 702 pkg mysql-server-core-8.0: /usr/sbin/mysqld\n"


def host_with(
    services: list[Service] | None = None,
    vulnerabilities: list[Vulnerability] | None = None,
) -> Host:
    return Host(
        name="web",
        os=Os(type="linux"),
        image="focal-guest",
        interfaces=[Interface(network="lab")],
        services=services or [],
        vulnerabilities=vulnerabilities or [],
    )


def by_name(results: list[DeclarationResult], name: str) -> DeclarationResult:
    return next(r for r in results if r.name == name)


def test_parse_ss_tcp_and_udp() -> None:
    tcp = parse_ss(SS_TCP, "tcp")
    assert (tcp[0].port, tcp[0].process, tcp[0].pid) == (80, "nginx", 615)
    assert (tcp[2].port, tcp[2].process, tcp[2].pid) == (3306, None, None)
    udp = parse_ss(SS_UDP, "udp")
    assert udp[0].proto == "udp" and udp[0].port == 38358


def test_parse_packages_and_attributions() -> None:
    packages = parse_packages(DPKG)
    assert packages["nginx-core"] == "1.18.0-6ubuntu14.4"
    assert parse_pid_packages(ATTRIB) == {
        615: "nginx-core",
        702: "mysql-server-core-8.0",
    }


@pytest.mark.parametrize(
    ("declared", "observed", "expected"),
    [
        ("1.18", "1.18.0-6ubuntu14.4", True),
        ("1.18.0", "1.18.0-6ubuntu14.4", True),
        ("3.0.3", "1:3.0.3+dfsg-1", True),
        ("1.1", "1.18.0-6ubuntu14.4", False),
        ("1.19", "1.18.0-6ubuntu14.4", False),
        ("8.0.39", "8.0.39-0ubuntu0.20.04.1", True),
        ("1.18", "1.18~rc1-1", False),
        ("1:3.0.3", "1:3.0.3+dfsg-1", True),
        # round-1: a ~ deeper in the upstream component is still a pre-release
        ("3.0", "3.0.3~rc1-1", False),
        ("1.18", "1.18.0~rc1-1", False),
        # ...but a backport suffix in the DEBIAN REVISION stays matchable
        ("1.18", "1.18.0-1ubuntu1~20.04", True),
        # a deliberately declared pre-release matches itself
        ("1.18.0~rc1", "1.18.0~rc1-1", True),
        # round-1: the +really downgrade convention binds to what ships
        ("1.18.0", "1.18.0+really1.16.1-1", False),
        ("1.16", "1.18.0+really1.16.1-1", True),
        # round-2: a verbatim-copied +really declaration matches itself
        ("1.18.0+really1.16.1", "1.18.0+really1.16.1-1", True),
    ],
)
def test_version_matches(declared: str, observed: str, expected: bool) -> None:
    assert version_matches(declared, observed) is expected


def facts() -> GuestFacts:
    return GuestFacts(
        listeners=parse_ss(SS_TCP, "tcp") + parse_ss(SS_UDP, "udp"),
        packages=parse_packages(DPKG),
        pid_packages=parse_pid_packages(ATTRIB),
    )


def test_service_verifies_listening_and_version_via_listener_chain() -> None:
    host = host_with([Service(name="nginx", port=80, version="1.18")])
    result = by_name(evaluate_host(host, facts()), "nginx")
    assert result.status == "ok" and result.code == ""
    assert "nginx-core" in result.observed


def test_service_version_via_declared_package_field() -> None:
    host = host_with(
        [
            Service(
                name="zabbix-web",
                port=80,
                version="3.0.3",
                package="zabbix-frontend-php",
            )
        ]
    )
    result = by_name(evaluate_host(host, facts()), "zabbix-web")
    assert result.status == "ok"
    assert "zabbix-frontend-php" in result.observed


def test_service_version_mismatch_names_the_delta() -> None:
    host = host_with([Service(name="nginx", port=80, version="1.19")])
    result = by_name(evaluate_host(host, facts()), "nginx")
    assert result.status == "fail" and result.code == "service-not-verified"
    assert (
        "1.18.0-6ubuntu14.4" in result.observed and "declared 1.19" in result.observed
    )


def test_dead_service_fails_on_listening() -> None:
    host = host_with([Service(name="redis", port=6379)])
    result = by_name(evaluate_host(host, facts()), "redis")
    assert result.status == "fail"
    assert "no tcp/udp socket on port 6379" in result.observed


def test_unattributable_version_names_the_paths_tried() -> None:
    # port 3306 listener has no pid attribution and no package named 'mysql'
    host = host_with([Service(name="mysql", port=3306, version="8.0")])
    result = by_name(evaluate_host(host, facts()), "mysql")
    assert result.status == "fail"
    assert "version unattributable" in result.observed
    assert "no package named 'mysql'" in result.observed


def test_declared_package_absent_fails() -> None:
    host = host_with([Service(name="app", port=80, version="1.0", package="ghost-pkg")])
    result = by_name(evaluate_host(host, facts()), "app")
    assert result.status == "fail"
    assert "'ghost-pkg' is not installed" in result.observed


def test_name_only_service_is_vacuously_ok() -> None:
    host = host_with([Service(name="syslog")])
    result = by_name(evaluate_host(host, facts()), "syslog")
    assert result.status == "ok"
    assert "nothing mechanically checkable" in result.observed


def test_udp_satisfies_listening() -> None:
    host = host_with([Service(name="timesync", port=38358)])
    assert by_name(evaluate_host(host, facts()), "timesync").status == "ok"


def test_vulnerability_follows_its_linked_service() -> None:
    host = host_with(
        [
            Service(name="nginx", port=80, version="1.19"),
            Service(name="ok-svc", port=3306),
        ],
        [
            Vulnerability(id="cve-x", service="nginx", description="d"),
            Vulnerability(id="cve-y", service="ok-svc", description="d"),
            Vulnerability(id="free-vuln", description="d"),
        ],
    )
    results = evaluate_host(host, facts())
    assert by_name(results, "cve-x").status == "fail"
    assert by_name(results, "cve-x").code == "vulnerability-not-verified"
    assert "failed its assertion" in by_name(results, "cve-x").observed
    assert by_name(results, "cve-y").status == "ok"
    free = by_name(results, "free-vuln")
    assert free.status == "ok" and "no service linkage" in free.observed


def test_parse_packages_filters_removed_but_not_purged() -> None:
    """Round-1: rc-state packages print full versions; counting them installed false-passes version declarations against files that are gone."""
    output = (
        "nginx-core\t1.18.0-6ubuntu14.4\tinstall ok installed\n"
        "oldpkg\t2.0-1\tdeinstall ok config-files\n"
        "pinned\t1.2.3-1\thold ok installed\n"
        "legacyline\t3.1-2\n"
    )
    packages = parse_packages(output)
    assert packages == {
        "nginx-core": "1.18.0-6ubuntu14.4",
        # held-but-installed stays counted (round-2: apt-mark hold is the
        # canonical pin for vulnerable-by-design versions)
        "pinned": "1.2.3-1",
        # a status-less line (the pre-review probe shape) stays accepted
        "legacyline": "3.1-2",
    }

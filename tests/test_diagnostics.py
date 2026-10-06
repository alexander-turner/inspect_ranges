from pathlib import Path
from typing import Any

import pytest
import yaml
from inspect_ranges._diagnostics import ValidationReport, format_path
from inspect_ranges.schema import validate_range

MINIMAL = """
range:
  name: minimal
  description: minimal valid range
networks:
  - { name: lab, cidr: 10.0.0.0/24, mode: isolated }
hosts:
  - name: web
    os: { type: linux }
    image: img
    interfaces: [{ network: lab, ip: 10.0.0.10 }]
attacker:
  interfaces: [{ network: lab }]
  entry: external
"""


def report_for(text: str, tmp_path: Path) -> ValidationReport:
    path = tmp_path / "range.yaml"
    path.write_text(text)
    return validate_range(path)


def report_with(overrides_yaml: str, tmp_path: Path) -> ValidationReport:
    data: dict[str, Any] = yaml.safe_load(MINIMAL)
    data.update(yaml.safe_load(overrides_yaml))
    return report_for(yaml.safe_dump(data), tmp_path)


def codes(report: ValidationReport) -> list[str]:
    return [issue.code for issue in report.issues]


# --- structural stage ----------------------------------------------------------


@pytest.mark.parametrize(
    ("text", "code"),
    [
        pytest.param("range: [unclosed", "yaml-syntax", id="yaml-syntax"),
        pytest.param("- a\n- b\n", "not-a-mapping", id="not-a-mapping"),
        pytest.param(
            MINIMAL.replace("image:", "imagee:"), "unknown-key", id="unknown-key"
        ),
        pytest.param(
            MINIMAL.replace("    image: img\n", ""), "missing-field", id="missing-field"
        ),
        pytest.param(
            MINIMAL.replace("10.0.0.0/24", "10.0.0.0/33"),
            "invalid-cidr",
            id="invalid-cidr",
        ),
        pytest.param(
            MINIMAL.replace("ip: 10.0.0.10", "ip: banana"),
            "invalid-ip",
            id="invalid-ip",
        ),
        pytest.param(
            MINIMAL.replace("mode: isolated", "mode: bananas"),
            "invalid-value",
            id="invalid-value",
        ),
        pytest.param(
            MINIMAL + "\nextra_hosts: 5\n", "unknown-key", id="unknown-top-level-key"
        ),
    ],
)
def test_structural_codes(text: str, code: str, tmp_path: Path) -> None:
    report = report_for(text, tmp_path)
    assert not report.valid
    assert code in codes(report)


def test_invalid_schema_version_code(tmp_path: Path) -> None:
    data: dict[str, Any] = yaml.safe_load(MINIMAL)
    data["range"]["schema_version"] = "0.3"
    report = report_for(yaml.safe_dump(data), tmp_path)
    assert codes(report) == ["invalid-schema-version"]
    assert "'0.1'" in report.issues[0].message


def test_schema_version_02_accepted(tmp_path: Path) -> None:
    data: dict[str, Any] = yaml.safe_load(MINIMAL)
    data["range"]["schema_version"] = "0.2"
    report = report_for(yaml.safe_dump(data), tmp_path)
    assert report.valid


def test_dual_stack_union_error_collapses_to_one_issue(tmp_path: Path) -> None:
    report = report_for(MINIMAL.replace("10.0.0.0/24", "banana"), tmp_path)
    assert codes(report) == ["invalid-cidr"]
    assert "IPv4 or IPv6 network" in report.issues[0].message


ACL_BASE = """
networks:
  - {{ name: lab, cidr: 10.0.0.0/24, mode: isolated }}
  - {{ name: dmz, cidr: 10.0.1.0/24, mode: isolated }}
hosts:
  - name: web
    os: {{ type: linux }}
    image: img
    interfaces: [{{ network: dmz, ip: 10.0.1.10 }}]
routers:
  - name: r
    interfaces: [{{ network: lab }}, {{ network: dmz }}]
    acl: {acl}
"""


@pytest.mark.parametrize(
    ("acl", "code"),
    [
        pytest.param(
            "[{ from: lab, to: dmz, allow: [tcp/80], deny: [tcp/22] }]",
            "invalid-deny-rule",
            id="both-allow-and-deny",
        ),
        pytest.param(
            "[{ from: lab, to: dmz }]", "invalid-deny-rule", id="neither-allow-nor-deny"
        ),
        pytest.param(
            "[{ from: lab, to: dmz, allow: [icmp/8] }]",
            "invalid-icmp-rule",
            id="icmp-with-port",
        ),
    ],
)
def test_acl_rule_shape_codes(acl: str, code: str, tmp_path: Path) -> None:
    report = report_with(ACL_BASE.format(acl=acl), tmp_path)
    assert code in codes(report)


def test_acl_v2_constructs_validate(tmp_path: Path) -> None:
    acl = (
        "[{ from: lab, to: web, deny: [tcp/22] },"
        " { from: lab, to: dmz, allow: [tcp/22, icmp] },"
        " { from: 0.0.0.0/0, to: 10.0.1.10/32, allow: [tcp/443] }]"
    )
    report = report_with(ACL_BASE.format(acl=acl), tmp_path)
    assert report.valid, [issue.message for issue in report.issues]


def test_invalid_allow_entry_path_is_rerooted(tmp_path: Path) -> None:
    report = report_with(
        """
        networks:
          - { name: lab, cidr: 10.0.0.0/24, mode: isolated }
          - { name: dmz, cidr: 10.0.1.0/24, mode: isolated }
        routers:
          - name: r
            interfaces: [{ network: lab }, { network: dmz }]
            acl: [{ from: lab, to: dmz, allow: ["25", tcp/80, udp/0] }]
        """,
        tmp_path,
    )
    assert codes(report) == ["invalid-allow-entry", "invalid-allow-entry"]
    assert report.issues[0].path == ("routers", 0, "acl", 0, "allow", 0)
    assert report.issues[1].path == ("routers", 0, "acl", 0, "allow", 2)
    assert not report.semantic_checked  # nested-validator errors suppress the root pass


def test_unknown_key_did_you_mean(tmp_path: Path) -> None:
    report = report_for(MINIMAL.replace("image:", "imagee:"), tmp_path)
    issue = next(i for i in report.issues if i.code == "unknown-key")
    assert issue.hint == "did you mean 'image'?"
    assert issue.path_str == "hosts[0].imagee"


@pytest.mark.parametrize(
    ("overrides", "path_str", "hint_part"),
    [
        pytest.param("goals: []", "goals", "challenges.yaml", id="top-goals"),
        pytest.param(
            "attack_path: []", "attack_path", "deferred.yaml", id="top-attack-path"
        ),
        pytest.param(
            """
            hosts:
              - name: web
                os: { type: linux }
                image: img
                interfaces: [{ network: lab }]
                services: []
            """,
            "hosts[0].services",
            "deferred.yaml",
            id="host-services",
        ),
        pytest.param(
            """
            networks:
              - { name: lab, cidr: 10.0.0.0/24, mode: isolated, acl: [] }
            """,
            "networks[0].acl",
            "routers",
            id="network-acl",
        ),
    ],
)
def test_deferred_sections(
    overrides: str, path_str: str, hint_part: str, tmp_path: Path
) -> None:
    report = report_with(overrides, tmp_path)
    issue = next(i for i in report.issues if i.code == "deferred-section")
    assert issue.path_str == path_str
    assert issue.hint is not None and hint_part in issue.hint


def test_structural_errors_suppress_semantic_stage(tmp_path: Path) -> None:
    text = MINIMAL.replace("10.0.0.0/24", "10.0.0.0/33").replace(
        "network: lab, ip: 10.0.0.10", "network: wan, ip: 10.0.0.10"
    )
    report = report_for(text, tmp_path)
    assert codes(report) == ["invalid-cidr"]
    assert not report.semantic_checked
    assert "cross-reference checks" in report.render()


# --- semantic stage ------------------------------------------------------------


@pytest.mark.parametrize(
    ("overrides", "code", "path_str"),
    [
        pytest.param(
            """
            hosts:
              - name: web
                os: { type: linux }
                image: img
                interfaces: [{ network: wan }]
            """,
            "undeclared-network",
            "hosts[0].interfaces[0].network",
            id="undeclared-network",
        ),
        pytest.param(
            """
            hosts:
              - name: web
                os: { type: linux }
                image: img
                interfaces: [{ network: lab, ip: 10.0.0.10 }, { network: lab }]
            """,
            "duplicate-attachment",
            "hosts[0].interfaces[1].network",
            id="duplicate-attachment",
        ),
        pytest.param(
            """
            hosts:
              - name: web
                os: { type: linux }
                image: img
                interfaces: [{ network: lab, ip: 10.9.9.9 }]
            """,
            "ip-outside-subnet",
            "hosts[0].interfaces[0].ip",
            id="ip-outside-subnet",
        ),
        pytest.param(
            """
            hosts:
              - name: web
                os: { type: linux }
                image: img
                interfaces: [{ network: lab, ip: 10.0.0.255 }]
            """,
            "reserved-ip",
            "hosts[0].interfaces[0].ip",
            id="reserved-ip",
        ),
        pytest.param(
            """
            hosts:
              - name: web
                os: { type: linux }
                image: img
                interfaces: [{ network: lab, ip: 10.0.0.10 }]
              - name: db
                os: { type: linux }
                image: img
                interfaces: [{ network: lab, ip: 10.0.0.10 }]
            """,
            "duplicate-ip",
            "hosts[1].interfaces[0].ip",
            id="duplicate-ip",
        ),
        pytest.param(
            """
            networks:
              - { name: lab, cidr: 10.0.0.0/24, mode: isolated }
              - { name: lab, cidr: 10.0.1.0/24, mode: isolated }
            """,
            "duplicate-network-name",
            "networks[1].name",
            id="duplicate-network-name",
        ),
        pytest.param(
            """
            hosts:
              - name: attacker
                os: { type: linux }
                image: img
                interfaces: [{ network: lab }]
            """,
            "duplicate-guest-name",
            "attacker.name",
            id="duplicate-guest-name",
        ),
        pytest.param(
            """
            networks:
              - { name: lab, cidr: 10.0.0.0/24, mode: isolated }
              - { name: dmz, cidr: 10.0.1.0/24, mode: isolated }
            routers:
              - name: r
                interfaces: [{ network: lab }, { network: dmz }]
                acl: [{ from: lab, to: wan, allow: [] }]
            """,
            "acl-endpoint-unknown",
            "routers[0].acl[0].to",
            id="acl-endpoint-unknown",
        ),
        pytest.param(
            """
            networks:
              - { name: lab, cidr: 10.0.0.0/24, mode: isolated }
              - { name: dmz, cidr: 10.0.1.0/24, mode: isolated }
            routers:
              - name: r
                interfaces: [{ network: lab }, { network: dmz }]
                acl: [{ from: lab, to: 10.0.1.5/24, allow: [tcp/80] }]
            """,
            "acl-endpoint-unknown",
            "routers[0].acl[0].to",
            id="acl-endpoint-bad-cidr",
        ),
        pytest.param(
            """
            networks:
              - { name: lab, cidr: 10.0.0.0/24, mode: isolated }
              - { name: dmz, cidr: 10.0.1.0/24, mode: isolated }
              - { name: far, cidr: 10.0.2.0/24, mode: isolated }
            hosts:
              - name: web
                os: { type: linux }
                image: img
                interfaces: [{ network: far }]
            routers:
              - name: r
                interfaces: [{ network: lab }, { network: dmz }]
                acl: [{ from: lab, to: web, allow: [tcp/80] }]
            """,
            "acl-unattached-network",
            "routers[0].acl[0].to",
            id="acl-unattached-guest",
        ),
        pytest.param(
            """
            networks:
              - { name: lab, cidr: 10.0.0.0/24, mode: isolated }
              - { name: dmz, cidr: 10.0.1.0/24, mode: isolated }
            routers:
              - name: r
                interfaces: [{ network: lab }, { network: dmz }]
                acl: [{ from: lab, to: "fd00::/8", allow: [tcp/80] }]
            """,
            "ipv6-not-realized",
            "routers[0].acl[0].to",
            id="acl-ipv6-cidr-endpoint-gated",
        ),
        pytest.param(
            """
            networks:
              - { name: lab, cidr: 10.0.0.0/24, mode: isolated }
              - { name: dmz, cidr: 10.0.1.0/24, mode: isolated }
              - { name: ext, cidr: 10.0.2.0/24, mode: isolated }
            routers:
              - name: r
                interfaces: [{ network: lab }, { network: dmz }]
                acl: [{ from: lab, to: ext, allow: [] }]
            """,
            "acl-unattached-network",
            "routers[0].acl[0].to",
            id="acl-unattached-network",
        ),
        pytest.param(
            """
            networks:
              - { name: lab, cidr: 10.0.0.0/24, mode: isolated }
              - { name: dmz, cidr: 10.0.1.0/24, mode: isolated }
            routers:
              - name: r
                interfaces: [{ network: lab }, { network: dmz }]
                acl: [{ from: lab, to: lab, allow: [] }]
            """,
            "acl-same-segment",
            "routers[0].acl[0]",
            id="acl-same-segment",
        ),
        pytest.param(
            """
            networks:
              - name: lab
                cidr: 10.0.0.0/24
                mode: isolated
                dns: { authoritative: [ghost] }
            """,
            "dns-undeclared-guest",
            "networks[0].dns.authoritative[0]",
            id="dns-undeclared-guest",
        ),
        pytest.param(
            """
            networks:
              - { name: lab, cidr: 10.0.0.0/24, mode: isolated }
              - name: dmz
                cidr: 10.0.1.0/24
                mode: isolated
                dns: { authoritative: [web] }
            """,
            "dns-unattached-guest",
            "networks[1].dns.authoritative[0]",
            id="dns-unattached-guest",
        ),
        pytest.param(
            "attacker: { host: nosuch, entry: assumed-breach }",
            "undeclared-attacker-host",
            "attacker.host",
            id="undeclared-attacker-host",
        ),
        pytest.param(
            "networks: [{ name: lab, cidr: 'fd00::/8', mode: isolated }]",
            "ipv6-not-realized",
            "networks[0].cidr",
            id="ipv6-gate-cidr",
        ),
        pytest.param(
            """
            hosts:
              - name: web
                os: { type: linux }
                image: img
                interfaces: [{ network: lab, ip: 'fd00::1' }]
            """,
            "ipv6-not-realized",
            "hosts[0].interfaces[0].ip",
            id="ipv6-gate-interface-ip",
        ),
        pytest.param(
            """
            networks:
              - name: lab
                cidr: 10.0.0.0/24
                mode: isolated
                dns: { nameservers: ['2606:4700:4700::1111'] }
            """,
            "ipv6-not-realized",
            "networks[0].dns.nameservers[0]",
            id="ipv6-gate-nameserver",
        ),
        pytest.param(
            """
            hosts:
              - name: lab
                os: { type: linux }
                image: img
                interfaces: [{ network: lab }]
            """,
            "name-collision",
            "hosts[0].name",
            id="guest-network-name-collision",
        ),
        pytest.param(
            """
            attacker:
              host: web
              interfaces: [{ network: lab }]
              entry: assumed-breach
            """,
            "attacker-foothold-conflict",
            "attacker",
            id="attacker-foothold-conflict",
        ),
        pytest.param(
            "attacker: { entry: external }",
            "attacker-no-foothold",
            "attacker",
            id="attacker-no-foothold",
        ),
    ],
)
def test_semantic_codes(
    overrides: str, code: str, path_str: str, tmp_path: Path
) -> None:
    report = report_with(overrides, tmp_path)
    assert not report.valid
    issue = next(i for i in report.issues if i.code == code)
    assert issue.path_str == path_str
    # attacker foothold checks live on the nested Attacker validator, which suppresses the root pass
    nested = code in ("attacker-foothold-conflict", "attacker-no-foothold")
    assert report.semantic_checked == (not nested)


def test_semantic_report_is_complete(tmp_path: Path) -> None:
    report = report_with(
        """
        networks:
          - { name: lab, cidr: 10.0.0.0/24, mode: isolated }
          - { name: dmz, cidr: 10.0.1.0/24, mode: isolated }
        routers:
          - name: r
            interfaces: [{ network: lab }, { network: dmz }]
            acl: [{ from: lab, to: lab, allow: [] }]
        hosts:
          - name: web
            os: { type: linux }
            image: img
            interfaces: [{ network: wan }]
          - name: db
            os: { type: linux }
            image: img
            interfaces: [{ network: lab, ip: 10.0.0.255 }]
          - name: db2
            os: { type: linux }
            image: img
            interfaces: [{ network: lab, ip: 10.9.9.9 }]
        attacker: { host: nosuch, entry: assumed-breach }
        """,
        tmp_path,
    )
    assert sorted(codes(report)) == [
        "acl-same-segment",
        "ip-outside-subnet",
        "reserved-ip",
        "undeclared-attacker-host",
        "undeclared-network",
    ]


def test_undeclared_network_did_you_mean(tmp_path: Path) -> None:
    report = report_for(
        MINIMAL.replace("network: lab, ip", "network: lob, ip"), tmp_path
    )
    issue = next(i for i in report.issues if i.code == "undeclared-network")
    assert issue.hint == "did you mean 'lab'?"


# --- positions and rendering ---------------------------------------------------


def test_positions_resolve_to_source_lines(tmp_path: Path) -> None:
    text = MINIMAL.replace("10.0.0.0/24", "10.0.0.0/33")
    report = report_for(text, tmp_path)
    issue = report.issues[0]
    lines = text.splitlines()
    assert issue.line is not None and issue.col is not None
    assert "10.0.0.0/33" in lines[issue.line - 1]
    assert lines[issue.line - 1][issue.col - 1 :].startswith("10.0.0.0/33")


def test_missing_field_falls_back_to_parent_position(tmp_path: Path) -> None:
    text = MINIMAL.replace("    image: img\n", "")
    report = report_for(text, tmp_path)
    issue = next(i for i in report.issues if i.code == "missing-field")
    assert issue.line is not None  # the host mapping's position, not nothing


def test_yaml_syntax_error_has_position(tmp_path: Path) -> None:
    report = report_for("range:\n  name: [unclosed\n", tmp_path)
    assert codes(report) == ["yaml-syntax"]
    assert report.issues[0].line is not None


def test_render_lists_every_error_once(tmp_path: Path) -> None:
    report = report_with("attacker: { host: nosuch, entry: assumed-breach }", tmp_path)
    rendered = report.render()
    assert rendered.startswith("✗")
    assert "1 error" in rendered
    assert "undeclared host 'nosuch'" in rendered


def test_valid_file_reports_valid_with_spec(tmp_path: Path) -> None:
    report = report_for(MINIMAL, tmp_path)
    assert report.valid
    assert report.spec is not None and report.spec.meta.name == "minimal"
    assert report.render() == f"✓ {report.file}"
    assert report.to_json()["issues"] == []


def test_format_path() -> None:
    assert format_path(()) == "(root)"
    assert format_path(("networks", 0, "cidr")) == "networks[0].cidr"
    assert format_path(("attacker",)) == "attacker"


def test_to_json_contract(tmp_path: Path) -> None:
    report = report_for(MINIMAL.replace("image:", "imagee:"), tmp_path)
    data = report.to_json()
    assert data["valid"] is False
    issue = next(i for i in data["issues"] if i["code"] == "unknown-key")
    assert set(issue) == {
        "code",
        "severity",
        "path",
        "loc",
        "line",
        "col",
        "message",
        "hint",
    }
    assert issue["loc"] == ["hosts", 0, "imagee"]

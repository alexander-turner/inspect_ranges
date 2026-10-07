from pathlib import Path
from typing import Any

import pytest
import yaml
from inspect_ranges.schema import RangeSpec, load_range, range_json_schema
from pydantic import ValidationError

EXAMPLES = sorted(
    (Path(__file__).parent.parent / "design/inspect-ranges/ranges").glob("*/range.yaml")
)

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


def _with(overrides_yaml: str) -> Any:
    data = yaml.safe_load(MINIMAL)
    data.update(yaml.safe_load(overrides_yaml))
    return data


def test_examples_validate() -> None:
    assert len(EXAMPLES) == 6
    for path in EXAMPLES:
        spec = load_range(path)
        assert spec.meta.schema_version in {"0.1", "0.2", "0.3"}


def test_minimal_spec_validates() -> None:
    spec = RangeSpec.model_validate(yaml.safe_load(MINIMAL))
    assert spec.attacker.name == "attacker"
    assert spec.attacker.egress == "none"


def test_invalid_spec_raises_with_every_finding() -> None:
    """Valid-by-construction: direct `model_validate` rejects semantic errors, and the raised error carries all of them (per-code coverage lives in `test_diagnostics.py`)."""
    data = _with(
        """
        hosts:
          - name: web
            os: { type: linux }
            image: img
            interfaces: [{ network: wan }]
          - name: db
            os: { type: linux }
            image: img
            interfaces: [{ network: lab, ip: 10.0.0.255 }]
        """
    )
    with pytest.raises(ValidationError) as excinfo:
        RangeSpec.model_validate(data)
    message = str(excinfo.value)
    assert "undeclared network 'wan'" in message
    assert "network or broadcast address" in message


@pytest.mark.parametrize("entry", ["tcp/5432", "udp/53", "tcp/1-65535"])
def test_valid_allow_entries(entry: str) -> None:
    data = _with(
        f"""
        networks:
          - {{ name: lab, cidr: 10.0.0.0/24, mode: isolated }}
          - {{ name: dmz, cidr: 10.0.1.0/24, mode: isolated }}
        routers:
          - name: r
            interfaces: [{{ network: lab }}, {{ network: dmz }}]
            acl: [{{ from: lab, to: dmz, allow: [{entry}] }}]
        """
    )
    RangeSpec.model_validate(data)


def test_dns_config_validates() -> None:
    data = _with(
        """
        networks:
          - name: lab
            cidr: 10.0.0.0/24
            mode: isolated
            dns:
              records: [{ name: files.corp.local, ip: 10.0.0.50 }]
              authoritative: [web]
              forwarder: 1.1.1.1
        """
    )
    spec = RangeSpec.model_validate(data)
    assert spec.networks[0].dns is not None
    assert spec.networks[0].dns.authoritative == ["web"]


def test_json_schema_exports_aliases() -> None:
    schema = range_json_schema()
    assert "range" in schema["properties"]
    acl_rule = schema["$defs"]["AclRule"]
    assert "from" in acl_rule["properties"]

"""The attack-box conformance battery: refusals, report semantics, and the CLI verb.

The battery's live obligations run real render/up/docker and are the devbox acceptance gate (`INSPECT_RANGES_ATTACK_BOX=tests.fake_attackbox.factory inspect-ranges attackbox verify --spec <canonical range>`); CI holds the refusal surface, the report contract, and the CLI rendering.
"""

import json
from pathlib import Path

import pytest
from click.testing import CliRunner
from inspect_ranges._attackbox.conformance import (
    BatteryError,
    BatteryReport,
    BatteryRow,
    run_attack_box_battery,
)
from inspect_ranges._cli.attackboxcmd import attackbox

FOOTHOLD_SPEC = """\
meta:
  name: battery-foothold
  description: battery refusal fixture.
networks:
  - { name: lab, cidr: 10.10.10.0/24, mode: isolated }
hosts:
  - name: web
    os: { type: linux }
    image: img
    interfaces: [{ network: lab }]
attacker: { host: web, entry: external }
"""


def write_spec(tmp_path: Path, text: str = FOOTHOLD_SPEC) -> Path:
    spec = tmp_path / "range.yaml"
    spec.write_text(text)
    return spec


def test_battery_refuses_without_the_variable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("INSPECT_RANGES_ATTACK_BOX", raising=False)
    with pytest.raises(BatteryError, match="INSPECT_RANGES_ATTACK_BOX is not set"):
        run_attack_box_battery(write_spec(tmp_path))


def test_battery_refuses_an_unresolvable_backend(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("INSPECT_RANGES_ATTACK_BOX", "no_such_pkg_xyz.boxes.cell")
    with pytest.raises(BatteryError, match="does not import"):
        run_attack_box_battery(write_spec(tmp_path))


def test_battery_refuses_a_foothold_spec(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A foothold range has no dedicated attack box; the battery names the scope rather than running vacuously."""
    monkeypatch.setenv("INSPECT_RANGES_ATTACK_BOX", "tests.fake_attackbox.factory")
    with pytest.raises(BatteryError, match="dedicated attack box"):
        run_attack_box_battery(write_spec(tmp_path), state_dir=tmp_path / "state")


def test_report_passes_only_when_every_row_does() -> None:
    ok = BatteryRow("realize", True)
    bad = BatteryRow("teardown", False, "record survived")
    assert BatteryReport(rows=[ok]).passed
    assert not BatteryReport(rows=[ok, bad]).passed
    payload = BatteryReport(rows=[ok, bad], project="ir-x").to_json()
    assert payload["passed"] is False and payload["project"] == "ir-x"
    assert [row["name"] for row in payload["rows"]] == ["realize", "teardown"]


def test_cli_verify_renders_rows_and_fails_loudly(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import inspect_ranges._cli.attackboxcmd as command_module

    report = BatteryReport(
        rows=[
            BatteryRow("realize", True, "project ir-x"),
            BatteryRow("exec-parity", False, "test_exec_timeout: hung"),
        ],
        project="ir-x",
    )

    def fake_battery(*args: object, **kwargs: object) -> BatteryReport:
        return report

    monkeypatch.setattr(command_module, "run_attack_box_battery", fake_battery)
    spec = write_spec(tmp_path)
    result = CliRunner().invoke(attackbox, ["verify", "--spec", str(spec)])
    assert result.exit_code == 1
    assert "[FAIL] exec-parity" in result.output
    assert "a provider boots when it passes: FAIL" in result.output


def test_cli_verify_json_and_pass_exit_zero(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import inspect_ranges._cli.attackboxcmd as command_module

    report = BatteryReport(rows=[BatteryRow("realize", True)], project="ir-x")

    def fake_battery(*args: object, **kwargs: object) -> BatteryReport:
        return report

    monkeypatch.setattr(command_module, "run_attack_box_battery", fake_battery)
    spec = write_spec(tmp_path)
    result = CliRunner().invoke(attackbox, ["verify", "--spec", str(spec), "--json"])
    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload["passed"] is True


def test_cli_verify_turns_refusals_into_clean_errors(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("INSPECT_RANGES_ATTACK_BOX", raising=False)
    spec = write_spec(tmp_path)
    result = CliRunner().invoke(attackbox, ["verify", "--spec", str(spec)])
    assert result.exit_code != 0
    assert "INSPECT_RANGES_ATTACK_BOX is not set" in result.output

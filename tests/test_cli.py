import json
from pathlib import Path

from click.testing import CliRunner
from inspect_ranges import __version__
from inspect_ranges._cli.main import ranges

EXAMPLE = str(
    Path(__file__).parent.parent
    / "design/inspect-ranges/ranges/vulhub-zabbix/range.yaml"
)


def test_version() -> None:
    result = CliRunner().invoke(ranges, ["--version"])
    assert result.exit_code == 0
    assert __version__ in result.output


def test_validate_accepts_example_and_rejects_bad_file(tmp_path: Path) -> None:
    bad = tmp_path / "bad.yaml"
    bad.write_text("range: {}\nunknown_section: 1\n")
    ok = CliRunner().invoke(ranges, ["validate", EXAMPLE])
    assert ok.exit_code == 0
    assert "vulhub-zabbix" in ok.output
    failed = CliRunner().invoke(ranges, ["validate", EXAMPLE, str(bad)])
    assert failed.exit_code == 1
    assert "unknown_section" in failed.output


def test_validate_json_contract(tmp_path: Path) -> None:
    bad = tmp_path / "bad.yaml"
    bad.write_text("range: {}\nunknown_section: 1\n")
    result = CliRunner().invoke(ranges, ["validate", "--json", EXAMPLE, str(bad)])
    assert result.exit_code == 1
    reports = json.loads(result.output)
    assert [report["valid"] for report in reports] == [True, False]
    issue = next(
        issue for issue in reports[1]["issues"] if issue["code"] == "unknown-key"
    )
    assert issue["path"] == "unknown_section"
    assert issue["line"] == 2


def test_devbox_command_registered() -> None:
    result = CliRunner().invoke(ranges, ["devbox", "--help"])
    assert result.exit_code == 0
    assert "development box" in result.output


def test_schema_outputs_json() -> None:
    result = CliRunner().invoke(ranges, ["schema"])
    assert result.exit_code == 0
    assert json.loads(result.output)["properties"]["range"]


def test_doctor_fix_script_outputs_shell_script() -> None:
    # runs the real checks; the script shape holds whatever this machine's state
    result = CliRunner().invoke(ranges, ["doctor", "--fix-script"])
    assert result.exit_code == 0
    assert result.output.startswith("#!/bin/sh")


def test_doctor_fix_script_and_json_are_mutually_exclusive() -> None:
    result = CliRunner().invoke(ranges, ["doctor", "--json", "--fix-script"])
    assert result.exit_code != 0
    assert "mutually exclusive" in result.output


def test_doctor_json_exit_code_reflects_result() -> None:
    # runs the real checks, so assert only the output contract, not this machine's state
    result = CliRunner().invoke(ranges, ["doctor", "--json"])
    report = json.loads(result.output)
    assert result.exit_code == (0 if report["passed"] else 1)
    assert report["checks"]
    assert {check["status"] for check in report["checks"]} <= {
        "ok",
        "warn",
        "fail",
        "skip",
    }

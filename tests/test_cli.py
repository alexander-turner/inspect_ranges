import json
from pathlib import Path

import pytest
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


def test_validate_unreadable_path_is_a_clean_error(tmp_path: Path) -> None:
    """A directory or binary argument renders a positioned issue and the run keeps going per-file, no traceback."""
    binary = tmp_path / "binary.yaml"
    binary.write_bytes(b"\xd8\x00\x00\x00")
    result = CliRunner().invoke(
        ranges, ["validate", str(tmp_path), str(binary), EXAMPLE]
    )
    assert result.exit_code == 1
    assert result.exception is None or isinstance(result.exception, SystemExit)
    assert result.output.count("cannot read file") == 2
    assert "vulhub-zabbix" in result.output  # later files still report


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


def test_plan_json_contract(tmp_path: Path) -> None:
    # a spec without guest content: migrated examples gate at planning by design
    spec = str(Path(__file__).parent.parent / "design/spikes/acl-v2/spec.yaml")
    result = CliRunner().invoke(ranges, ["plan", spec, "--json"])
    assert result.exit_code == 0
    plan = json.loads(result.output)
    assert plan["format_version"] == "1"
    assert plan["range"]["name"] == "acl-v2"
    assert plan["totals"]["guests"] == len(plan["guests"])


def test_plan_gates_migrated_guest_content() -> None:
    result = CliRunner().invoke(ranges, ["plan", EXAMPLE])
    assert result.exit_code == 1
    assert (
        "guest-config-not-realized" in result.output
        or "not yet realized" in result.output
    )


def test_render_writes_verifiable_bundle(tmp_path: Path) -> None:
    cache = tmp_path / "cache"
    cache.mkdir()
    spec = Path(__file__).parent.parent / "design/spikes/acl-v2/spec.yaml"
    (cache / "noble-range-guest.qcow2").write_bytes(b"fake")
    out = tmp_path / "bundle"
    result = CliRunner().invoke(
        ranges,
        ["render", str(spec), "-o", str(out), "--image-cache", str(cache)],
    )
    assert result.exit_code == 0, result.output
    assert "bundle sha256:" in result.output
    manifest = json.loads((out / "manifest.json").read_text())
    assert "plan.json" in manifest["files"]


def test_plan_refuses_windows_examples() -> None:
    goad = str(
        Path(__file__).parent.parent
        / "design/inspect-ranges/ranges/goad-light/range.yaml"
    )
    result = CliRunner().invoke(ranges, ["plan", goad])
    assert result.exit_code == 1
    assert (
        "windows-render-not-supported" in result.output
        or "Windows guest" in result.output
    )


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


def test_image_cache_knob_reaches_the_cli(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """`INSPECT_RANGES_IMAGE_CACHE` is the one cache default for every surface: the CLI must resolve through it, or the docs' claim ("images derive writes here") sends goldens to the wrong cache and doctor's printed fix reproduces the miss."""
    knob_cache = tmp_path / "knob-cache"
    knob_cache.mkdir()
    monkeypatch.setenv("INSPECT_RANGES_IMAGE_CACHE", str(knob_cache))
    result = CliRunner().invoke(ranges, ["images", "list"])
    assert result.exit_code == 0
    assert str(knob_cache) in result.output

    explicit = tmp_path / "explicit"
    explicit.mkdir()
    overridden = CliRunner().invoke(
        ranges, ["images", "list", "--image-cache", str(explicit)]
    )
    assert overridden.exit_code == 0
    assert str(explicit) in overridden.output


def test_applier_startup_refusal_is_a_clean_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An unhealthy host's documented refusal surfaces as a one-line error with a nonzero exit, not a traceback (every other command converts expected failures the same way)."""
    from inspect_ranges._cli import appliercmd
    from inspect_ranges._host.local import HostNotReadyError

    class RefusingApplier:
        def __init__(self, *args: object, **kwargs: object) -> None:
            pass

        async def start(self) -> None:
            raise HostNotReadyError("host not ready: docker daemon (fail)")

        async def aclose(self) -> None:
            pass

    monkeypatch.setattr(appliercmd, "Applier", RefusingApplier)
    result = CliRunner().invoke(
        ranges, ["applier", "--socket", str(tmp_path / "applier.sock")]
    )
    assert result.exit_code == 1
    assert "host not ready" in result.output
    assert "Traceback" not in result.output

import json
import os
import subprocess
from pathlib import Path

import pytest
from inspect_ranges._doctor import (
    CheckResult,
    CheckStatus,
    passed,
    render_fix_script,
    render_text,
)
from inspect_ranges._doctor.checks import (
    check_br_netfilter,
    check_docker,
    check_image_tools,
    check_ipv6,
    check_kernel_readable,
    check_virtualization,
    parse_version,
)


def _completed(
    returncode: int = 0, stdout: str = "", stderr: str = ""
) -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(["docker"], returncode, stdout, stderr)


def _info(
    server_version: str = "29.8.1", cgroup_version: str = "2"
) -> subprocess.CompletedProcess[str]:
    return _completed(
        stdout=json.dumps(
            {"ServerVersion": server_version, "CgroupVersion": cgroup_version}
        )
    )


def _compose(version: str = "v5.5.1") -> subprocess.CompletedProcess[str]:
    return _completed(stdout=json.dumps({"version": version}))


# real output shape when the daemon can't be reached: exit 1, empty ServerVersion, reason on stderr
_UNREACHABLE = '{"ID":"","ServerVersion":"","CgroupVersion":""}'


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("29.8.1", (29, 8, 1)),
        ("v5.5.1", (5, 5, 1)),
        ("2.29.1-desktop.1", (2, 29, 1)),
        ("24.0", (24, 0)),
        ("dev", None),
    ],
)
def test_parse_version(text: str, expected: tuple[int, ...] | None) -> None:
    assert parse_version(text) == expected


@pytest.mark.parametrize(
    ("info", "compose", "expected", "fix_mentions"),
    [
        pytest.param(_info(), _compose(), ["ok", "ok", "ok", "ok"], None, id="healthy"),
        pytest.param(
            None,
            None,
            ["fail", "skip", "skip", "skip"],
            "install",
            id="docker-not-installed",
        ),
        pytest.param(
            _completed(
                1,
                _UNREACHABLE,
                "permission denied while trying to connect to the docker API",
            ),
            _compose(),
            ["fail", "skip", "skip", "skip"],
            "usermod -aG docker",
            id="permission-denied",
        ),
        pytest.param(
            _completed(
                1, _UNREACHABLE, "failed to connect to the docker API at unix:///x.sock"
            ),
            _compose(),
            ["fail", "skip", "skip", "skip"],
            "DOCKER_HOST",
            id="daemon-unreachable",
        ),
        pytest.param(
            _info(server_version="20.10.24"),
            _compose(),
            ["ok", "fail", "ok", "ok"],
            "Upgrade",
            id="old-engine",
        ),
        pytest.param(
            _info(),
            _completed(1, "", "docker: unknown command: docker compose"),
            ["ok", "ok", "fail", "ok"],
            "docker-compose-plugin",
            id="compose-missing",
        ),
        pytest.param(
            _info(),
            _compose("v2.21.0"),
            ["ok", "ok", "fail", "ok"],
            "--only-upgrade",
            id="old-compose",
        ),
        pytest.param(
            _info(cgroup_version="1"),
            _compose(),
            ["ok", "ok", "ok", "warn"],
            "cgroup",
            id="cgroup-v1",
        ),
    ],
)
def test_check_docker(
    info: subprocess.CompletedProcess[str] | None,
    compose: subprocess.CompletedProcess[str] | None,
    expected: list[CheckStatus],
    fix_mentions: str | None,
) -> None:
    results = check_docker(info, compose)
    assert [result.status for result in results] == expected
    if fix_mentions is not None:
        fixes = " ".join(result.fix or "" for result in results)
        assert fix_mentions in fixes


@pytest.mark.parametrize(
    ("device", "expected"),
    [
        ("net/tun", "fail"),
        ("vhost-net", "warn"),
        ("vhost-vsock", "fail"),
    ],
)
def test_check_virtualization_missing_device(
    tmp_path: Path, device: str, expected: CheckStatus
) -> None:
    for name in ("kvm", "net/tun", "vhost-net", "vhost-vsock"):
        if name != device:
            path = tmp_path / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.touch()
    statuses = {result.name: result.status for result in check_virtualization(tmp_path)}
    assert statuses[(tmp_path / device).as_posix()] == expected
    present = tmp_path / "vhost-net" if device != "vhost-net" else tmp_path / "kvm"
    assert statuses[present.as_posix()] == "ok"


@pytest.mark.parametrize(
    ("value", "expected"),
    [(None, "ok"), ("0", "ok"), ("1", "warn")],
)
def test_check_br_netfilter(
    tmp_path: Path, value: str | None, expected: CheckStatus
) -> None:
    if value is not None:
        setting = tmp_path / "net" / "bridge" / "bridge-nf-call-iptables"
        setting.parent.mkdir(parents=True)
        setting.write_text(f"{value}\n")
    assert check_br_netfilter(tmp_path).status == expected


@pytest.mark.parametrize(
    ("value", "expected"),
    [(None, "warn"), ("0", "ok"), ("1", "warn")],
)
def test_check_ipv6(tmp_path: Path, value: str | None, expected: CheckStatus) -> None:
    if value is not None:
        setting = tmp_path / "net" / "ipv6" / "conf" / "all" / "disable_ipv6"
        setting.parent.mkdir(parents=True)
        setting.write_text(f"{value}\n")
    assert check_ipv6(tmp_path).status == expected


@pytest.mark.parametrize(
    ("modes", "expected"),
    [([], "warn"), ([0o644], "ok"), ([0o644, 0o600], "ok"), ([0o644, 0o000], "fail")],
)
def test_check_kernel_readable(
    tmp_path: Path, modes: list[int], expected: CheckStatus
) -> None:
    if expected == "fail" and os.geteuid() == 0:
        pytest.skip("root can read files regardless of mode")
    for index, mode in enumerate(modes):
        kernel = tmp_path / f"vmlinuz-6.{index}.0-generic"
        kernel.write_bytes(b"kernel")
        kernel.chmod(mode)
    assert check_kernel_readable(tmp_path).status == expected


def test_check_image_tools_reports_missing_tool_with_package() -> None:
    def which(tool: str) -> str | None:
        return "/usr/bin/qemu-img" if tool == "qemu-img" else None

    results = {result.name: result for result in check_image_tools(which)}
    assert results["qemu-img"].status == "ok"
    assert results["virt-customize"].status == "fail"
    assert results["virt-customize"].fix == "sudo apt-get install libguestfs-tools"


@pytest.mark.parametrize(
    ("statuses", "expected"),
    [(["ok", "warn", "skip"], True), (["ok", "fail"], False), ([], True)],
)
def test_passed_ignores_warnings_and_skips(
    statuses: list[CheckStatus], expected: bool
) -> None:
    results = [
        CheckResult("Group", f"check {index}", status, "detail")
        for index, status in enumerate(statuses)
    ]
    assert passed(results) is expected


def test_render_text_shows_fixes_only_for_problems() -> None:
    results = [
        CheckResult("Group", "fine", "ok", "all good", fix="unused fix"),
        CheckResult("Group", "broken", "fail", "is broken", fix="run the fix"),
    ]
    text = render_text(results)
    assert "fix: run the fix" in text
    assert "unused fix" not in text
    assert text.endswith("1 ok, 0 warning(s), 1 failed, 0 skipped")


def test_render_text_hints_fix_script_when_fixes_are_runnable() -> None:
    results = [
        CheckResult(
            "G", "broken", "fail", "x", fix="f", fix_command="apt-get install -y x"
        )
    ]
    assert "doctor --fix-script" in render_text(results)
    assert "doctor --fix-script" not in render_text(
        [CheckResult("G", "broken", "fail", "x", fix="advice only")]
    )


def test_render_fix_script_includes_only_runnable_fixes_for_problems() -> None:
    results = [
        CheckResult(
            "G", "fine", "ok", "x", fix="f", fix_command="echo should-not-appear"
        ),
        CheckResult(
            "G",
            "pkg",
            "fail",
            "x",
            fix="f",
            fix_command="apt-get install -y qemu-utils",
        ),
        CheckResult(
            "G",
            "group",
            "warn",
            "x",
            fix="f",
            fix_command='usermod -aG kvm "$SUDO_USER"',
        ),
        CheckResult("G", "platform", "fail", "x", fix="use another machine"),
    ]
    script = render_fix_script(results)
    assert script.startswith("#!/bin/sh")
    assert "set -eu" in script
    assert '[ "$(id -u)" -eq 0 ]' in script  # refuses to run unprivileged
    assert "${SUDO_USER:?" in script  # usermod fix needs the invoking user
    assert script.index("apt-get update") < script.index(
        "apt-get install -y qemu-utils"
    )
    assert 'usermod -aG kvm "$SUDO_USER"' in script
    assert "should-not-appear" not in script
    assert "#   G / platform: use another machine" in script  # advice stays a comment


def test_render_fix_script_with_nothing_to_fix() -> None:
    script = render_fix_script([CheckResult("G", "fine", "ok", "x")])
    assert "no runnable fixes needed" in script
    assert "id -u" not in script

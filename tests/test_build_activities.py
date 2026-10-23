"""Scheduled-activity realization through its public surface (scheduled-activity-v1): script resolution and digesting, the in-guest commands emitted for Linux and Windows, and the verification probes. The command builders are pure, so no guest boots here."""

import hashlib
from pathlib import Path

import pytest
from inspect_ranges._build.activities import (
    ExecOp,
    ResolvedActivity,
    WriteOp,
    activity_check_command,
    activity_ops,
    activity_unit_name,
    resolve_activities,
)
from inspect_ranges.types import (
    Attacker,
    Host,
    Interface,
    IssueError,
    Network,
    Os,
    RangeMeta,
    RangeSpec,
    ScheduledActivity,
)


def spec_with(hosts: list[Host]) -> RangeSpec:
    return RangeSpec(
        meta=RangeMeta(name="acts", description="activity fixture"),
        networks=[Network(name="lab", cidr="10.0.0.0/24", mode="isolated")],
        hosts=hosts,
        attacker=Attacker(
            image="tiny-golden",
            interfaces=[Interface(network="lab")],
            entry="external",
        ),
    )


def host_with(
    activities: list[ScheduledActivity], *, name: str = "web", windows: bool = False
) -> Host:
    return Host(
        name=name,
        os=Os(type="windows") if windows else Os(type="linux"),
        image="tiny-golden",
        interfaces=[Interface(network="lab")],
        scheduled_activity=activities,
    )


def write_activity(range_dir: Path, script: str, content: str = "#!/bin/sh\n") -> Path:
    path = range_dir / "activities" / script
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content)
    return path


def resolved_activity(
    tmp_path: Path,
    *,
    script: str = "tick.sh",
    schedule: str = "every 5m",
    user: str | None = None,
    windows: bool = False,
) -> ResolvedActivity:
    range_dir = tmp_path / "range"
    write_activity(range_dir, script)
    spec = spec_with(
        [
            host_with(
                [ScheduledActivity(script=script, schedule=schedule, user=user)],
                name="win" if windows else "web",
                windows=windows,
            )
        ]
    )
    (resolved,) = resolve_activities(spec, range_dir)
    return resolved


def test_resolution_digests_the_script_content(tmp_path: Path) -> None:
    range_dir = tmp_path / "range"
    script = write_activity(range_dir, "tick.sh", "#!/bin/sh\necho tick\n")
    spec = spec_with(
        [host_with([ScheduledActivity(script="tick.sh", schedule="every 5m")])]
    )
    (resolved,) = resolve_activities(spec, range_dir)
    assert resolved.unit == activity_unit_name("tick.sh") == "tick"
    assert resolved.digest == hashlib.sha256(script.read_bytes()).hexdigest()
    # an edited script re-keys: the digest is content identity
    script.write_text("#!/bin/sh\necho tock\n")
    (edited,) = resolve_activities(spec, range_dir)
    assert edited.digest != resolved.digest


def test_resolution_collects_every_refusal(tmp_path: Path) -> None:
    range_dir = tmp_path / "range"
    write_activity(range_dir, "seconds.ps1")
    spec = spec_with(
        [
            host_with(
                [
                    ScheduledActivity(script="absent.sh", schedule="every 5m"),
                    ScheduledActivity(script="unscheduled.sh"),
                ]
            ),
            host_with(
                [ScheduledActivity(script="seconds.ps1", schedule="every 30s")],
                name="win",
                windows=True,
            ),
        ]
    )
    with pytest.raises(IssueError) as excinfo:
        resolve_activities(spec, range_dir)
    assert [(issue.code, issue.path) for issue in excinfo.value.issues] == [
        ("activity-not-resolved", ("hosts", 0, "scheduled_activity", 0, "script")),
        (
            "activity-schedule-required",
            ("hosts", 0, "scheduled_activity", 1, "schedule"),
        ),
        (
            "activity-schedule-unsupported",
            ("hosts", 1, "scheduled_activity", 0, "schedule"),
        ),
    ]


def test_resolution_refuses_colliding_unit_names(tmp_path: Path) -> None:
    """Unit names derive from the script's file stem, so two scripts on one host with the same stem would realize the same unit."""
    range_dir = tmp_path / "range"
    write_activity(range_dir, "tick.sh")
    write_activity(range_dir, "sub/tick.sh")
    spec = spec_with(
        [
            host_with(
                [
                    ScheduledActivity(script="tick.sh", schedule="every 5m"),
                    ScheduledActivity(script="sub/tick.sh", schedule="@boot"),
                ]
            )
        ]
    )
    with pytest.raises(IssueError) as excinfo:
        resolve_activities(spec, range_dir)
    (issue,) = excinfo.value.issues
    assert issue.code == "activity-name-conflict"
    assert issue.path == ("hosts", 0, "scheduled_activity", 1, "script")
    assert "'tick'" in issue.message


def exec_texts(ops: tuple[WriteOp | ExecOp, ...]) -> list[str]:
    return [" ".join(op.cmd) for op in ops if isinstance(op, ExecOp)]


@pytest.mark.parametrize(
    ("schedule", "user", "enabled", "unit_fragments"),
    [
        pytest.param(
            "every 5m",
            None,
            "tick.timer",
            ["OnBootSec=5m", "OnUnitActiveSec=5m", "Type=oneshot"],
            id="interval-timer",
        ),
        pytest.param(
            "every 2h",
            "clerk",
            "tick.timer",
            ["OnBootSec=2h", "OnUnitActiveSec=2h", "User=clerk"],
            id="interval-with-user",
        ),
        pytest.param(
            "@boot",
            None,
            "tick.service",
            ["Type=simple", "WantedBy=multi-user.target"],
            id="boot-service",
        ),
    ],
)
def test_linux_ops_install_and_enable_the_unit(
    tmp_path: Path,
    schedule: str,
    user: str | None,
    enabled: str,
    unit_fragments: list[str],
) -> None:
    activity = resolved_activity(tmp_path, schedule=schedule, user=user)
    ops = activity_ops(activity, b"#!/bin/sh\n")
    script_write = ops[0]
    assert isinstance(script_write, WriteOp) and script_write.mode == 0o600
    assert script_write.data == b"#!/bin/sh\n"
    unit_text = "\n".join(
        op.data.decode() for op in ops if isinstance(op, WriteOp) and op is not ops[0]
    )
    for fragment in [*unit_fragments, "/opt/guestd/activities/tick.sh"]:
        assert fragment in unit_text or any(
            fragment in text for text in exec_texts(ops)
        ), fragment
    install, enable = exec_texts(ops)
    assert "install -D -m 755" in install
    assert "/opt/guestd/activities/tick.sh" in install
    assert "systemctl daemon-reload" in enable
    assert f"systemctl enable {enabled}" in enable
    assert all(op.user == "root" for op in ops if isinstance(op, ExecOp))


@pytest.mark.parametrize(
    ("schedule", "user", "fragments"),
    [
        pytest.param(
            "every 10m",
            None,
            [
                "-RepetitionInterval (New-TimeSpan -Minutes 10)",
                "-UserId 'SYSTEM' -LogonType ServiceAccount",
            ],
            id="interval-system",
        ),
        pytest.param(
            "every 1h",
            "corp\\admin.user",
            [
                "-RepetitionInterval (New-TimeSpan -Hours 1)",
                "-UserId 'corp\\admin.user' -LogonType S4U",
            ],
            id="interval-with-user",
        ),
        pytest.param(
            "@boot",
            None,
            ["New-ScheduledTaskTrigger -AtStartup"],
            id="boot-task",
        ),
    ],
)
def test_windows_ops_register_the_scheduled_task(
    tmp_path: Path, schedule: str, user: str | None, fragments: list[str]
) -> None:
    activity = resolved_activity(
        tmp_path, script="tick.ps1", schedule=schedule, user=user, windows=True
    )
    ops = activity_ops(activity, b"Get-Service\n")
    staging = ops[0]
    assert isinstance(staging, WriteOp)
    assert staging.path.startswith("C:\\Windows\\Temp\\")
    promote, register = exec_texts(ops)
    assert "Move-Item" in promote
    assert "C:\\ProgramData\\guestd\\activities\\tick.ps1" in promote
    assert "Register-ScheduledTask -TaskName 'tick'" in register
    assert '-File "C:\\ProgramData\\guestd\\activities\\tick.ps1"' in register
    for fragment in fragments:
        assert fragment in register, fragment
    # the contract default "root" is not a Windows principal; the daemon's own
    # identity runs the install commands
    assert all(op.user is None for op in ops if isinstance(op, ExecOp))


@pytest.mark.parametrize(
    ("schedule", "windows", "expected", "user"),
    [
        pytest.param(
            "every 5m",
            False,
            ("systemctl", "is-enabled", "--", "tick.timer"),
            "root",
            id="linux-interval-checks-the-timer",
        ),
        pytest.param(
            "@boot",
            False,
            ("systemctl", "is-enabled", "--", "tick.service"),
            "root",
            id="linux-boot-checks-the-service",
        ),
    ],
)
def test_activity_check_commands(
    schedule: str, windows: bool, expected: tuple[str, ...], user: str | None
) -> None:
    activity = ScheduledActivity(script="tick.sh", schedule=schedule)
    cmd, probe_user = activity_check_command(activity, unit="tick", windows=windows)
    assert cmd == expected and probe_user == user


def test_windows_check_queries_the_task_state() -> None:
    activity = ScheduledActivity(script="tick.ps1", schedule="every 10m")
    cmd, user = activity_check_command(activity, unit="tick", windows=True)
    assert cmd[:4] == ("powershell", "-NoProfile", "-NonInteractive", "-Command")
    assert "Get-ScheduledTask -TaskName 'tick'" in cmd[4]
    assert "Disabled" in cmd[4]
    assert user is None

"""Scheduled-activity realization (scheduled-activity-v1): recurring in-guest behavior installed at build.

A `hosts[].scheduled_activity` declaration names a script under the range's `activities/` directory plus a schedule (`@boot`, or `every <N>s|m|h`). The build resolves and content-digests each script at the fail-fast resolution step (the digest enters the guest's build key, so an edited script rebuilds exactly the guests that declare it), then installs each activity as a persistent unit in the guest after recipes and before verification: on Linux a systemd service (plus a timer for interval schedules) enabled under `/etc/systemd/system/`, on Windows a scheduled task registered through `Register-ScheduledTask`. The captured image carries the unit, so every consumer boot runs the activity on its schedule with no per-sample work. Units are enabled, never started, at build: a build-time run would dirty the captured disk at an arbitrary point, and the verification engine checks the enabled unit instead (`verify.py`, kind `activity`).

Unit and task names are the script's file stem (sanitized), derived from the spec alone, so verification needs no record of the realization and the installed unit reads like ordinary admin cruft rather than a harness marker (`_brand.py`); two declarations on one host that would realize the same name refuse at resolution. The activity runs as the declared `user` (`User=` on the Linux service; an S4U principal on the Windows task, no stored credential), root/SYSTEM otherwise.
"""

import asyncio
import re
import shlex
from collections.abc import Mapping
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Literal, Union

from pydantic import BaseModel, ConfigDict

from .._brand import GUEST_OPT_LINUX, GUEST_PROGRAMDATA_WINDOWS
from .._channel.channel import MessageChannel, request_id
from .._channel.protocol import Budget, ExecRequest
from .._channel.vsock import HybridEndpoint, VsockTransport
from .._runtime.images import sha256_file
from ..types import (
    ACTIVITY_SCHEDULE,
    Issue,
    IssueError,
    RangeSpec,
    ScheduledActivity,
)
from .errors import BuildError
from .guesttool import ps_quote
from .recipes import StageSink

ACTIVITIES_DIR_NAME = "activities"
"""Directory inside a range that holds its scheduled-activity scripts."""

LINUX_ACTIVITY_DIR = f"{GUEST_OPT_LINUX}/activities"
"""Where activity scripts land in a Linux guest."""

WINDOWS_ACTIVITY_DIR = f"{GUEST_PROGRAMDATA_WINDOWS}\\activities"
"""Where activity scripts land in a Windows guest."""

ACTIVITY_EXEC_BUDGET_MS = 120_000
"""Per-exec budget for the install commands (file promotion, unit registration; Windows PowerShell cold starts cost seconds)."""

_UNIT_NAME_CHARS = re.compile(r"[^A-Za-z0-9_.-]+")


def activity_unit_name(script: str) -> str:
    """The systemd unit / scheduled task base name for one declaration: the script's file stem with unit-unsafe characters collapsed to `-`, derived from the spec alone (resolution refuses same-host collisions)."""
    return _UNIT_NAME_CHARS.sub("-", PurePosixPath(script).stem)


def schedule_interval(schedule: str) -> tuple[int, Literal["s", "m", "h"]] | None:
    """The `(N, unit)` of an `every <N><unit>` schedule, or `None` for `@boot`.

    Raises:
        ValueError: when the schedule does not match the v0 grammar (validation refuses it first on every spec path).
    """
    match = ACTIVITY_SCHEDULE.match(schedule)
    if match is None:
        raise ValueError(f"schedule {schedule!r} is not in the v0 grammar")
    if match.group(1) is None:
        return None
    unit = match.group(2)
    assert unit in ("s", "m", "h")
    return int(match.group(1)), unit


class ResolvedActivity(BaseModel):
    """One scheduled-activity declaration resolved to its script file, digested and ready to realize."""

    model_config = ConfigDict(frozen=True)

    guest: str
    index: int
    """Position in the host's `scheduled_activity` list (names the unit)."""

    declaration: ScheduledActivity
    path: Path
    """The resolved script file under the range's `activities/` directory."""

    digest: str
    """sha256 of the script's content: a build-key input, so an edited script re-keys its guests."""

    windows: bool

    @property
    def unit(self) -> str:
        """The in-guest unit / task base name."""
        return activity_unit_name(self.declaration.script)


def resolve_activities(spec: RangeSpec, range_dir: Path) -> list[ResolvedActivity]:
    """Resolve and pre-validate every host's scheduled activities, failing fast before anything boots.

    All issues across all declarations are collected into one refusal: missing script files (`activity-not-resolved`), declarations without a schedule (`activity-schedule-required`), second-granularity intervals on Windows hosts, whose task scheduler repeats at one-minute granularity (`activity-schedule-unsupported`), and two declarations on one host whose scripts realize the same unit name (`activity-name-conflict`), since unit names derive from the script's file stem.
    """
    resolved: list[ResolvedActivity] = []
    issues: list[Issue] = []
    for host_index, host in enumerate(spec.hosts):
        windows = host.os.type == "windows"
        unit_names: dict[str, str] = {}
        for index, activity in enumerate(host.scheduled_activity):
            path_prefix = ("hosts", host_index, "scheduled_activity", index)
            unit = activity_unit_name(activity.script)
            if unit in unit_names:
                issues.append(
                    Issue(
                        code="activity-name-conflict",
                        path=(*path_prefix, "script"),
                        message=f"host {host.name!r} declares activities {unit_names[unit]!r} and {activity.script!r}, which both realize the unit name {unit!r}",
                        hint="give the scripts distinct file stems (unit and task names derive from the stem)",
                    )
                )
                continue
            unit_names[unit] = activity.script
            if activity.schedule is None:
                issues.append(
                    Issue(
                        code="activity-schedule-required",
                        path=(*path_prefix, "schedule"),
                        message=f"host {host.name!r} declares activity {activity.script!r} without a schedule, so the build cannot install it",
                        hint="declare schedule: `@boot` or `every <N>s|m|h`",
                    )
                )
                continue
            interval = schedule_interval(activity.schedule)
            if windows and interval is not None and interval[1] == "s":
                issues.append(
                    Issue(
                        code="activity-schedule-unsupported",
                        path=(*path_prefix, "schedule"),
                        message=f"host {host.name!r} is a Windows guest and activity {activity.script!r} declares {activity.schedule!r}; the Windows task scheduler repeats at one-minute granularity",
                        hint="declare the interval in minutes or hours (e.g. every 1m)",
                    )
                )
                continue
            script = range_dir / ACTIVITIES_DIR_NAME / activity.script
            if not script.is_file():
                issues.append(
                    Issue(
                        code="activity-not-resolved",
                        path=(*path_prefix, "script"),
                        message=f"activity script {activity.script!r} for host {host.name!r} is not a file at {script}, so the build cannot install it",
                        hint=f"add ./{ACTIVITIES_DIR_NAME}/{activity.script} to the range directory",
                    )
                )
                continue
            resolved.append(
                ResolvedActivity(
                    guest=host.name,
                    index=index,
                    declaration=activity,
                    path=script,
                    digest=sha256_file(script),
                    windows=windows,
                )
            )
    if issues:
        raise IssueError(issues)
    return resolved


class WriteOp(BaseModel):
    """A file write into the guest (the channel file plane; staged paths are promoted by a following exec)."""

    model_config = ConfigDict(frozen=True)

    kind: Literal["write"] = "write"
    path: str
    data: bytes
    mode: int | None = None


class ExecOp(BaseModel):
    """A command run in the guest."""

    model_config = ConfigDict(frozen=True)

    kind: Literal["exec"] = "exec"
    cmd: tuple[str, ...]
    user: str | None = None


ActivityOp = Union[WriteOp, ExecOp]
"""One in-guest realization step; `activity_ops` renders a declaration into an ordered sequence of these."""


def linux_script_path(activity: ResolvedActivity) -> str:
    """The in-guest path a Linux activity script installs to."""
    return f"{LINUX_ACTIVITY_DIR}/{activity.declaration.script}"


def windows_script_path(activity: ResolvedActivity) -> str:
    """The in-guest path a Windows activity script installs to."""
    relative = str(PureWindowsPath(activity.declaration.script.replace("/", "\\")))
    return f"{WINDOWS_ACTIVITY_DIR}\\{relative}"


def _linux_units(activity: ResolvedActivity) -> dict[str, str]:
    """The systemd unit files for one activity: a service always, plus a timer for interval schedules."""
    declaration = activity.declaration
    assert declaration.schedule is not None  # gated by resolve_activities
    interval = schedule_interval(declaration.schedule)
    unit = activity.unit
    script = linux_script_path(activity)
    user_line = f"User={declaration.user}\n" if declaration.user is not None else ""
    # the description is just the unit name: unit text is agent-readable in
    # the captured image, so it carries no harness identity (_brand.py)
    description = unit
    if interval is None:
        service = (
            f"[Unit]\nDescription={description}\n\n"
            f'[Service]\nType=simple\nExecStart="{script}"\n{user_line}\n'
            "[Install]\nWantedBy=multi-user.target\n"
        )
        return {f"{unit}.service": service}
    count, suffix = interval
    service = (
        f"[Unit]\nDescription={description}\n\n"
        f'[Service]\nType=oneshot\nExecStart="{script}"\n{user_line}'
    )
    timer = (
        f"[Unit]\nDescription={description} timer\n\n"
        f"[Timer]\nOnBootSec={count}{suffix}\nOnUnitActiveSec={count}{suffix}\n\n"
        "[Install]\nWantedBy=timers.target\n"
    )
    return {f"{unit}.service": service, f"{unit}.timer": timer}


def enabled_unit(schedule: str, unit: str) -> str:
    """The systemd unit the build enables (and verification checks): the timer for interval schedules, the service for `@boot`."""
    return f"{unit}.service" if schedule_interval(schedule) is None else f"{unit}.timer"


def _windows_register(activity: ResolvedActivity) -> str:
    """The PowerShell that registers one activity as a scheduled task."""
    declaration = activity.declaration
    assert declaration.schedule is not None  # gated by resolve_activities
    interval = schedule_interval(declaration.schedule)
    argument = (
        f'-NoProfile -ExecutionPolicy Bypass -File "{windows_script_path(activity)}"'
    )
    if interval is None:
        trigger = "New-ScheduledTaskTrigger -AtStartup"
    else:
        count, suffix = interval
        span = f"-Minutes {count}" if suffix == "m" else f"-Hours {count}"
        # a past start boundary with no repetition duration repeats
        # indefinitely from the next interval multiple, across reboots of the
        # captured image (scheduled-activity-v1)
        trigger = (
            "New-ScheduledTaskTrigger -Once -At '2000-01-01T00:00:00' "
            f"-RepetitionInterval (New-TimeSpan {span})"
        )
    if declaration.user is None:
        principal = (
            "New-ScheduledTaskPrincipal -UserId 'SYSTEM' "
            "-LogonType ServiceAccount -RunLevel Highest"
        )
    else:
        # S4U: the task runs as the user with no stored credential and no
        # interactive token
        principal = (
            f"New-ScheduledTaskPrincipal -UserId {ps_quote(declaration.user)} "
            "-LogonType S4U -RunLevel Highest"
        )
    return (
        "$ErrorActionPreference='Stop'; "
        "$action = New-ScheduledTaskAction -Execute 'powershell.exe' "
        f"-Argument {ps_quote(argument)}; "
        f"$trigger = {trigger}; "
        f"$principal = {principal}; "
        f"Register-ScheduledTask -TaskName {ps_quote(activity.unit)} "
        "-Action $action -Trigger $trigger -Principal $principal -Force | Out-Null"
    )


def activity_ops(activity: ResolvedActivity, script: bytes) -> tuple[ActivityOp, ...]:
    """The ordered in-guest steps that realize one activity: stage the script, promote it, and register the unit or task.

    Pure over the declaration and the script bytes, so tests cover the emitted commands without a guest. Staging follows the push idiom: the channel file plane acts as the agent user, so privileged destinations stage through the temp directory and promote via a root/SYSTEM exec.
    """
    unit = activity.unit
    if activity.windows:
        staging = f"C:\\Windows\\Temp\\.{unit}-{request_id()}"
        destination = windows_script_path(activity)
        promote = (
            "$ErrorActionPreference='Stop'; "
            f"$parent = Split-Path -Parent {ps_quote(destination)}; "
            "if ($parent) { New-Item -ItemType Directory -Force -Path $parent | Out-Null }; "
            f"Move-Item -LiteralPath {ps_quote(staging)} "
            f"-Destination {ps_quote(destination)} -Force"
        )
        powershell = ("powershell", "-NoProfile", "-NonInteractive", "-Command")
        return (
            WriteOp(path=staging, data=script),
            ExecOp(cmd=(*powershell, promote)),
            ExecOp(cmd=(*powershell, _windows_register(activity))),
        )
    assert activity.declaration.schedule is not None  # gated by resolve_activities
    staging = f"/tmp/.{unit}-{request_id()}"
    install = (
        f"set -e; install -D -m 755 -- {shlex.quote(staging)} "
        f"{shlex.quote(linux_script_path(activity))}; rm -f -- {shlex.quote(staging)}"
    )
    ops: list[ActivityOp] = [
        WriteOp(path=staging, data=script, mode=0o600),
        ExecOp(cmd=("sh", "-c", install), user="root"),
    ]
    unit_staging: dict[str, str] = {}
    for name, content in _linux_units(activity).items():
        staged = f"/tmp/.{name}-{request_id()}"
        unit_staging[name] = staged
        ops.append(WriteOp(path=staged, data=content.encode(), mode=0o600))
    promote_units = "; ".join(
        f"install -D -m 644 -- {shlex.quote(staged)} "
        f"{shlex.quote(f'/etc/systemd/system/{name}')}; rm -f -- {shlex.quote(staged)}"
        for name, staged in unit_staging.items()
    )
    enable = (
        f"set -e; {promote_units}; systemctl daemon-reload; "
        f"systemctl enable {shlex.quote(enabled_unit(activity.declaration.schedule, unit))}"
    )
    ops.append(ExecOp(cmd=("sh", "-c", enable), user="root"))
    return tuple(ops)


def activity_check_command(
    activity: ScheduledActivity, *, unit: str, windows: bool
) -> tuple[tuple[str, ...], str | None]:
    """The verification probe for one activity as `(argv, user)`: rc 0 exactly when the unit or task exists and is enabled.

    Derived from the spec alone, so the same check runs in the build's verify pass and in the proof boot's convergence loop against the captured artifact.
    """
    if windows:
        probe = (
            "$ErrorActionPreference='Stop'; "
            f"$task = Get-ScheduledTask -TaskName {ps_quote(unit)}; "
            "Write-Output ('state ' + $task.State); "
            "if ($task.State -eq 'Disabled') { exit 1 }"
        )
        return (
            ("powershell", "-NoProfile", "-NonInteractive", "-Command", probe),
            None,
        )
    checked = (
        enabled_unit(activity.schedule, unit)
        if activity.schedule is not None
        else f"{unit}.service"
    )
    return (("systemctl", "is-enabled", "--", checked), "root")


def realize_activities(
    activities: list[ResolvedActivity],
    cids: dict[str, int],
    *,
    skip: frozenset[str] = frozenset(),
    stage_log: StageSink | None = None,
    hybrid_sockets: "Mapping[str, HybridEndpoint] | None" = None,
) -> None:
    """Install every resolved activity into its booted guest (guests in `skip` boot from reused realized images that already carry theirs).

    Raises:
        BuildError: stage `activity` when an install command fails, naming the guest and unit with the command's stderr tail.
    """

    async def run(activity: ResolvedActivity) -> None:
        channel = MessageChannel(
            VsockTransport(cids, hybrid_sockets=hybrid_sockets),
            label="build-activity",
        )
        for op in activity_ops(activity, activity.path.read_bytes()):
            if isinstance(op, WriteOp):
                await channel.write_file(activity.guest, op.path, op.data, mode=op.mode)
                continue
            outcome = await channel.exec(
                activity.guest,
                ExecRequest(
                    id=request_id(),
                    cmd=list(op.cmd),
                    user=op.user,
                    budget=Budget(command_ms=ACTIVITY_EXEC_BUDGET_MS),
                ),
            )
            if outcome.rc != 0:
                stderr = outcome.stderr.decode(errors="replace").strip()[-300:]
                raise BuildError(
                    "activity",
                    f"installing activity {activity.unit!r} failed: "
                    f"{op.cmd[0]} exited {outcome.rc}: {stderr or '(no stderr)'}",
                    guest=activity.guest,
                )

    for activity in activities:
        if activity.guest in skip:
            if stage_log is not None:
                stage_log.log(
                    "activity",
                    "ok",
                    guest=activity.guest,
                    unit=activity.unit,
                    skipped="unchanged",
                )
            continue
        asyncio.run(run(activity))
        if stage_log is not None:
            stage_log.log(
                "activity",
                "ok",
                guest=activity.guest,
                unit=activity.unit,
                script=activity.declaration.script,
                schedule=activity.declaration.schedule,
            )

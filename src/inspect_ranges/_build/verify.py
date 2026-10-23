"""The verification engine (build-v1 slice 4): declarations verified against the booted range.

Verification is mechanical and derived from the spec, never from recipe claims: after all recipes complete, each guest with declarations is probed once over the channel (listening sockets, installed packages, listener-process package attribution), and every `services`/`vulnerabilities` assertion is evaluated against those observed facts. A service verifies on its listening port and, when declared, its version; the version attributes through an explicit `Service.package`, then the listener-process chain (port, pid, exe, owning dpkg), then a dpkg named exactly like the service (user decision, 2026-10-17), and a declared version that cannot be attributed fails naming the paths tried. A vulnerability verifies iff its linked service verifies (exploitability proof is challenge behavioral-check territory per the ratified verification structure); one without a service linkage verifies vacuously and says so.

`credentials` and free-text fields are not mechanically checkable and are not checked. Failures carry the house codes (`service-not-verified`, `vulnerability-not-verified`) with the observed-versus-declared delta and the per-guest probe log path; the evaluation itself is pure over `GuestFacts`, so it tests without a guest.

`scheduled_activity` declarations verify as installed units (scheduled-activity-v1): one probe per declaration checks that the unit or task exists and is enabled (`systemctl is-enabled` on Linux, `Get-ScheduledTask` state on Windows), with unit names derived from the spec alone, so the same check covers the build range and the proof boot. Failures carry `activity-not-verified`.

Windows guests (windows-ad-v1 slice 2) probe over PowerShell into the same `GuestFacts` shape: listeners from `Get-NetTCPConnection`/`Get-NetUDPEndpoint` (pid-attributed, process names joined from `Get-Process`), packages from the registry uninstall enumeration (DisplayName to DisplayVersion), and the listener attribution chain through the owning process's executable `ProductVersion` (the dpkg-ownership analogue: the exe path stands in for the owning package name). Everything below `GuestFacts` — the evaluation, the version matcher — is shared; Windows versions are plain dotted numerics, which the component-prefix matcher handles and the dpkg-specific rules (`~`, `+really`, epochs) simply never trigger on.
"""

import asyncio
import re
import time
from collections.abc import Mapping
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict

from .._channel.channel import MessageChannel, request_id
from .._channel.protocol import Budget, ExecRequest
from .._channel.vsock import HybridEndpoint, VsockTransport
from ..types import Host, RangeSpec
from .recipes import StageSink

PROBE_BUDGET_MS = 15_000
"""Per-exec budget for the fact probes (read-only, fast)."""

_SS_PROCESS = re.compile(r'users:\(\("(?P<name>[^"]+)",pid=(?P<pid>\d+)')


class Listener(BaseModel):
    """One observed bound socket."""

    model_config = ConfigDict(frozen=True)

    proto: Literal["tcp", "udp"]
    port: int
    process: str | None = None
    pid: int | None = None


class GuestFacts(BaseModel):
    """Observed in-guest facts a guest's declarations evaluate against."""

    listeners: list[Listener] = []
    packages: dict[str, str] = {}
    """Installed packages, name to full version (dpkg on linux; registry uninstall DisplayNames plus listener-executable paths with their ProductVersions on Windows)."""

    pid_packages: dict[int, str] = {}
    """Listener pid to the package owning its executable (the attribution chain's middle step): the dpkg name on linux, the executable path on Windows."""

    def listening(self, port: int) -> Listener | None:
        """The listener on `port`, tcp preferred over udp."""
        best: Listener | None = None
        for listener in self.listeners:
            if listener.port != port:
                continue
            if listener.proto == "tcp":
                return listener
            best = best or listener
        return best


class DeclarationResult(BaseModel):
    """One assertion's verification outcome, as the build report and manifest record it."""

    model_config = ConfigDict(frozen=True)

    kind: Literal["service", "vulnerability", "activity"]
    guest: str
    name: str
    status: Literal["ok", "fail"]
    code: str
    """`service-not-verified` / `vulnerability-not-verified` / `activity-not-verified` on failure, empty on ok."""

    declared: str
    observed: str


def parse_ss(output: str, proto: Literal["tcp", "udp"]) -> list[Listener]:
    """Parse `ss -tlnpH` / `ss -ulnpH` output into listeners (bound sockets for udp)."""
    listeners: list[Listener] = []
    for line in output.splitlines():
        parts = line.split()
        if len(parts) < 4:
            continue
        local = parts[3]
        port_text = local.rsplit(":", 1)[-1]
        if not port_text.isdigit():
            continue
        match = _SS_PROCESS.search(line)
        listeners.append(
            Listener(
                proto=proto,
                port=int(port_text),
                process=match.group("name") if match else None,
                pid=int(match.group("pid")) if match else None,
            )
        )
    return listeners


def parse_packages(output: str) -> dict[str, str]:
    r"""Parse `dpkg-query -W -f '${Package}\t${Version}\t${Status}\n'` output, keeping installed packages only.

    dpkg-query lists removed-but-not-purged packages (`deinstall ok config-files`) with full version strings; counting those as installed false-passes a version declaration against files that are gone (round-1 review). Status-less lines (the pre-review probe shape) stay accepted so recorded probe logs re-parse.
    """
    packages: dict[str, str] = {}
    for line in output.splitlines():
        name, _, rest = line.partition("\t")
        version, _, status = rest.partition("\t")
        if not (name and version):
            continue
        # Status is `want error-flag status`: match the status WORD so
        # held-but-installed packages (apt-mark hold, the canonical pin for
        # vulnerable-by-design versions) stay counted (round-2 review)
        if status and status.strip().split()[-1] != "installed":
            continue
        packages[name.strip()] = version.strip()
    return packages


def parse_pid_packages(output: str) -> dict[int, str]:
    """Parse the attribution probe's `pid <pid> pkg <dpkg -S line>` records."""
    attributions: dict[int, str] = {}
    for line in output.splitlines():
        match = re.match(r"pid (\d+) pkg ([^:]+):", line)
        if match:
            attributions[int(match.group(1))] = match.group(2).strip()
    return attributions


def parse_win_processes(output: str) -> dict[int, str]:
    """Parse the Windows probe's `===PROCS===` section (`<pid> <name>` per line from `Get-Process`)."""
    processes: dict[int, str] = {}
    for line in output.splitlines():
        parts = line.split(None, 1)
        if len(parts) == 2 and parts[0].isdigit():
            processes[int(parts[0])] = parts[1].strip()
    return processes


def parse_win_listeners(
    output: str, proto: Literal["tcp", "udp"], processes: Mapping[int, str]
) -> list[Listener]:
    """Parse the Windows probe's listener sections (`<port> <pid>` per line from `Get-NetTCPConnection -State Listen` / `Get-NetUDPEndpoint`), process names joined from the `===PROCS===` map."""
    listeners: list[Listener] = []
    for line in output.splitlines():
        parts = line.split()
        if len(parts) != 2 or not parts[0].isdigit() or not parts[1].isdigit():
            continue
        pid = int(parts[1])
        listeners.append(
            Listener(
                proto=proto,
                port=int(parts[0]),
                pid=pid,
                process=processes.get(pid),
            )
        )
    return listeners


def parse_win_packages(output: str) -> dict[str, str]:
    """Parse the Windows probe's `===PKGS===` section (registry uninstall enumeration, `DisplayName<TAB>DisplayVersion` per line); versionless entries record an empty version."""
    packages: dict[str, str] = {}
    for line in output.splitlines():
        name, _, version = line.partition("\t")
        if name.strip():
            packages[name.strip()] = version.strip()
    return packages


def parse_win_attribution(output: str) -> tuple[dict[int, str], dict[str, str]]:
    """Parse the Windows attribution probe's tab-separated `pid TAB exe-path TAB version` records into (pid to exe path, exe path to ProductVersion): the exe path stands in for the owning package name, so the shared attribution chain reads unchanged. Tab-separated because ProductVersion is a free string (third-party binaries carry spaces) and paths cannot contain tabs; a versionless record keeps its pid-to-exe mapping with an empty version."""
    pid_packages: dict[int, str] = {}
    versions: dict[str, str] = {}
    for line in output.splitlines():
        parts = line.split("\t")
        if len(parts) != 3 or not parts[0].strip().isdigit() or not parts[1].strip():
            continue
        path = parts[1].strip()
        pid_packages[int(parts[0].strip())] = path
        versions[path] = parts[2].strip()
    return pid_packages, versions


def version_matches(declared: str, observed: str) -> bool:
    """Component-prefix match on the upstream version, epochs stripped from both sides.

    `"1.18"` matches `1.18.0-6ubuntu14` and `1:1.18.0+dfsg-1`, but not `1.180` (the next character must not extend a numeric component) and not pre-releases: a `~` ANYWHERE in the remaining upstream component (`3.0.3~rc1` against a declared `3.0`) orders strictly below the declared release in dpkg semantics, while `~` inside the Debian revision (backport suffixes like `-1ubuntu1~20.04`) stays matchable. The Debian `+really` downgrade convention binds the match to what actually ships: `1.18.0+really1.16.1-1` is version 1.16.1 (round-1 review closed both fail-open shapes).
    """
    upstream = observed.split(":", 1)[-1]
    wanted = declared.split(":", 1)[-1]
    if "+really" in upstream:
        upstream = upstream.split("+really", 1)[1]
        # an author who copied the shipped string verbatim declared the same
        # convention; bind both sides to what actually ships (round-2 review)
        if "+really" in wanted:
            wanted = wanted.split("+really", 1)[1]
    if not upstream.startswith(wanted):
        return False
    if len(upstream) == len(wanted):
        return True
    following = upstream[len(wanted)]
    if following.isdigit() or following == "~":
        return False
    component = upstream.split("-", 1)[0]
    if component.startswith(wanted) and "~" in component[len(wanted) :]:
        return False
    return True


def evaluate_host(host: Host, facts: GuestFacts) -> list[DeclarationResult]:
    """Evaluate one host's `services` and `vulnerabilities` assertions against observed facts (pure)."""
    results: list[DeclarationResult] = []
    service_ok: dict[str, bool] = {}
    for service in host.services:
        failures: list[str] = []
        observations: list[str] = []
        if service.port is not None:
            listener = facts.listening(service.port)
            if listener is None:
                failures.append(f"no tcp/udp socket on port {service.port}")
            else:
                observations.append(
                    f"{listener.proto}/{listener.port} by {listener.process or 'unknown process'}"
                )
        if service.version is not None:
            attributed = _attribute_version(
                service.name, service.package, service.port, facts
            )
            if attributed.version is None:
                failures.append(f"version unattributable ({attributed.detail})")
            elif not version_matches(service.version, attributed.version):
                failures.append(
                    f"version {attributed.version} from {attributed.detail}, declared {service.version}"
                )
            else:
                observations.append(
                    f"version {attributed.version} from {attributed.detail}"
                )
        if service.port is None and service.version is None:
            observations.append(
                "nothing mechanically checkable (name-only declaration)"
            )
        ok = not failures
        service_ok[service.name] = ok
        results.append(
            DeclarationResult(
                kind="service",
                guest=host.name,
                name=service.name,
                status="ok" if ok else "fail",
                code="" if ok else "service-not-verified",
                declared=_declared_service(
                    service_name=service.name,
                    port=service.port,
                    version=service.version,
                ),
                observed="; ".join(failures or observations),
            )
        )
    for vulnerability in host.vulnerabilities:
        if vulnerability.service is None:
            results.append(
                DeclarationResult(
                    kind="vulnerability",
                    guest=host.name,
                    name=vulnerability.id,
                    status="ok",
                    code="",
                    declared=vulnerability.id,
                    observed="no service linkage; exploitability proof is challenge behavioral-check territory",
                )
            )
            continue
        linked_ok = service_ok.get(vulnerability.service, False)
        results.append(
            DeclarationResult(
                kind="vulnerability",
                guest=host.name,
                name=vulnerability.id,
                status="ok" if linked_ok else "fail",
                code="" if linked_ok else "vulnerability-not-verified",
                declared=f"{vulnerability.id} in service {vulnerability.service!r}",
                observed=(
                    f"linked service {vulnerability.service!r} verified"
                    if linked_ok
                    else f"linked service {vulnerability.service!r} failed its assertion"
                ),
            )
        )
    return results


class _Attribution(BaseModel):
    version: str | None
    detail: str


def _attribute_version(
    name: str, package: str | None, port: int | None, facts: GuestFacts
) -> _Attribution:
    tried: list[str] = []
    if package is not None:
        version = facts.packages.get(package)
        if version is not None:
            return _Attribution(version=version, detail=f"declared package {package!r}")
        # a declared package is authoritative, so a miss is terminal; the owner
        # the listener chain would have attributed rides along as the fix
        detail = f"declared package {package!r} is not installed"
        if port is not None:
            listener = facts.listening(port)
            if listener is not None and listener.pid is not None:
                owner = facts.pid_packages.get(listener.pid)
                if owner is not None and owner in facts.packages:
                    detail += (
                        f" (the listener process {listener.process!r}"
                        f" is owned by package {owner!r})"
                    )
        return _Attribution(version=None, detail=detail)
    tried.append("no package field")
    if port is not None:
        listener = facts.listening(port)
        if listener is not None and listener.pid is not None:
            owner = facts.pid_packages.get(listener.pid)
            if owner is not None and owner in facts.packages:
                return _Attribution(
                    version=facts.packages[owner],
                    detail=f"listener process {listener.process!r} -> package {owner!r}",
                )
            tried.append(f"listener pid {listener.pid} has no attributable package")
        else:
            tried.append("no attributable listener process")
    exact = facts.packages.get(name)
    if exact is not None:
        return _Attribution(version=exact, detail=f"package named {name!r}")
    tried.append(f"no package named {name!r}")
    return _Attribution(version=None, detail="; ".join(tried))


def _declared_service(service_name: str, port: int | None, version: str | None) -> str:
    parts = [service_name]
    if port is not None:
        parts.append(f"port {port}")
    if version is not None:
        parts.append(f"version {version}")
    return " ".join(parts)


def verify_range(
    spec: RangeSpec,
    cids: dict[str, int],
    *,
    log_dir: Path,
    stage_log: StageSink | None = None,
    hybrid_sockets: "Mapping[str, HybridEndpoint] | None" = None,
) -> list[DeclarationResult]:
    """Verify every host's declarations against the live range; one probe pass per declaring guest.

    Each guest's raw probe output lands in `log_dir/<guest>.log`; every declaration gets a `verify` stage record with its code and the observed-versus-declared delta.
    """
    log_dir.mkdir(parents=True, exist_ok=True)
    results: list[DeclarationResult] = []
    for host in spec.hosts:
        if (
            not host.services
            and not host.vulnerabilities
            and not host.scheduled_activity
        ):
            continue
        windows = host.os.type == "windows"
        log_path = log_dir / f"{host.name}.log"
        activities_log = log_dir / f"{host.name}-activities.log"
        host_results: list[DeclarationResult] = []
        if host.services or host.vulnerabilities:
            facts = asyncio.run(
                _collect_facts(
                    cids,
                    host.name,
                    log_path,
                    hybrid_sockets,
                    windows=windows,
                )
            )
            host_results.extend(evaluate_host(host, facts))
        if host.scheduled_activity:
            host_results.extend(
                asyncio.run(
                    _check_activities(
                        cids,
                        host,
                        activities_log,
                        hybrid_sockets,
                        windows=windows,
                    )
                )
            )
        results.extend(host_results)
        if stage_log is not None:
            for result in host_results:
                stage_log.log(
                    "verify",
                    result.status,
                    kind=result.kind,
                    guest=result.guest,
                    name=result.name,
                    code=result.code,
                    declared=result.declared,
                    observed=result.observed,
                    log=str(activities_log if result.kind == "activity" else log_path),
                )
    return results


async def _check_activities(
    cids: dict[str, int],
    host: Host,
    log_path: Path,
    hybrid_sockets: "Mapping[str, HybridEndpoint] | None" = None,
    *,
    windows: bool = False,
) -> list[DeclarationResult]:
    """Verify every declared scheduled activity's installed unit or task: `systemctl is-enabled` on Linux, `Get-ScheduledTask` state on Windows (scheduled-activity-v1).

    The probe derives the unit names from the spec alone, so the same check covers the build range and the proof boot's captured artifacts.
    """
    from .activities import activity_check_command, activity_unit_name

    channel = MessageChannel(
        VsockTransport(cids, hybrid_sockets=hybrid_sockets), label="build-verify"
    )
    results: list[DeclarationResult] = []
    records: list[str] = []
    for activity in host.scheduled_activity:
        unit = activity_unit_name(activity.script)
        cmd, user = activity_check_command(activity, unit=unit, windows=windows)
        outcome = await channel.exec(
            host.name,
            ExecRequest(
                id=request_id(),
                cmd=list(cmd),
                user=user,
                budget=Budget(command_ms=PROBE_BUDGET_MS),
            ),
        )
        stdout = outcome.stdout.decode(errors="replace").strip()
        stderr = outcome.stderr.decode(errors="replace").strip()
        records.append(f"# {unit} rc={outcome.rc}\n{stdout}\n{stderr}")
        ok = outcome.rc == 0
        observed = stdout or stderr or "(no output)"
        results.append(
            DeclarationResult(
                kind="activity",
                guest=host.name,
                name=unit,
                status="ok" if ok else "fail",
                code="" if ok else "activity-not-verified",
                declared=f"{activity.script} {activity.schedule or '(no schedule)'}",
                observed=(observed if ok else f"probe exited {outcome.rc}: {observed}"),
            )
        )
    log_path.write_text("\n".join(records) + "\n")
    return results


_WIN_PROBE = (
    "$ErrorActionPreference='SilentlyContinue'; "
    "Write-Output '===TCP==='; "
    "Get-NetTCPConnection -State Listen | ForEach-Object { '{0} {1}' -f $_.LocalPort, $_.OwningProcess }; "
    "Write-Output '===UDP==='; "
    "Get-NetUDPEndpoint | ForEach-Object { '{0} {1}' -f $_.LocalPort, $_.OwningProcess }; "
    "Write-Output '===PROCS==='; "
    "Get-Process | ForEach-Object { '{0} {1}' -f $_.Id, $_.ProcessName }; "
    "Write-Output '===PKGS==='; "
    "Get-ItemProperty "
    "'HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*',"
    "'HKLM:\\Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*' "
    "| Where-Object { $_.DisplayName } "
    '| ForEach-Object { "{0}`t{1}" -f $_.DisplayName, $_.DisplayVersion }'
)


async def _collect_facts(
    cids: dict[str, int],
    guest: str,
    log_path: Path,
    hybrid_sockets: "Mapping[str, HybridEndpoint] | None" = None,
    *,
    windows: bool = False,
) -> GuestFacts:
    channel = MessageChannel(
        VsockTransport(cids, hybrid_sockets=hybrid_sockets), label="build-verify"
    )
    if windows:
        cmd = ["powershell", "-NoProfile", "-NonInteractive", "-Command", _WIN_PROBE]
        user: str | None = None
    else:
        probe = (
            "echo ===TCP===; ss -tlnpH; echo ===UDP===; ss -ulnpH; "
            "echo ===PKGS===; dpkg-query -W -f '${Package}\\t${Version}\\t${Status}\\n'"
        )
        cmd = ["sh", "-c", probe]
        user = "root"
    outcome = await channel.exec(
        guest,
        ExecRequest(
            id=request_id(),
            cmd=cmd,
            user=user,
            budget=Budget(command_ms=PROBE_BUDGET_MS),
        ),
    )
    text = outcome.stdout.decode(errors="replace")
    stderr_text = outcome.stderr.decode(errors="replace")
    if outcome.rc != 0 or outcome.stdout_truncated:
        log_path.write_text(
            f"# build-verify probe of guest {guest} FAILED rc={outcome.rc} truncated={outcome.stdout_truncated}\n{text}\n===STDERR===\n{stderr_text}"
        )
        raise RuntimeError(
            f"fact probe on guest {guest!r} exited {outcome.rc}"
            f"{' (output truncated)' if outcome.stdout_truncated else ''}; log: {log_path}"
        )
    sections = _split_sections(text)
    if windows:
        processes = parse_win_processes(sections.get("PROCS", ""))
        listeners = parse_win_listeners(
            sections.get("TCP", ""), "tcp", processes
        ) + parse_win_listeners(sections.get("UDP", ""), "udp", processes)
        packages = parse_win_packages(sections.get("PKGS", ""))
    else:
        listeners = parse_ss(sections.get("TCP", ""), "tcp") + parse_ss(
            sections.get("UDP", ""), "udp"
        )
        packages = parse_packages(sections.get("PKGS", ""))
    pids = sorted({listener.pid for listener in listeners if listener.pid is not None})
    attribution_text = ""
    pid_packages: dict[int, str] = {}
    if pids:
        if windows:
            # the one data interpolation into PowerShell command text in the
            # Windows surface that skips ps_quote: every pid came through
            # int() in the listener parser, so the joined list is digits and
            # commas by construction — keep it that way or quote each value
            pid_list = ",".join(str(pid) for pid in pids)
            script = (
                "$ErrorActionPreference='SilentlyContinue'; "
                f"foreach ($p in @({pid_list})) {{ "
                "$proc = Get-Process -Id $p; "
                "if ($proc -and $proc.Path) { "
                "$v = (Get-Item $proc.Path).VersionInfo.ProductVersion; "
                'Write-Output ("{0}`t{1}`t{2}" -f $p, $proc.Path, $v) } }'
            )
            attribution_cmd = [
                "powershell",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                script,
            ]
            attribution_user: str | None = None
        else:
            lines = "; ".join(
                f'exe=$(readlink /proc/{pid}/exe 2>/dev/null) && [ -n "$exe" ] '
                f'&& echo "pid {pid} pkg $(dpkg -S "$exe" 2>/dev/null)"'
                for pid in pids
            )
            attribution_cmd = ["sh", "-c", f"{lines}; true"]
            attribution_user = "root"
        attribution = await channel.exec(
            guest,
            ExecRequest(
                id=request_id(),
                cmd=attribution_cmd,
                user=attribution_user,
                budget=Budget(command_ms=PROBE_BUDGET_MS),
            ),
        )
        attribution_text = attribution.stdout.decode(errors="replace")
        if windows:
            pid_packages, exe_versions = parse_win_attribution(attribution_text)
            # the exe's ProductVersion is the Windows analogue of the owning
            # package's version: merged under the path the chain resolves to
            packages = {**packages, **exe_versions}
        else:
            pid_packages = parse_pid_packages(attribution_text)
    stamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    log_path.write_text(
        f"# build-verify probe of guest {guest} at {stamp}\n{text}\n===STDERR===\n{stderr_text}\n===ATTRIBUTION===\n{attribution_text}"
    )
    return GuestFacts(
        listeners=listeners,
        packages=packages,
        pid_packages=pid_packages,
    )


def _split_sections(text: str) -> dict[str, str]:
    sections: dict[str, list[str]] = {}
    current: str | None = None
    for line in text.splitlines():
        match = re.fullmatch(r"===(\w+)===", line.strip())
        if match:
            current = str(match.group(1))
            sections[current] = []
        elif current is not None:
            sections[current].append(line)
    return {name: "\n".join(lines) for name, lines in sections.items()}

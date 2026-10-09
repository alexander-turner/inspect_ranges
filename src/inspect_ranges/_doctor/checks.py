import json
import os
import platform
import re
import shutil
import subprocess
from collections.abc import Callable
from pathlib import Path
from typing import Any, cast

from .result import CheckResult, CheckStatus

PLATFORM = "Platform"
REALIZER = "Realizer"
PROVIDER = "Provider"
VIRTUALIZATION = "Virtualization"
DOCKER = "Docker"
NETWORKING = "Networking"
IMAGE_TOOLING = "Image tooling"

# same minimums as inspect_ai's Docker sandbox provider (Compose 2.22.0 is its `pull --policy` floor)
DOCKER_ENGINE_MIN_VERSION = (24, 0, 6)
DOCKER_COMPOSE_MIN_VERSION = (2, 22, 0)

COMMAND_TIMEOUT = 30


def run_checks() -> list[CheckResult]:
    """Check this machine, returning results in report order."""
    host = check_platform(platform.system(), platform.machine())
    results = [host]
    if host.status == "ok":
        results += check_virtualization(Path("/dev"))
    else:
        results.append(_skip(VIRTUALIZATION, "all checks", "requires Linux x86_64"))
    results += check_docker(
        info=_run(["docker", "info", "--format", "{{json .}}"]),
        compose=_run(["docker", "compose", "version", "--format", "json"]),
    )
    if host.status == "ok":
        results += [
            check_br_netfilter(Path("/proc/sys")),
            check_ipv6(Path("/proc/sys")),
            *check_image_tools(shutil.which),
            check_kernel_readable(Path("/boot")),
        ]
    else:
        results.append(_skip(NETWORKING, "all checks", "requires Linux x86_64"))
        results.append(_skip(IMAGE_TOOLING, "all checks", "requires Linux x86_64"))
    results += check_provider(
        state_dir=_provider_state_dir(),
        image_cache=_provider_image_cache(),
    )
    if host.status != "ok":
        results.append(_skip(REALIZER, "all checks", "requires Linux x86_64"))
    else:
        docker_probe = _run(["docker", "version", "--format", "ok"])
        results += check_realizer(
            image_inspect=(
                _run(
                    [
                        "docker",
                        "image",
                        "inspect",
                        _range_image_tag(),
                        "--format",
                        "ok",
                    ]
                )
                if docker_probe is not None and docker_probe.returncode == 0
                else None
            ),
        )
    return results


def _provider_state_dir() -> Path:
    from .._runtime.ownership import default_state_dir

    return default_state_dir()


def _provider_image_cache() -> Path:
    from .._provider.state import default_image_cache

    return default_image_cache()


def check_provider(state_dir: Path, image_cache: Path) -> list[CheckResult]:
    """The Inspect sandbox provider surface: entry-point registration, the inspect-ai floor, a current-recipe golden, and the CID lease registry's health."""
    import importlib.metadata as metadata

    from .._runtime.images import RECIPE_VERSION, ImageMetadata

    results: list[CheckResult] = []

    # entry point: the only registration path `inspect eval` has
    entries = {e.name: e.value for e in metadata.entry_points(group="inspect_ai")}
    if entries.get("inspect_ranges") == "inspect_ranges._registry":
        results.append(
            CheckResult(PROVIDER, "entry point", "ok", "libvirt_range registered")
        )
    else:
        results.append(
            CheckResult(
                PROVIDER,
                "entry point",
                "fail",
                "inspect_ranges is not registered in the inspect_ai entry-point group",
                fix="reinstall the package: pip install -e . (or uv sync)",
            )
        )

    # inspect-ai floor, read from this package's own dependency pin
    floor = _inspect_ai_floor()
    try:
        installed = metadata.version("inspect-ai")
    except metadata.PackageNotFoundError:
        installed = None
    if installed is None:
        results.append(
            CheckResult(
                PROVIDER,
                "inspect-ai",
                "fail",
                "inspect-ai is not installed",
                fix="pip install inspect-ai",
            )
        )
    elif floor is None:
        results.append(
            CheckResult(
                PROVIDER,
                "inspect-ai",
                "warn",
                f"{installed} installed, but the package's own floor could not be "
                "read from its metadata, so the version check did not run",
            )
        )
    elif (parse_version(installed) or ()) < (parse_version(floor) or ()):
        results.append(
            CheckResult(
                PROVIDER,
                "inspect-ai",
                "fail",
                f"{installed} is below the verified floor {floor}",
                fix=f"pip install 'inspect-ai>={floor}'",
            )
        )
    else:
        results.append(CheckResult(PROVIDER, "inspect-ai", "ok", installed))

    # a current-recipe golden must exist as both sidecar AND image file;
    # older-recipe goldens carry a pre-3.1.0 daemon whose session-less pong
    # the host rejects tamper-shaped at boot
    current: list[str] = []
    other_recipe: list[tuple[str, str]] = []
    missing_file: list[str] = []
    for sidecar in sorted(image_cache.glob("*.json")) if image_cache.is_dir() else []:
        try:
            meta = ImageMetadata.model_validate_json(sidecar.read_text())
        except (OSError, ValueError):
            continue
        if meta.recipe_version != RECIPE_VERSION:
            other_recipe.append((meta.file, meta.recipe_version))
        elif not (image_cache / meta.file).is_file():
            missing_file.append(meta.file)
        else:
            current.append(meta.file)
    if current:
        results.append(CheckResult(PROVIDER, "golden image", "ok", ", ".join(current)))
    elif missing_file:
        results.append(
            CheckResult(
                PROVIDER,
                "golden image",
                "warn",
                "sidecar(s) present but the image file is gone: "
                + ", ".join(missing_file),
                fix="re-derive: inspect-ranges images derive <vendor> --sha256 <digest> ...",
            )
        )
    elif other_recipe:
        details: list[str] = []
        for name, version in other_recipe:
            try:
                older = int(version) < int(RECIPE_VERSION)
            except ValueError:
                older = None
            if older:
                details.append(
                    f"{name} (recipe v{version}: its daemon predates the required "
                    "pong session field, so this host fails the boot ping tamper-shaped)"
                )
            elif older is None:
                details.append(f"{name} (recipe v{version}, not v{RECIPE_VERSION})")
            else:
                details.append(
                    f"{name} (recipe v{version} is NEWER than this package's "
                    f"v{RECIPE_VERSION}: upgrade inspect_ranges or re-derive)"
                )
        results.append(
            CheckResult(
                PROVIDER,
                "golden image",
                "warn",
                "no current-recipe golden: " + "; ".join(details),
                fix="re-derive: inspect-ranges images derive <vendor> --sha256 <digest> ...",
            )
        )
    else:
        results.append(
            CheckResult(
                PROVIDER,
                "golden image",
                "warn",
                f"no goldens in {image_cache}; derive one before running evals",
                fix="inspect-ranges images derive <vendor> --sha256 <digest> ...",
            )
        )

    # the CID lease registry: a STRICT read, deliberately stricter than the
    # allocator's own forgiving reader. The file is a flat {project: lease}
    # mapping; a corrupt file or an entry whose block cannot be determined
    # makes `lease()` raise `CidRegistryError` at admission time, which is
    # exactly the pre-eval failure doctor exists to catch.
    from .._provider.naming import CidLease, entry_block

    def reservable(entry: object) -> bool:
        try:
            CidLease.model_validate(entry)
            return True
        except ValueError:
            return entry_block(entry) is not None

    lease_path = state_dir / "cids.json"
    if not lease_path.exists():
        results.append(
            CheckResult(PROVIDER, "cid leases", "ok", "no lease file yet (clean state)")
        )
    else:
        try:
            raw = json.loads(lease_path.read_text())
            if not isinstance(raw, dict):
                raise ValueError("registry root is not an object")
            entries = cast("dict[str, object]", raw)
            blocked = sorted(
                project for project, entry in entries.items() if not reservable(entry)
            )
            if blocked:
                raise ValueError(
                    "entries whose CID block cannot be determined: "
                    + ", ".join(blocked)
                )
            results.append(
                CheckResult(
                    PROVIDER,
                    "cid leases",
                    "ok",
                    f"{len(entries)} entr{'y' if len(entries) == 1 else 'ies'} at {lease_path}",
                )
            )
        except (OSError, ValueError) as error:
            results.append(
                CheckResult(
                    PROVIDER,
                    "cid leases",
                    "fail",
                    f"{lease_path} unreadable or corrupt ({error}): undeterminable entries block all leasing, and a corrupt file reads as EMPTY to the allocator, so fresh leases could silently overlap CIDs of still-running VMs",
                    fix=(
                        "tear everything down, then remove the registry: "
                        f"inspect sandbox cleanup libvirt_range && rm {lease_path}"
                    ),
                )
            )
    return results


def _inspect_ai_floor() -> str | None:
    """The inspect-ai minimum from this package's own dependency metadata.

    Tolerates extras, parenthesized specifiers, and multi-clause pins; `None` means the floor could not be read (the caller reports that visibly rather than skipping silently).
    """
    import importlib.metadata as metadata

    try:
        requires = metadata.requires("inspect_ranges") or []
    except metadata.PackageNotFoundError:
        return None
    for requirement in requires:
        if not requirement.replace("_", "-").startswith("inspect-ai"):
            continue
        match = re.search(r">=\s*([0-9.]+)", requirement)
        if match:
            return match.group(1)
    return None


def _range_image_tag() -> str:
    from .._runtime.rangeimage import RANGE_IMAGE_TAG

    return RANGE_IMAGE_TAG


def _artifact_state(sidecar: Path) -> str:
    """`ok`, `tar-missing`, or `absent`: the sidecar names the tarball that must exist beside it."""
    from .._channel.bundle import DaemonBundleInfo, bundle_file_name

    if not sidecar.is_file():
        return "absent"
    try:
        info = DaemonBundleInfo.model_validate_json(sidecar.read_text())
    except (OSError, ValueError):
        return "absent"
    return (
        "ok"
        if (sidecar.parent / bundle_file_name(info.version)).is_file()
        else "tar-missing"
    )


def check_realizer(
    image_inspect: subprocess.CompletedProcess[str] | None,
) -> list[CheckResult]:
    """Realizer host surface: the hardened range image, the daemon artifact, and the Go toolchain that builds it (warnings, not failures: `up` builds the image on demand and `daemon-bundle` publishes the artifact)."""
    from .._channel.bundle import GO_PIN, locate_go
    from .._runtime.images import DEFAULT_ARTIFACT_DIR

    results: list[CheckResult] = []
    if image_inspect is None:
        results.append(
            CheckResult(
                REALIZER,
                "range image",
                "skip",
                "docker unreachable, cannot tell whether the image exists",
            )
        )
    elif image_inspect.returncode == 0:
        results.append(CheckResult(REALIZER, "range image", "ok", _range_image_tag()))
    else:
        results.append(
            CheckResult(
                REALIZER,
                "range image",
                "warn",
                f"{_range_image_tag()} not built yet; `inspect-ranges up` builds it on first use",
            )
        )
    sidecar = DEFAULT_ARTIFACT_DIR / "daemon.json"
    artifact_state = _artifact_state(sidecar)
    if artifact_state == "ok":
        results.append(
            CheckResult(REALIZER, "daemon artifact", "ok", str(DEFAULT_ARTIFACT_DIR))
        )
    elif artifact_state == "tar-missing":
        results.append(
            CheckResult(
                REALIZER,
                "daemon artifact",
                "warn",
                f"sidecar present but its bundle tar is missing at {DEFAULT_ARTIFACT_DIR}; republish",
                fix=f"inspect-ranges daemon-bundle -o {DEFAULT_ARTIFACT_DIR}",
            )
        )
    else:
        results.append(
            CheckResult(
                REALIZER,
                "daemon artifact",
                "warn",
                f"none at {DEFAULT_ARTIFACT_DIR}; publish one: inspect-ranges daemon-bundle -o {DEFAULT_ARTIFACT_DIR}",
                fix=f"inspect-ranges daemon-bundle -o {DEFAULT_ARTIFACT_DIR}",
            )
        )
    go = locate_go()
    if go is not None:
        results.append(CheckResult(REALIZER, "go toolchain", "ok", str(go)))
    else:
        results.append(
            CheckResult(
                REALIZER,
                "go toolchain",
                "warn",
                f"no Go toolchain (needed only to build the daemon artifact; pin {GO_PIN})",
            )
        )
    return results


def check_platform(system: str, machine: str) -> CheckResult:
    if system == "Linux" and machine in ("x86_64", "amd64"):
        return CheckResult(PLATFORM, "Linux x86_64", "ok", f"{system} {machine}")
    return CheckResult(
        PLATFORM,
        "Linux x86_64",
        "fail",
        f"{system} {machine}",
        fix="Develop on a Linux x86_64 machine with KVM, e.g. the EC2 devbox (see devbox/README.md).",
    )


def check_virtualization(dev: Path) -> list[CheckResult]:
    kvm = dev / "kvm"
    results = [
        _device(
            kvm,
            "fail",
            "Use a KVM-capable host: on EC2 a metal instance (e.g. m6i.metal) or a c8i/m8i/r8i instance launched with nested virtualization; elsewhere enable VT-x in firmware and load kvm_intel.",
        )
    ]
    if not kvm.exists():
        results.append(_skip(VIRTUALIZATION, "/dev/kvm access", "no /dev/kvm"))
    elif os.access(kvm, os.R_OK | os.W_OK):
        results.append(
            CheckResult(
                VIRTUALIZATION,
                "/dev/kvm access",
                "ok",
                "readable and writable by this user",
            )
        )
    else:
        results.append(
            CheckResult(
                VIRTUALIZATION,
                "/dev/kvm access",
                "warn",
                "not accessible by this user (needed only by tools run directly on the host, e.g. qemu-img, virt-install)",
                fix="sudo usermod -aG kvm $USER, then log in again",
                fix_command='usermod -aG kvm "$SUDO_USER"',
            )
        )
    results.append(
        _device(
            dev / "net" / "tun",
            "fail",
            "sudo modprobe tun && echo tun | sudo tee /etc/modules-load.d/tun.conf",
            fix_command="modprobe tun && echo tun > /etc/modules-load.d/tun.conf",
        )
    )
    results.append(
        _device(
            dev / "vhost-net",
            "warn",
            "sudo modprobe vhost_net && echo vhost_net | sudo tee /etc/modules-load.d/vhost_net.conf",
            fix_command="modprobe vhost_net && echo vhost_net > /etc/modules-load.d/vhost_net.conf",
            missing="missing (VM networking works but is slower)",
        )
    )
    results.append(
        _device(
            dev / "vhost-vsock",
            "fail",
            "sudo modprobe vhost_vsock && echo vhost_vsock | sudo tee /etc/modules-load.d/vhost_vsock.conf",
            fix_command="modprobe vhost_vsock && echo vhost_vsock > /etc/modules-load.d/vhost_vsock.conf",
            missing="missing (vsock is the exec/file control channel for VMs)",
        )
    )
    return results


def check_docker(
    info: subprocess.CompletedProcess[str] | None,
    compose: subprocess.CompletedProcess[str] | None,
) -> list[CheckResult]:
    """Judge `docker info --format '{{json .}}'` and `docker compose version --format json` output (`None` when `docker` isn't installed)."""
    dependents = ["Docker Engine version", "Docker Compose version", "cgroup version"]
    if info is None:
        return [
            CheckResult(
                DOCKER,
                "Docker daemon",
                "fail",
                "docker CLI not found",
                fix="Install Docker Engine: https://docs.docker.com/engine/install/ubuntu/",
            ),
            *_skipped(DOCKER, dependents, "Docker daemon unavailable"),
        ]

    data = _json_object(info.stdout)
    server_version = str(data.get("ServerVersion") or "")
    if info.returncode != 0 or not server_version:
        error = _first_line(info.stderr) or "no server version reported"
        permission = "permission denied" in error.lower()
        fix = (
            "sudo usermod -aG docker $USER, then log in again"
            if permission
            else "Start the daemon (sudo systemctl start docker), or check DOCKER_HOST / the current docker context."
        )
        return [
            CheckResult(
                DOCKER,
                "Docker daemon",
                "fail",
                f"unreachable: {error}",
                fix=fix,
                fix_command='usermod -aG docker "$SUDO_USER"' if permission else None,
            ),
            *_skipped(DOCKER, dependents, "Docker daemon unavailable"),
        ]

    results = [
        CheckResult(DOCKER, "Docker daemon", "ok", "reachable by this user"),
        _minimum_version(
            "Docker Engine version",
            server_version,
            DOCKER_ENGINE_MIN_VERSION,
            "Upgrade Docker Engine: https://docs.docker.com/engine/install/ubuntu/",
        ),
    ]

    compose_version = (
        str(_json_object(compose.stdout).get("version") or "") if compose else ""
    )
    if compose is None or compose.returncode != 0 or not compose_version:
        results.append(
            CheckResult(
                DOCKER,
                "Docker Compose version",
                "fail",
                "Docker Compose plugin not found",
                fix="sudo apt-get install docker-compose-plugin",
                fix_command="apt-get install -y docker-compose-plugin",
            )
        )
    else:
        results.append(
            _minimum_version(
                "Docker Compose version",
                compose_version,
                DOCKER_COMPOSE_MIN_VERSION,
                "sudo apt-get install --only-upgrade docker-compose-plugin",
                fix_command="apt-get install -y --only-upgrade docker-compose-plugin",
            )
        )

    cgroup_version = str(data.get("CgroupVersion") or "unknown")
    if cgroup_version == "2":
        results.append(CheckResult(DOCKER, "cgroup version", "ok", "cgroup v2"))
    else:
        results.append(
            CheckResult(
                DOCKER,
                "cgroup version",
                "warn",
                f"cgroup {cgroup_version} (range memory limits assume cgroup v2)",
                fix="Use a distribution that defaults to cgroup v2 (e.g. Ubuntu 22.04+), or boot with systemd.unified_cgroup_hierarchy=1.",
            )
        )
    return results


def check_br_netfilter(proc_sys: Path) -> CheckResult:
    setting = proc_sys / "net" / "bridge" / "bridge-nf-call-iptables"
    if not setting.exists():
        return CheckResult(NETWORKING, "br_netfilter", "ok", "not loaded")
    if setting.read_text().strip() == "0":
        return CheckResult(
            NETWORKING, "br_netfilter", "ok", "loaded, but bridge-nf-call-iptables=0"
        )
    return CheckResult(
        NETWORKING,
        "br_netfilter",
        "warn",
        "loaded with bridge-nf-call-iptables=1 (host iptables rules can filter bridged range traffic)",
        fix="sudo sysctl -w net.bridge.bridge-nf-call-iptables=0 net.bridge.bridge-nf-call-ip6tables=0",
        fix_command="sysctl -w net.bridge.bridge-nf-call-iptables=0 net.bridge.bridge-nf-call-ip6tables=0",
    )


def check_ipv6(proc_sys: Path) -> CheckResult:
    setting = proc_sys / "net" / "ipv6" / "conf" / "all" / "disable_ipv6"
    if not setting.exists():
        return CheckResult(
            NETWORKING,
            "IPv6",
            "warn",
            "not available in this kernel (ranges that rely on IPv6, e.g. mitm6 scenarios, won't work)",
            fix="Enable IPv6 in the kernel (remove ipv6.disable=1 from the boot parameters).",
        )
    if setting.read_text().strip() == "0":
        return CheckResult(NETWORKING, "IPv6", "ok", "enabled")
    return CheckResult(
        NETWORKING,
        "IPv6",
        "warn",
        "disabled (ranges that rely on IPv6, e.g. mitm6 scenarios, won't work)",
        fix="sudo sysctl -w net.ipv6.conf.all.disable_ipv6=0",
        fix_command="sysctl -w net.ipv6.conf.all.disable_ipv6=0",
    )


def check_image_tools(which: Callable[[str], str | None]) -> list[CheckResult]:
    """Check the tools used to build VM images (`which` resolves a command name to a path or `None`)."""
    tools = {"qemu-img": "qemu-utils", "virt-customize": "libguestfs-tools"}
    results: list[CheckResult] = []
    for tool, package in tools.items():
        path = which(tool)
        if path:
            results.append(CheckResult(IMAGE_TOOLING, tool, "ok", str(path)))
        else:
            results.append(
                CheckResult(
                    IMAGE_TOOLING,
                    tool,
                    "fail",
                    "not found",
                    fix=f"sudo apt-get install {package}",
                    fix_command=f"apt-get install -y {package}",
                )
            )
    return results


def check_kernel_readable(boot: Path) -> CheckResult:
    """Libguestfs (virt-customize) copies the host kernel to build its appliance, so it must be readable by this user."""
    kernels = sorted(boot.glob("vmlinuz-*"))
    if not kernels:
        return CheckResult(
            IMAGE_TOOLING,
            "host kernel readable",
            "warn",
            f"no vmlinuz-* in {boot} (libguestfs needs a host kernel to build its appliance)",
        )
    unreadable = [kernel.name for kernel in kernels if not os.access(kernel, os.R_OK)]
    if not unreadable:
        return CheckResult(
            IMAGE_TOOLING,
            "host kernel readable",
            "ok",
            f"{len(kernels)} kernel(s) in {boot}",
        )
    return CheckResult(
        IMAGE_TOOLING,
        "host kernel readable",
        "fail",
        f"not readable by this user: {', '.join(unreadable)} (virt-customize will fail)",
        fix="sudo chmod 0644 /boot/vmlinuz-*, and install the kernel hook from the devbox bootstrap "
        + "(/etc/kernel/postinst.d/zz-devbox-kernel-readable) so future kernels stay readable",
        fix_command=(
            "chmod 0644 /boot/vmlinuz-*\n"
            "printf '#!/bin/sh\\nchmod 0644 /boot/vmlinuz-*\\n' > /etc/kernel/postinst.d/zz-devbox-kernel-readable\n"
            "chmod 755 /etc/kernel/postinst.d/zz-devbox-kernel-readable"
        ),
    )


def parse_version(text: str) -> tuple[int, ...] | None:
    """Parse the leading dotted number of a version string, e.g. "v2.22.0-desktop.1" -> (2, 22, 0)."""
    match = re.match(r"v?(\d+(?:\.\d+)*)", text.strip())
    if match is None:
        return None
    return tuple(int(part) for part in match.group(1).split("."))


def _minimum_version(
    name: str,
    version: str,
    minimum: tuple[int, ...],
    fix: str,
    fix_command: str | None = None,
) -> CheckResult:
    required = ".".join(str(part) for part in minimum)
    parsed = parse_version(version)
    if parsed is None:
        return CheckResult(
            DOCKER,
            name,
            "warn",
            f"couldn't parse version {version!r} (need >= {required})",
        )
    if parsed < minimum:
        return CheckResult(
            DOCKER,
            name,
            "fail",
            f"{version} (need >= {required})",
            fix=fix,
            fix_command=fix_command,
        )
    return CheckResult(DOCKER, name, "ok", version)


def _device(
    path: Path,
    severity: CheckStatus,
    fix: str,
    fix_command: str | None = None,
    missing: str = "missing",
) -> CheckResult:
    if path.exists():
        return CheckResult(VIRTUALIZATION, path.as_posix(), "ok", "present")
    return CheckResult(
        VIRTUALIZATION,
        path.as_posix(),
        severity,
        missing,
        fix=fix,
        fix_command=fix_command,
    )


def _skip(group: str, name: str, reason: str) -> CheckResult:
    return CheckResult(group, name, "skip", reason)


def _skipped(group: str, names: list[str], reason: str) -> list[CheckResult]:
    return [_skip(group, name, reason) for name in names]


def _run(cmd: list[str]) -> subprocess.CompletedProcess[str] | None:
    """Run a command, returning `None` when its executable isn't installed."""
    try:
        return subprocess.run(
            cmd, capture_output=True, text=True, timeout=COMMAND_TIMEOUT, check=False
        )
    except FileNotFoundError:
        return None
    except subprocess.TimeoutExpired:
        return subprocess.CompletedProcess(
            cmd, returncode=-1, stdout="", stderr=f"timed out after {COMMAND_TIMEOUT}s"
        )


def _json_object(text: str) -> dict[str, Any]:
    try:
        value = json.loads(text)
    except json.JSONDecodeError:
        return {}
    return cast(dict[str, Any], value) if isinstance(value, dict) else {}


def _first_line(text: str) -> str:
    return next((line.strip() for line in text.splitlines() if line.strip()), "")

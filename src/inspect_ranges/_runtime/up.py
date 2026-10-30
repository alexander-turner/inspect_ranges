"""`inspect-ranges up`: realize a rendered bundle into a running, ready range (realizer-v1 slice 2).

The applier consumes a digest-verified bundle and nothing else: every manifest digest verifies before anything runs (mismatch, missing, or unlisted files refuse), then the render contract executes in order (hardened range container on the bundle's own compose project, guest overlays and seed ISOs, define and start per `boot.json`, wait on every readiness probe). Ownership registers before the first docker resource so teardown never depends on this process surviving. Every stage transition lands in the project's JSONL stage log; failures name their stage and guest; on readiness failure the affected guests' serial console logs are pulled into the project state directory before teardown (kept with `keep_on_failure`).
"""

import asyncio
import hashlib
import json
import logging
import os
import shlex
import subprocess
import time
from collections.abc import Callable
from ipaddress import IPv4Address
from pathlib import Path
from typing import Any, Literal, cast

import yaml
from pydantic import BaseModel, ConfigDict, Field, model_validator

from .._attackbox.attach import (
    ATTACH_HELPER_SOURCE,
    Attacher,
    AttachInvocation,
    attachment_from_boot,
    helper_config,
    run_attacher,
)
from .._attackbox.backend import (
    AttackBoxBackend,
    AttackBoxHandle,
    choose_attack_box,
    resolve_attack_box,
)
from .._attackbox.record import (
    AttackBoxRecord,
    AttackBoxRecordError,
    read_attack_box_record,
    record_timestamp,
    write_attack_box_record,
)
from .._channel.channel import MessageChannel, request_id
from .._channel.protocol import Budget, ExecRequest
from .._channel.vsock import HybridEndpoint, VsockTransport
from .._compiler.plan import GUEST_UID_BASE, guest_uid
from .ownership import (
    PROJECT_PREFIX,
    StageLog,
    default_state_dir,
    owner_record,
    prepare_ch_vsock_dir,
    project_dir,
    write_owner,
)
from .rangeimage import ensure_range_image

logger = logging.getLogger("inspect_ranges.up")

Runner = Callable[..., "subprocess.CompletedProcess[str]"]
"""Executes a command: `run(argv, env=None, input=None, timeout=None)`; injectable for tests. A runner must honor the timeout contract `run_command` sets: on expiry it returns rc 124 with the timeout named in stderr, never raises, so call sites surface the hang through their normal stage-named failure paths (an injected runner that ignores `timeout` silently reintroduces the unbounded hang the bound exists to prevent)."""

OnStage = Callable[[str, str, dict[str, Any]], None]
"""Mirrors every stage-log write as `(stage, status, fields)`; exceptions are logged and never alter `up`'s outcome. The mirror begins where the stage log does (after ownership registration); earlier failures surface as `UpError` only."""


IMAGE_BUILD_TIMEOUT_S = 1800.0
"""Bound on the one legitimately slow docker call (`ensure_range_image` builds the hypervisor image on first use); a wedged docker daemon surfaces as a stage-named `UpError` instead of hanging `up()` forever (quality-review B21)."""


def run_command(
    argv: list[str],
    env: dict[str, str] | None = None,
    input: str | None = None,
    timeout: float | None = None,
) -> "subprocess.CompletedProcess[str]":
    """The default runner: captured text output, no check.

    A `timeout` expiry returns rc 124 with the timeout named in stderr (never raises), so call sites surface it through their normal stage-named failure paths: `up()` must be internally bounded, since the provider's cancellation drain awaits it to completion (quality-review B21).
    """
    try:
        return subprocess.run(
            argv, capture_output=True, text=True, env=env, input=input, timeout=timeout
        )
    except subprocess.TimeoutExpired as expired:
        detail = expired.stderr
        stderr = (
            detail.decode(errors="replace") if isinstance(detail, bytes) else detail
        )
        return subprocess.CompletedProcess(
            argv,
            returncode=124,
            stdout="",
            stderr=f"timed out after {timeout:.0f}s: {stderr or ''}".strip(),
        )


class UpError(Exception):
    """Realization failure, naming the stage (and guest where one applies)."""

    def __init__(self, stage: str, message: str, guest: str | None = None) -> None:
        self.stage = stage
        self.guest = guest
        where = f"[{stage}]" + (f" guest {guest!r}:" if guest else "")
        super().__init__(f"{where} {message}")


class UpOptions(BaseModel):
    """Applier inputs. CIDs, addresses, and every artifact are bundle contents; these are host-side knobs only."""

    project: str | None = None
    image_cache: Path
    state_dir: Path = Field(default_factory=default_state_dir)
    readiness_timeout: float = 300.0
    readiness_min_window: float = 10.0
    keep_on_failure: bool = False
    uplink_network: str | None = None
    attack_box: str | None = None
    """An external attack-box backend origin (`attack_box_origin()`: the pinned default provider unless `INSPECT_RANGES_ATTACK_BOX` says otherwise), consulted where `up` runs: the plan's dedicated attack box is attached (taps in the range netns, fds handed over) and booted by the registered provider instead of locally. `None` (the value `builtin`) realizes the whole plan locally."""
    attack_box_is_default: bool = False
    """Whether `attack_box` is the unset default (`attack_box_is_default()`): the default steps aside for the built-in box when the bundle's attacker declares its own image (`choose_attack_box`)."""


class GuestState(BaseModel):
    """Per-guest outcome reported by `up`."""

    name: str
    cid: int
    ready: bool
    hybrid_vsock: HybridEndpoint | None = None
    """A Cloud Hypervisor guest's hybrid-vsock socket and the VMM uid its peer must have (`SO_PEERCRED`); `None` for QEMU guests, which are reached by CID."""


class UpResult(BaseModel):
    """What a successful `up` reports: the project and every guest ready."""

    project: str
    range_name: str
    guests: list[GuestState]
    seconds: float


def bundle_digest(bundle: Path) -> str:
    """The canonical bundle digest: sha256 of `manifest.json` bytes (`range-host-v1.md`).

    Render emits the manifest deterministically, so the digest is stable per spec and options; it is what `RealizeRequest.bundle_digest` names and what the applier verifies before acting.

    Raises:
        UpError: The bundle has no readable manifest.
    """
    try:
        return hashlib.sha256((bundle / "manifest.json").read_bytes()).hexdigest()
    except OSError as error:
        raise UpError(
            "verify-bundle", f"{bundle} has no readable manifest.json: {error}"
        ) from error


def verify_bundle(bundle: Path, expected_digest: str | None = None) -> dict[str, Any]:
    """Verify every manifest digest and that nothing unlisted is present; returns the manifest.

    With `expected_digest`, the bundle's canonical digest (sha256 of the manifest bytes) must match before anything else is checked: the applier refuses a bundle other than the one the driver named.

    Raises:
        UpError: Any missing, unreadable, mismatched, unlisted, or symlinked file, a malformed manifest, a required render file absent from the manifest (all reported at once), or a canonical-digest mismatch; acting on an unverified bundle is never attempted.
    """
    manifest_path = bundle / "manifest.json"
    if not manifest_path.is_file():
        raise UpError("verify-bundle", f"{bundle} has no manifest.json")
    # one read: the digest-verified bytes ARE the bytes parsed and acted on
    try:
        manifest_bytes = manifest_path.read_bytes()
    except OSError as error:
        raise UpError(
            "verify-bundle", f"{bundle} has no readable manifest.json: {error}"
        ) from error
    if expected_digest is not None:
        actual = hashlib.sha256(manifest_bytes).hexdigest()
        if actual != expected_digest:
            raise UpError(
                "verify-bundle",
                f"bundle digest {actual} does not match the requested {expected_digest}",
            )
    try:
        parsed: object = json.loads(manifest_bytes)
        if not isinstance(parsed, dict):
            raise ValueError("manifest is not a JSON object")
        manifest = cast(dict[str, Any], parsed)
        raw_files: object = manifest["files"]
        range_name: object = manifest["range"]
        spec_sha: object = manifest["spec_sha256"]
        if not (
            isinstance(raw_files, dict)
            and isinstance(range_name, str)
            and range_name
            and isinstance(spec_sha, str)
            and spec_sha
        ):
            raise ValueError("manifest fields have the wrong shape")
        files = cast(dict[str, Any], raw_files)
    except (OSError, ValueError, KeyError, TypeError) as error:
        raise UpError(
            "verify-bundle", f"manifest.json is unreadable or malformed: {error}"
        ) from error
    bundle_root = bundle.resolve()
    failures: list[str] = []
    for required in ("boot.json", "compose.yaml", "plan.json"):
        if required not in files:
            failures.append(f"{required}: required render file not listed in manifest")
    for relative, meta in files.items():
        member = Path(relative)
        # member names must stay inside the bundle: traversal or absolute
        # names would hash arbitrary host files (and the mismatch error would
        # become a digest oracle for them)
        if (
            member.is_absolute()
            or ".." in member.parts
            or not (bundle_root / member).resolve().is_relative_to(bundle_root)
        ):
            failures.append(f"{relative}: escapes the bundle root")
            continue
        if not isinstance(meta, dict):
            failures.append(f"{relative}: manifest entry is not an object")
            continue
        meta_dict = cast(dict[str, Any], meta)
        path = bundle / relative
        if not path.is_file():
            failures.append(f"{relative}: missing")
            continue
        try:
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
        except OSError as error:
            failures.append(f"{relative}: unreadable ({error})")
            continue
        if digest != meta_dict.get("sha256"):
            failures.append(f"{relative}: sha256 mismatch")
    listed = set(files) | {"manifest.json"}
    on_disk: set[str] = set()
    for path in bundle.rglob("*"):
        relative = str(path.relative_to(bundle))
        if path.is_symlink():
            # the container applies /render by its own resolution: host-side
            # verification of a symlink target is not verification of what is
            # applied, so symlinks are refused outright
            failures.append(f"{relative}: symlink (not allowed in a bundle)")
        elif path.is_file():
            on_disk.add(relative)
    failures.extend(f"{extra}: not in manifest" for extra in sorted(on_disk - listed))
    if failures:
        raise UpError(
            "verify-bundle",
            "bundle fails verification:\n  " + "\n  ".join(failures),
        )
    return manifest


_SAFE_NAME = r"^[A-Za-z0-9][A-Za-z0-9_.-]*$"


class BootInterface(BaseModel):
    """One Cloud Hypervisor guest NIC: the range bridge its tap joins and the MAC its netplan matches.

    An attacker entry additionally carries the allocated address facts (ip, prefixlen, gateway): descriptive plan facts a deployment-selected external attack-box provider consumes at realize time, absent for every other guest.
    """

    model_config = ConfigDict(extra="forbid")

    bridge: str = Field(pattern=_SAFE_NAME, max_length=15)
    mac: str = Field(pattern=r"^[0-9a-f]{2}(:[0-9a-f]{2}){5}$")
    network: str | None = Field(default=None, pattern=_SAFE_NAME)
    ip: IPv4Address | None = None
    prefixlen: int | None = Field(default=None, ge=0, le=32)
    gateway: IPv4Address | None = None


class BootGuest(BaseModel):
    """One guest in `boot.json`, shape-validated before anything interpolates it anywhere."""

    model_config = ConfigDict(extra="forbid")

    name: str = Field(pattern=_SAFE_NAME)
    kind: Literal["host", "router", "attacker"] = "host"
    cid: int = Field(ge=3, le=99_999_999)
    image_file: str = Field(pattern=_SAFE_NAME)
    image_digest: str | None = None
    backing_file: str | None = Field(default=None, pattern=_SAFE_NAME)
    """A realized overlay's backing golden in the cache; verified at boot like the overlay itself (round-2 review: the overlay digest cannot see its backing, and goldens re-derive in place under the same name)."""
    backing_digest: str | None = None
    overlay_gb: int = Field(ge=1)
    readiness: Literal["cloud-init", "daemon"]
    injector: Literal["cloud-init", "unattend"] = "cloud-init"
    vmm: Literal["qemu", "cloud-hypervisor"] = "qemu"
    cpus: int | None = Field(default=None, ge=1)
    memory_mb: int | None = Field(default=None, ge=64)
    interfaces: list[BootInterface] = []

    @model_validator(mode="after")
    def _check_vmm_fields(self) -> "BootGuest":
        sized = self.cpus is not None and self.memory_mb is not None
        if self.vmm == "cloud-hypervisor" and not sized:
            raise ValueError(
                f"cloud-hypervisor guest {self.name!r} needs cpus and memory_mb"
            )
        return self


class BootPlan(BaseModel):
    """`boot.json` as the applier consumes it; unknown keys or shapes refuse."""

    model_config = ConfigDict(extra="forbid")

    parallel: bool
    guests: list[BootGuest] = Field(min_length=1)
    verify: dict[str, Any]


def load_boot(bundle: Path) -> BootPlan:
    """Parse and shape-validate the bundle's `boot.json`.

    Raises:
        UpError: The file is unreadable or its shape does not match what render emits.
    """
    try:
        return BootPlan.model_validate_json((bundle / "boot.json").read_text())
    except (OSError, ValueError) as error:
        raise UpError(
            "verify-bundle", f"boot.json is unreadable or malformed: {error}"
        ) from error


CH_UID_BASE = GUEST_UID_BASE
"""Alias of `GUEST_UID_BASE` (the per-guest uid scheme now covers QEMU guests too, via the DAC seclabel): a host-side dialer's `SO_PEERCRED` check names exactly one VMM."""
CH_BINARY = "/usr/local/bin/cloud-hypervisor"
CH_FIRMWARE = "/usr/local/share/cloud-hypervisor/firmware.fd"
CH_VSOCK_MOUNT = "/run/ch-vsock"
"""Where the range container sees the host directory holding Cloud Hypervisor guests' vsock sockets (compose's `CH_VSOCK_DIR`)."""


def ch_uid(cid: int) -> int:
    """The uid the guest's VMM runs as (`guest_uid`; the name predates QEMU joining the scheme)."""
    return guest_uid(cid)


def boot_script(boot: BootPlan, skip: frozenset[str] = frozenset()) -> str:
    """The in-container realization script for `boot.json` (overlays, seeds, define, start). Every interpolated value is shape-validated by `BootPlan` and shell-quoted anyway.

    A `cloud-hypervisor` guest has no domain XML: root prepares what the unprivileged VMM cannot (a persistent tap per NIC owned by the VMM's uid, image and console-log ownership), then Cloud Hypervisor starts as its own uid (`ch_uid`) with group `kvm`, no capabilities and its default seccomp filter, detached, its vsock socket in the host-supplied directory.

    `skip` names guests realized by an external provider (the attack box behind `INSPECT_RANGES_ATTACK_BOX`): they keep their boot entry (addressing facts, readiness) but this script touches nothing for them. Empty by default, so the script is byte-identical to the pre-seam output.
    """
    lines = ["#!/bin/bash", "set -euo pipefail"]
    ch_guests: list[str] = []
    for guest in boot.guests:
        if guest.name in skip:
            continue
        name = shlex.quote(guest.name)
        image = shlex.quote(guest.image_file)
        lines.append(
            f"qemu-img create -f qcow2 -F qcow2 -b /images/{image} "
            f"/scratch/{name}.qcow2 {guest.overlay_gb}G >/dev/null"
        )
        if guest.injector == "unattend":
            # a windows guest's seed is a plain ISO with the per-boot answer
            # file at its root (the implicit specialize search reads it from
            # removable media); -J keeps the 8.3-unfriendly name intact
            lines.append(
                f"genisoimage -quiet -o /scratch/{name}-seed.iso -J -R "
                f"/render/guests/{name}/seed/unattend.xml"
            )
        else:
            lines.append(
                f"cloud-localds -N /render/guests/{name}/seed/network-config "
                f"/scratch/{name}-seed.iso "
                f"/render/guests/{name}/seed/user-data /render/guests/{name}/seed/meta-data"
            )
        if guest.vmm == "qemu":
            # the DAC seclabel runs this QEMU as its own uid with relabel off
            # (issue #5): root pre-owns the files the unprivileged VMM opens
            uid = guest_uid(guest.cid)
            lines.append(
                f"chown {uid}:kvm /scratch/{name}.qcow2 /scratch/{name}-seed.iso"
            )
            lines.append(
                f"install -o {uid} -g kvm -m 0640 /dev/null /scratch/console/{name}.log"
            )
            lines.append(
                f"virsh -c qemu:///system define /render/guests/{name}/domain.xml >/dev/null"
            )
            lines.append(f"virsh -c qemu:///system start {name} >/dev/null")
            continue
        if not ch_guests:
            lines.append("install -d -m 0755 /scratch/ch")
        ch_guests.append(name)
        uid = ch_uid(guest.cid)
        lines.append(f"chown {uid}:kvm /scratch/{name}.qcow2 /scratch/{name}-seed.iso")
        # the VMM cannot create files in the root-owned console dir: hand it its log
        lines.append(
            f"install -o {uid} -g kvm -m 0640 /dev/null /scratch/console/{name}.log"
        )
        nets: list[str] = []
        for index, interface in enumerate(guest.interfaces):
            tap = f"ch{guest.cid}n{index}"  # CID-derived: unique per host, within IFNAMSIZ
            lines.append(f"ip tuntap add dev {tap} mode tap user {uid} group kvm")
            # libvirt's tap MAC rule (guest MAC, first octet 0xfe): the bridge
            # adopts its lowest port MAC, and a random tap MAC would leak onto
            # the segment in the bridge's own frames, unlike QEMU ranges
            lines.append(f"ip link set {tap} address fe{interface.mac[2:]}")
            lines.append(f"ip link set {tap} master {shlex.quote(interface.bridge)}")
            lines.append(f"ip link set {tap} up")
            nets.append(f"tap={tap},mac={interface.mac}")
        socket = f"{CH_VSOCK_MOUNT}/{name}.sock"
        argv = [
            CH_BINARY,
            "--firmware",
            CH_FIRMWARE,
            "--cpus",
            f"boot={guest.cpus}",
            "--memory",
            f"size={guest.memory_mb}M",
            "--disk",
            f"path=/scratch/{name}.qcow2,image_type=qcow2,backing_files=on",
            f"path=/scratch/{name}-seed.iso,image_type=raw,readonly=on",
            *(["--net", *nets] if nets else []),
            "--vsock",
            f"cid={guest.cid},socket={socket}",
            "--serial",
            f"file=/scratch/console/{name}.log",
            "--console",
            "off",
            "--rng",
            "src=/dev/urandom",
        ]
        lines.append(f"rm -f {socket}")
        lines.append(
            f"(exec setsid setpriv --reuid={uid} --regid=kvm "
            f"--clear-groups {' '.join(argv)} </dev/null "
            f">/scratch/ch/{name}.log 2>&1) &"
        )
        lines.append(f"echo $! > /scratch/ch/{name}.pid")
    if ch_guests:
        # a VMM that refuses its configuration never creates its socket: fail
        # the boot stage with its own error rather than timing out at readiness
        for name in ch_guests:
            socket = f"{CH_VSOCK_MOUNT}/{name}.sock"
            lines.append(
                f"for _ in $(seq 50); do [ -S {socket} ] && break; sleep 0.1; done"
            )
            lines.append(
                f"[ -S {socket} ] || {{ echo 'cloud-hypervisor for {name} did not start:' >&2; "
                f"tail -5 /scratch/ch/{name}.log >&2; exit 1; }}"
            )
            # Cloud Hypervisor creates the socket 0700 whatever the umask; the
            # host-side dialer runs as a uid this container does not know, so
            # open it up here: the host directory's private root bounds access
            lines.append(f"chmod 0666 {socket}")
    return "\n".join(lines) + "\n"


class _StageTee:
    """Mirrors every stage-log write to an optional `OnStage` callback.

    The JSONL write happens first and identically (the tee passes arguments through verbatim), so the stage log stays byte-identical with or without a callback; a raising callback is logged and ignored, never altering `up`'s outcome.
    """

    def __init__(self, log: StageLog, on_stage: OnStage | None) -> None:
        self._log = log
        self._on_stage = on_stage

    def log(self, stage: str, status: str, **fields: Any) -> None:
        self._log.log(stage, status, **fields)
        if self._on_stage is None:
            return
        try:
            self._on_stage(stage, status, dict(fields))
        except Exception:
            logger.exception("on_stage callback failed (ignored)")


CLOUD_INIT_PROBE = ["sh", "-c", "cloud-init status --wait >/dev/null 2>&1"]
"""The readiness exec: the exit status of `cloud-init status --wait` IS the signal (0 done; nonzero error or degraded, both meaning the declared configuration did not fully apply)."""


def make_channel(
    cids: "dict[str, int]", hybrid_sockets: "dict[str, HybridEndpoint] | None" = None
) -> MessageChannel:
    """The readiness channel to this range's guests (a test seam; built inside the event loop).

    The per-round-trip allowance is readiness-tuned: a daemon that accepts but never replies must cost seconds per attempt, not the channel's long default, or one wedged guest overshoots the whole readiness budget. Long cloud-init waits stay fine: exec liveness rides pending polls, each bounded by this allowance.

    `expected_unready` logs this channel's retries and loss dumps at INFO: a daemon not yet listening is the normal state of a booting guest, and a warning the user can do nothing about reads as a defect. Readiness outcomes still surface through the stage stream; tamper verdicts stay ERROR.
    """
    return MessageChannel(
        VsockTransport(cids, hybrid_sockets=hybrid_sockets),
        label="up-readiness",
        channel_budget_s=10.0,
        expected_unready=True,
    )


async def _await_ready(
    channel: MessageChannel,
    guest: str,
    readiness: str,
    deadline: float,
    min_window: float = 10.0,
) -> tuple[bool, str | None]:
    """One guest's readiness and, when unready, the swallowed cause for the stage log: daemon answering, then the cloud-init gate; any failure or malformed behavior is not-ready, never an escape."""
    while True:
        try:
            await channel.ping(guest)
            break
        except Exception as error:
            if time.monotonic() >= deadline:
                return False, f"daemon never answered: {error!r}"
            await asyncio.sleep(1.0)
    if readiness == "cloud-init":
        remaining_ms = max(
            int(min_window * 1000), int((deadline - time.monotonic()) * 1000)
        )
        try:
            outcome = await channel.exec(
                guest,
                ExecRequest(
                    id=request_id(),
                    cmd=CLOUD_INIT_PROBE,
                    budget=Budget(command_ms=min(remaining_ms, 3_600_000)),
                ),
            )
            if outcome.rc == 0:
                return True, None
            return False, f"cloud-init status --wait exited {outcome.rc}"
        except Exception as error:
            return False, f"readiness exec failed: {error!r}"
    return True, None


def project_containers(
    runner: Runner, project: str, *, running_only: bool = False
) -> list[str]:
    """Container ids carrying the project's compose label (live or exited by default; `running_only` narrows to running ones, the oracle attach's liveness question)."""
    result = runner(
        [
            "docker",
            "ps",
            *([] if running_only else ["-a"]),
            "-q",
            "--filter",
            f"label=com.docker.compose.project={project}",
        ]
    )
    return [line for line in result.stdout.splitlines() if line.strip()]


def _compose_argv(project: str, bundle: Path, *args: str) -> list[str]:
    return [
        "docker",
        "compose",
        "--project-name",
        project,
        "--project-directory",
        str(bundle),
        *args,
    ]


def _declared_attacker_image(bundle: Path) -> str | None:
    """The image the bundle's range declares for its attacker (`spec.yaml`, digest-verified with the bundle); `None` when it takes the default."""
    spec: Any = yaml.safe_load((bundle / "spec.yaml").read_text())
    attacker: Any = spec.get("attacker") or {}
    image: Any = attacker.get("image")
    return image if isinstance(image, str) else None


def _external_attack_box(
    options: UpOptions, boot: BootPlan, bundle: Path
) -> tuple[BootGuest | None, AttackBoxBackend | None]:
    """Resolve the external attack box, when one is configured: the attacker entry the provider realizes plus its backend bundle.

    Resolution happens before any docker resource exists (the provider-runtime pattern: an unresolvable value refuses the whole realize, fast). A foothold range has no dedicated attack box and realizes normally with one INFO line; a bundle from before the attack-box facts refuses with a re-render message rather than silently booting the box locally.

    Raises:
        UpError: The backend does not resolve (`attack-box`), or the bundle cannot carry an external box (`verify-bundle`: pre-facts bundle, or an explicit non-cloud-hypervisor attacker, whose compose output lacks the shared socket mount).
    """
    if options.attack_box is None:
        return None, None
    try:
        backend = resolve_attack_box(options.attack_box, options.state_dir)
    except ValueError as error:
        raise UpError("attack-box", str(error)) from error
    if backend.capabilities.console_stream:
        raise UpError(
            "attack-box",
            "the backend declares console_stream=True, which is not supported "
            "(no ingest path exists for a provider console stream); declare "
            "False and let the drop land as a declared evidence gap",
        )
    external = next((g for g in boot.guests if g.kind == "attacker"), None)
    if external is None:
        raw = json.loads((bundle / "boot.json").read_text())
        if any("kind" not in entry for entry in raw.get("guests", [])):
            raise UpError(
                "verify-bundle",
                "an external attack box is configured (INSPECT_RANGES_ATTACK_BOX) "
                "but this bundle predates attack-box facts (guests carry no "
                "kind); re-render the bundle, or set "
                "INSPECT_RANGES_ATTACK_BOX=builtin",
            )
        logger.info(
            "attack-box backend configured but the range has no dedicated "
            "attack box (foothold range); realizing normally"
        )
        return None, None
    if external.vmm != "cloud-hypervisor":
        raise UpError(
            "verify-bundle",
            f"an external attack box requires the attack box planned under "
            f"cloud-hypervisor (the default), but {external.name!r} declares "
            f"vmm: {external.vmm}; remove the attacker's vmm or set "
            "INSPECT_RANGES_ATTACK_BOX=builtin",
        )
    if any(
        nic.network is None or nic.ip is None or nic.prefixlen is None
        for nic in external.interfaces
    ):
        raise UpError(
            "verify-bundle",
            f"attacker entry {external.name!r} carries no address facts "
            "(bundle rendered before attack-box support); re-render the bundle",
        )
    return external, backend


def up(
    bundle: Path,
    options: UpOptions,
    runner: Runner | None = None,
    *,
    on_stage: OnStage | None = None,
    attacher: Attacher | None = None,
) -> UpResult:
    """Realize a verified bundle; returns the project name and per-guest state.

    `on_stage` mirrors every stage-log write (the applier's stage-translation hook); it never alters the log or the outcome.

    Raises:
        UpError: Stage-named failure (`verify-bundle`, `prepare`, `verify-images`, `range-image`, `range-container`, `guest-boot`, `readiness`), with per-guest diagnostics on readiness failures. Unless `keep_on_failure`, a failed `up` tears its project down before raising (state and console logs are kept for diagnosis).
    """
    run: Runner = runner or run_command
    started = time.monotonic()
    bundle = bundle.resolve()
    # compose's short volume syntax reads a relative path as a named volume,
    # so the cache the environment hands the project must be absolute and the
    # same one verify-images checked
    options = options.model_copy(update={"image_cache": options.image_cache.resolve()})

    manifest = verify_bundle(bundle)
    boot = load_boot(bundle)
    range_name = cast(str, manifest["range"])
    spec_sha = cast(str, manifest["spec_sha256"])
    project = options.project or f"{PROJECT_PREFIX}{range_name}-{spec_sha[:12]}"

    if project_containers(run, project):
        raise UpError(
            "prepare",
            f"project {project!r} is already running; refusing to supersede. "
            f"Tear it down first: inspect-ranges down {project}",
        )

    guests = boot.guests
    builtin_reason: str | None = None
    if options.attack_box is not None and options.attack_box_is_default:
        choice = choose_attack_box(
            options.attack_box,
            default=True,
            declared_image=_declared_attacker_image(bundle),
        )
        if choice.origin is None:
            builtin_reason = choice.reason
            logger.info("attack box for %s: %s", project, builtin_reason)
            # no attack-box record follows, so down tears the box down as
            # the built-in guest it is
            options = options.model_copy(update={"attack_box": None})
    external, attack_backend = _external_attack_box(options, boot, bundle)
    booted = [g.name for g in guests if external is None or g.name != external.name]
    vendor_memo: dict[str, str] = {}

    def verify_vendor_edge(image_file: str, guest_name: str) -> None:
        # the golden-to-vendor edge (round-3 distribution review B4): a golden
        # whose provenance sidecar names a vendor must sit over exactly those
        # vendor bytes, or QEMU would silently read a mixed chain (an
        # interrupted refresh, a re-pulled vendor) that no build verified
        sidecar = options.image_cache / (image_file.removesuffix(".qcow2") + ".json")
        if not sidecar.is_file():
            return
        try:
            meta = json.loads(sidecar.read_text())
            vendor_file = meta.get("vendor_file")
            vendor_sha = meta.get("vendor_sha256")
        except (OSError, ValueError):
            return  # a corrupt sidecar is the derive path's concern, not boot's
        if not isinstance(vendor_file, str) or not isinstance(vendor_sha, str):
            return
        vendor = options.image_cache / vendor_file
        if not vendor.is_file():
            raise UpError(
                "verify-images",
                f"vendor base {vendor_file} backing {image_file} is not in the cache; "
                "re-derive the golden or re-pull the image chain",
                guest=guest_name,
            )
        if vendor_file not in vendor_memo:
            vendor_memo[vendor_file] = _sha256(vendor)
        if vendor_memo[vendor_file] != vendor_sha:
            raise UpError(
                "verify-images",
                f"vendor base {vendor_file} hashes {vendor_memo[vendor_file][:12]}..., but "
                f"{image_file}'s provenance records {vendor_sha[:12]}...: the chain is mixed "
                "(a vendor refresh under an older golden, or an interrupted image refresh); "
                "refresh or re-derive the golden so the chain agrees",
                guest=guest_name,
            )

    for guest in guests:
        if external is not None and guest.name == external.name:
            continue  # the provider brings its own box; its image is never booted here
        image = options.image_cache / guest.image_file
        if not image.is_file():
            raise UpError(
                "verify-images",
                f"image {guest.image_file} is not in the cache {options.image_cache}",
                guest=guest.name,
            )
        if guest.image_digest is not None:
            actual = f"sha256:{_sha256(image)}"
            if actual != guest.image_digest:
                raise UpError(
                    "verify-images",
                    f"image {guest.image_file} digest {actual} does not match the bundle's {guest.image_digest}: "
                    "the cache's copy changed since this bundle was rendered (an image re-derive, update, or build); "
                    "re-render the bundle",
                    guest=guest.name,
                )
        if guest.backing_file is not None:
            backing = options.image_cache / guest.backing_file
            if not backing.is_file():
                raise UpError(
                    "verify-images",
                    f"backing golden {guest.backing_file} for {guest.image_file} is not in the cache {options.image_cache}; "
                    "re-derive the golden or pull the build artifacts",
                    guest=guest.name,
                )
            if guest.backing_digest:
                actual = f"sha256:{_sha256(backing)}"
                if actual != guest.backing_digest:
                    raise UpError(
                        "verify-images",
                        f"backing golden {guest.backing_file} digest {actual} does not match the build's {guest.backing_digest}: "
                        "the golden was re-derived or refreshed since the build, so the realized overlay would boot over a "
                        "composition no build verified; rebuild the range (builders), or re-pull the matching build / pin it "
                        "by digest (consumers)",
                        guest=guest.name,
                    )
            verify_vendor_edge(guest.backing_file, guest.name)
        else:
            verify_vendor_edge(guest.image_file, guest.name)

    try:
        range_image = ensure_range_image(
            lambda argv: run(argv, timeout=IMAGE_BUILD_TIMEOUT_S)
        )
    except Exception as error:
        raise UpError("range-image", str(error)) from error

    # ownership registers before the first compose resource (cleanup registry)
    write_owner(options.state_dir, owner_record(project, range_name, spec_sha, bundle))
    # the verified boot plan is recorded beside the owner record: the
    # out-of-band oracle attach (`range_oracle("<project>")`) rebuilds the
    # guest channel from it, and the bundle itself may be temporary
    # (`up --from-spec` renders into a TemporaryDirectory that is gone by
    # the time anything attaches)
    (project_dir(options.state_dir, project) / "boot.json").write_bytes(
        (bundle / "boot.json").read_bytes()
    )
    if external is not None:
        # a surviving record may hold a LIVE box's reclaim token (a prior run
        # whose containers vanished without a down); overwriting it with an
        # empty token would strand that box forever, the exact failure the
        # record discipline exists to prevent, so refuse like the
        # duplicate-project guard and let down reclaim deny-first
        try:
            stale = read_attack_box_record(options.state_dir, project)
        except AttackBoxRecordError as error:
            raise UpError("attack-box", str(error)) from error
        if stale is not None:
            raise UpError(
                "attack-box",
                f"project {project!r} already has an attack-box record (a "
                "prior run's external box may still be live); tear it down "
                f"first: inspect-ranges down {project}",
            )
        # before the provider boots anything (the owner-record discipline): a
        # crash in the window reclaims a provider no-op, which teardown
        # idempotency absorbs
        write_attack_box_record(
            options.state_dir,
            AttackBoxRecord(
                origin=cast(str, options.attack_box),
                project=project,
                guest_name=external.name,
                cid=external.cid,
                created=record_timestamp(),
            ),
        )
    log = _StageTee(StageLog(options.state_dir, project), on_stage)
    if builtin_reason is not None:
        log.log("attack-box", "ok", box="builtin", reason=builtin_reason)
    log.log("verify-bundle", "ok", files=len(cast(dict[str, Any], manifest["files"])))
    log.log("verify-images", "ok", guests=len(booted))
    log.log("range-image", "ok", tag=range_image)

    env = dict(os.environ)
    # the hardened image is hard-required: no compose-env override survives
    # (the digest-pinned INSPECT_RANGES_RANGE_IMAGE knob resolves inside
    # ensure_range_image, never here)
    env["RANGE_IMAGE"] = range_image
    env["IMAGE_CACHE"] = str(options.image_cache)
    if options.uplink_network is not None:
        env["UPLINK_NETWORK"] = options.uplink_network

    def fail(
        stage: str,
        message: str,
        guest: str | None = None,
        consoles: list[str] | None = None,
    ) -> UpError:
        log.log(stage, "fail", error=message, **({"guest": guest} if guest else {}))
        if consoles:
            # teardown removes the scratch volume holding the serial logs:
            # pull them first, they are the first artifact of boot debugging
            _pull_consoles(run, project, bundle, env, options, consoles)
        if not options.keep_on_failure:
            from .down import down as teardown

            try:
                teardown(
                    project, state_dir=options.state_dir, runner=run, keep_state=True
                )
            except Exception as teardown_error:
                # the diagnosed failure stays primary; a sick docker daemon
                # during cleanup is appended, never substituted
                log.log("teardown", "fail", error=str(teardown_error))
                message = (
                    f"{message} (teardown also failed, project left behind: "
                    f"{teardown_error}; retry with: inspect-ranges down {project})"
                )
        return UpError(stage, message, guest=guest)

    ch_dir: Path | None = None
    if any(guest.vmm == "cloud-hypervisor" for guest in guests):
        try:
            ch_dir = prepare_ch_vsock_dir(project)
        except OSError as error:
            # through fail(): the stage-log line and the owner-record teardown
            # match every other post-ownership failure (round-1 review)
            raise fail(
                "range-container",
                f"cannot prepare the cloud-hypervisor vsock dir: {error}",
            ) from error
        env["CH_VSOCK_DIR"] = str(ch_dir)

    log.log("range-container", "start")
    result = run(
        _compose_argv(
            project,
            bundle,
            "up",
            "-d",
            "--wait",
            "--wait-timeout",
            str(int(options.readiness_timeout)),
        ),
        env=env,
        timeout=options.readiness_timeout + 60.0,
    )
    if result.returncode != 0:
        raise fail(
            "range-container", f"compose up failed: {result.stderr.strip()[-800:]}"
        )
    log.log("range-container", "ok")

    # each VMM's uid follows from its CID in boot.json (`ch_uid`); host-side
    # dialers refuse any socket whose peer is not that one uid
    ch_sockets: dict[str, HybridEndpoint] = {}
    if ch_dir is not None:
        ch_sockets = {
            guest.name: HybridEndpoint(ch_dir / f"{guest.name}.sock", ch_uid(guest.cid))
            for guest in guests
            if guest.vmm == "cloud-hypervisor"
            and (external is None or guest.name != external.name)
        }

    log.log("guest-boot", "start", guests=booted)
    boot_result = run(
        _compose_argv(project, bundle, "exec", "-T", "range", "bash", "-s"),
        env=env,
        input=boot_script(
            boot,
            skip=frozenset({external.name}) if external is not None else frozenset(),
        ),
        timeout=options.readiness_timeout,
    )
    if boot_result.returncode != 0:
        raise fail(
            "guest-boot",
            f"guest boot failed: {boot_result.stderr.strip()[-800:]} "
            f"(consoles of already-booted guests under {project_dir(options.state_dir, project) / 'consoles'})",
            consoles=booted,
        )
    log.log("guest-boot", "ok")

    if external is not None and attack_backend is not None:
        # the external attacker is cloud-hypervisor-planned (checked above), so
        # the shared socket dir was prepared and is mounted in the container
        assert ch_dir is not None
        log.log("attach", "start", guest=external.name)
        config = helper_config(
            external, container_socket=f"{CH_VSOCK_MOUNT}/{external.name}-attach.sock"
        )
        invocation = AttachInvocation(
            argv=_compose_argv(
                project,
                bundle,
                "exec",
                "-T",
                "range",
                "python3",
                "-",
                json.dumps(config),
            ),
            env=env,
            source=ATTACH_HELPER_SOURCE,
            host_socket=ch_dir / f"{external.name}-attach.sock",
            expected_fds=len(external.interfaces),
        )
        try:
            fds = (attacher or run_attacher)(invocation)
        except Exception as error:
            raise fail(
                "attach",
                f"attack-box attachment failed: {error}",
                guest=external.name,
                consoles=booted,
            ) from error
        log.log("attach", "ok", guest=external.name, taps=len(fds))

        seed_dir = bundle / "guests" / external.name / "seed"
        try:
            attachment = attachment_from_boot(
                external,
                project=project,
                fds=fds,
                seed_dir=seed_dir if seed_dir.is_dir() else None,
            )
        except ValueError as error:
            # unreachable while _external_attack_box pre-checks the facts, but
            # a raw escape here would skip the stage log and the teardown
            for fd in fds:
                os.close(fd)
            raise fail("attach", str(error), guest=external.name) from error
        log.log("attack-box", "start", guest=external.name)

        async def boot_box() -> "AttackBoxHandle":
            # bounded like every other boot phase (B21): a provider that never
            # returns must fail the stage, not wedge the sample
            return await asyncio.wait_for(
                attack_backend.provider.boot(attachment),
                timeout=options.readiness_timeout,
            )

        try:
            # the provider owns the fds from this call on (it may already have
            # handed them to a VMM process), so no close here on failure; a
            # failed up tears the project down, and the taps die with the netns
            handle = asyncio.run(boot_box())
        except Exception as error:
            try:
                # best-effort reclaim of a half-boot; teardown is idempotent
                # and half-boot-tolerant by contract
                asyncio.run(attack_backend.provider.teardown(project, ""))
            except Exception:
                logger.exception("attack-box teardown after a failed boot failed")
            raise fail(
                "attack-box",
                f"external attack box boot failed: {error}",
                guest=external.name,
                consoles=booted,
            ) from error
        log.log("attack-box", "ok", guest=external.name)
        ch_sockets[external.name] = handle.exec_endpoint
        try:
            record = read_attack_box_record(options.state_dir, project)
            if record is None:
                # absent is exactly as untrustworthy as unreadable here: the
                # record this very up wrote is gone (a concurrent sweep), so
                # a success would leave a live box with no teardown trail
                raise AttackBoxRecordError(
                    f"the attack-box record for {project} vanished during the "
                    "provider boot (a concurrent down or sweep?)"
                )
        except AttackBoxRecordError as error:
            # nothing about this project's teardown can be trusted, so fail
            # while the in-process backend can still reclaim directly
            try:
                asyncio.run(attack_backend.provider.teardown(project, ""))
            except Exception:
                logger.exception("attack-box teardown after a record fault failed")
            raise fail("attack-box", str(error), guest=external.name) from error
        write_attack_box_record(
            options.state_dir,
            record.model_copy(
                update={
                    "reclaim_token": handle.reclaim_token,
                    "exec_socket": str(handle.exec_endpoint.path),
                    "exec_uid": handle.exec_endpoint.peer_uid,
                }
            ),
        )

    async def _readiness() -> list[GuestState]:
        channel = make_channel({g.name: g.cid for g in guests}, ch_sockets)
        deadline = time.monotonic() + options.readiness_timeout
        collected: list[GuestState] = []
        for guest in guests:
            log.log("readiness", "start", guest=guest.name, cid=guest.cid)
            # a hung guest must not consume later guests' diagnostics: every
            # guest gets a minimum probe window even after the shared deadline
            # passes, so the failure report names only genuinely unready guests
            guest_deadline = max(
                deadline, time.monotonic() + options.readiness_min_window
            )
            # an external box's bar here is daemon liveness only (ping over its
            # exec surface); the conformance battery holds the deeper bar
            readiness = (
                "daemon"
                if external is not None and guest.name == external.name
                else guest.readiness
            )
            ready, cause = await _await_ready(
                channel,
                guest.name,
                readiness,
                guest_deadline,
                min_window=options.readiness_min_window,
            )
            collected.append(
                GuestState(
                    name=guest.name,
                    cid=guest.cid,
                    ready=ready,
                    hybrid_vsock=ch_sockets.get(guest.name),
                )
            )
            log.log(
                "readiness",
                "ok" if ready else "fail",
                guest=guest.name,
                **({"cause": cause} if cause else {}),
            )
        return collected

    states = asyncio.run(_readiness())
    failed = [state.name for state in states if not state.ready]
    if failed:
        raise fail(
            "readiness",
            f"guests not ready within {options.readiness_timeout:.0f}s: {', '.join(failed)} "
            f"(console logs under {project_dir(options.state_dir, project) / 'consoles'})",
            guest=failed[0],
            consoles=[
                name for name in failed if external is None or name != external.name
            ],
        )

    log.log("ready", "ok", seconds=round(time.monotonic() - started, 1))
    return UpResult(
        project=project,
        range_name=range_name,
        guests=states,
        seconds=round(time.monotonic() - started, 1),
    )


def _pull_consoles(
    run: Runner,
    project: str,
    bundle: Path,
    env: dict[str, str],
    options: UpOptions,
    guests: list[str],
) -> None:
    """Copy failed guests' serial console logs into the project state dir (best effort)."""
    destination = project_dir(options.state_dir, project) / "consoles"
    destination.mkdir(parents=True, exist_ok=True)
    for name in guests:
        run(
            _compose_argv(
                project,
                bundle,
                "cp",
                f"range:/scratch/console/{name}.log",
                str(destination / f"{name}.log"),
            ),
            env=env,
            timeout=60.0,  # best-effort against a possibly wedged daemon
        )


def _sha256(path: Path) -> str:
    hasher = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 22), b""):
            hasher.update(chunk)
    return hasher.hexdigest()

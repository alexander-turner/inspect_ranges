"""`inspect-ranges up`: realize a rendered bundle into a running, ready range (realizer-v1 slice 2).

The applier consumes a digest-verified bundle and nothing else: every manifest digest verifies before anything runs (mismatch, missing, or unlisted files refuse), then the render contract executes in order (hardened range container on the bundle's own compose project, guest overlays and seed ISOs, define and start per `boot.json`, wait on every readiness probe). Ownership registers before the first docker resource so teardown never depends on this process surviving. Every stage transition lands in the project's JSONL stage log; failures name their stage and guest; on readiness failure the affected guests' serial console logs are pulled into the project state directory before teardown (kept with `keep_on_failure`).
"""

import asyncio
import hashlib
import json
import os
import shlex
import subprocess
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any, Literal, cast

from pydantic import BaseModel, ConfigDict, Field

from .._channel.channel import MessageChannel, request_id
from .._channel.protocol import Budget, ExecRequest
from .._channel.vsock import VsockTransport
from .ownership import (
    PROJECT_PREFIX,
    StageLog,
    default_state_dir,
    owner_record,
    project_dir,
    write_owner,
)
from .rangeimage import ensure_range_image

Runner = Callable[..., "subprocess.CompletedProcess[str]"]
"""Executes a command: `run(argv, env=None, input=None)`; injectable for tests."""


def run_command(
    argv: list[str],
    env: dict[str, str] | None = None,
    input: str | None = None,
) -> "subprocess.CompletedProcess[str]":
    """The default runner: captured text output, no check."""
    return subprocess.run(argv, capture_output=True, text=True, env=env, input=input)


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


class GuestState(BaseModel):
    """Per-guest outcome reported by `up`."""

    name: str
    cid: int
    ready: bool


class UpResult(BaseModel):
    """What a successful `up` reports: the project and every guest ready."""

    project: str
    range_name: str
    guests: list[GuestState]
    seconds: float


def verify_bundle(bundle: Path) -> dict[str, Any]:
    """Verify every manifest digest and that nothing unlisted is present; returns the manifest.

    Raises:
        UpError: Any missing, unreadable, mismatched, unlisted, or symlinked file, a malformed manifest, or a required render file absent from the manifest (all reported at once); acting on an unverified bundle is never attempted.
    """
    manifest_path = bundle / "manifest.json"
    if not manifest_path.is_file():
        raise UpError("verify-bundle", f"{bundle} has no manifest.json")
    try:
        parsed: object = json.loads(manifest_path.read_text())
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


class BootGuest(BaseModel):
    """One guest in `boot.json`, shape-validated before anything interpolates it anywhere."""

    model_config = ConfigDict(extra="forbid")

    name: str = Field(pattern=_SAFE_NAME)
    cid: int = Field(ge=3)
    image_file: str = Field(pattern=_SAFE_NAME)
    image_digest: str | None = None
    overlay_gb: int = Field(ge=1)
    readiness: Literal["cloud-init"]


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


def boot_script(boot: BootPlan) -> str:
    """The in-container realization script for `boot.json` (overlays, seeds, define, start). Every interpolated value is shape-validated by `BootPlan` and shell-quoted anyway."""
    lines = ["#!/bin/bash", "set -euo pipefail"]
    for guest in boot.guests:
        name = shlex.quote(guest.name)
        image = shlex.quote(guest.image_file)
        lines.append(
            f"qemu-img create -f qcow2 -F qcow2 -b /images/{image} "
            f"/scratch/{name}.qcow2 {guest.overlay_gb}G >/dev/null"
        )
        lines.append(
            f"cloud-localds -N /render/guests/{name}/seed/network-config "
            f"/scratch/{name}-seed.iso "
            f"/render/guests/{name}/seed/user-data /render/guests/{name}/seed/meta-data"
        )
        lines.append(
            f"virsh -c qemu:///system define /render/guests/{name}/domain.xml >/dev/null"
        )
        lines.append(f"virsh -c qemu:///system start {name} >/dev/null")
    return "\n".join(lines) + "\n"


CLOUD_INIT_PROBE = ["sh", "-c", "cloud-init status --wait >/dev/null 2>&1"]
"""The readiness exec: the exit status of `cloud-init status --wait` IS the signal (0 done; nonzero error or degraded, both meaning the declared configuration did not fully apply)."""


def make_channel(cids: "dict[str, int]") -> MessageChannel:
    """The readiness channel to this range's guests (a test seam; built inside the event loop).

    The per-round-trip allowance is readiness-tuned: a daemon that accepts but never replies must cost seconds per attempt, not the channel's long default, or one wedged guest overshoots the whole readiness budget. Long cloud-init waits stay fine: exec liveness rides pending polls, each bounded by this allowance.
    """
    return MessageChannel(
        VsockTransport(cids), label="up-readiness", channel_budget_s=10.0
    )


async def _await_ready(
    channel: MessageChannel,
    guest: str,
    readiness: str,
    deadline: float,
    min_window: float = 10.0,
) -> bool:
    """One guest's readiness: daemon answering, then the cloud-init gate; any failure or malformed behavior is not-ready, never an escape."""
    while True:
        try:
            await channel.ping(guest)
            break
        except Exception:
            if time.monotonic() >= deadline:
                return False
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
            return outcome.rc == 0
        except Exception:
            return False
    return True


def project_containers(runner: Runner, project: str) -> list[str]:
    """Container ids carrying the project's compose label (live or exited)."""
    result = runner(
        [
            "docker",
            "ps",
            "-a",
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


def up(bundle: Path, options: UpOptions, runner: Runner | None = None) -> UpResult:
    """Realize a verified bundle; returns the project name and per-guest state.

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
    for guest in guests:
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
                    f"image {guest.image_file} digest {actual} does not match the bundle's {guest.image_digest}",
                    guest=guest.name,
                )

    try:
        range_image = ensure_range_image(lambda argv: run(argv))
    except Exception as error:
        raise UpError("range-image", str(error)) from error

    # ownership registers before the first compose resource (cleanup registry)
    write_owner(options.state_dir, owner_record(project, range_name, spec_sha, bundle))
    log = StageLog(options.state_dir, project)
    log.log("verify-bundle", "ok", files=len(cast(dict[str, Any], manifest["files"])))
    log.log("verify-images", "ok", guests=len(guests))
    log.log("range-image", "ok", tag=range_image)

    env = dict(os.environ)
    # the hardened image is hard-required: no environment override survives
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

    log.log("range-container", "start")
    result = run(_compose_argv(project, bundle, "up", "-d", "--wait"), env=env)
    if result.returncode != 0:
        raise fail(
            "range-container", f"compose up failed: {result.stderr.strip()[-800:]}"
        )
    log.log("range-container", "ok")

    log.log("guest-boot", "start", guests=[g.name for g in guests])
    boot_result = run(
        _compose_argv(project, bundle, "exec", "-T", "range", "bash", "-s"),
        env=env,
        input=boot_script(boot),
    )
    if boot_result.returncode != 0:
        raise fail(
            "guest-boot",
            f"guest boot failed: {boot_result.stderr.strip()[-800:]} "
            f"(consoles of already-booted guests under {project_dir(options.state_dir, project) / 'consoles'})",
            consoles=[g.name for g in guests],
        )
    log.log("guest-boot", "ok")

    async def _readiness() -> list[GuestState]:
        channel = make_channel({g.name: g.cid for g in guests})
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
            ready = await _await_ready(
                channel,
                guest.name,
                guest.readiness,
                guest_deadline,
                min_window=options.readiness_min_window,
            )
            collected.append(GuestState(name=guest.name, cid=guest.cid, ready=ready))
            log.log("readiness", "ok" if ready else "fail", guest=guest.name)
        return collected

    states = asyncio.run(_readiness())
    failed = [state.name for state in states if not state.ready]
    if failed:
        raise fail(
            "readiness",
            f"guests not ready within {options.readiness_timeout:.0f}s: {', '.join(failed)} "
            f"(console logs under {project_dir(options.state_dir, project) / 'consoles'})",
            guest=failed[0],
            consoles=failed,
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
        )


def _sha256(path: Path) -> str:
    hasher = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 22), b""):
            hasher.update(chunk)
    return hasher.hexdigest()

"""`inspect-ranges up`: realize a rendered bundle into a running, ready range (realizer-v1 slice 2).

The applier consumes a digest-verified bundle and nothing else: every manifest digest verifies before anything runs (mismatch, missing, or unlisted files refuse), then the render contract executes in order (hardened range container on the bundle's own compose project, guest overlays and seed ISOs, define and start per `boot.json`, wait on every readiness probe). Ownership registers before the first docker resource so teardown never depends on this process surviving. Every stage transition lands in the project's JSONL stage log; failures name their stage and guest; on readiness failure the affected guests' serial console logs are pulled into the project state directory before teardown (kept with `keep_on_failure`).
"""

import hashlib
import json
import os
import subprocess
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any, cast

from pydantic import BaseModel

from . import probe
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
    state_dir: Path = default_state_dir()
    readiness_timeout: float = 300.0
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
        UpError: Any missing file, digest mismatch, or unlisted file (all reported at once); acting on an unverified bundle is never attempted.
    """
    manifest_path = bundle / "manifest.json"
    if not manifest_path.is_file():
        raise UpError("verify-bundle", f"{bundle} has no manifest.json")
    manifest = cast(dict[str, Any], json.loads(manifest_path.read_text()))
    files = cast(dict[str, dict[str, Any]], manifest["files"])
    failures: list[str] = []
    for relative, meta in files.items():
        path = bundle / relative
        if not path.is_file():
            failures.append(f"{relative}: missing")
            continue
        if hashlib.sha256(path.read_bytes()).hexdigest() != meta["sha256"]:
            failures.append(f"{relative}: sha256 mismatch")
    listed = set(files) | {"manifest.json"}
    on_disk = {
        str(path.relative_to(bundle)) for path in bundle.rglob("*") if path.is_file()
    }
    failures.extend(f"{extra}: not in manifest" for extra in sorted(on_disk - listed))
    if failures:
        raise UpError(
            "verify-bundle",
            "bundle fails verification:\n  " + "\n  ".join(failures),
        )
    return manifest


def boot_script(boot: dict[str, Any]) -> str:
    """The in-container realization script for `boot.json` (overlays, seeds, define, start)."""
    lines = ["#!/bin/bash", "set -euo pipefail"]
    for guest in cast(list[dict[str, Any]], boot["guests"]):
        name = guest["name"]
        lines.append(
            f"qemu-img create -f qcow2 -F qcow2 -b /images/{guest['image_file']} "
            f"/scratch/{name}.qcow2 {guest['overlay_gb']}G >/dev/null"
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

    manifest = verify_bundle(bundle)
    boot = cast(dict[str, Any], json.loads((bundle / "boot.json").read_text()))
    range_name = cast(str, manifest["range"])
    spec_sha = cast(str, manifest["spec_sha256"])
    project = options.project or f"{PROJECT_PREFIX}{range_name}-{spec_sha[:12]}"

    if project_containers(run, project):
        raise UpError(
            "prepare",
            f"project {project!r} is already running; refusing to supersede. "
            f"Tear it down first: inspect-ranges down {project}",
        )

    guests = cast(list[dict[str, Any]], boot["guests"])
    for guest in guests:
        image = options.image_cache / cast(str, guest["image_file"])
        if not image.is_file():
            raise UpError(
                "verify-images",
                f"image {guest['image_file']} is not in the cache {options.image_cache}",
                guest=cast(str, guest["name"]),
            )
        digest = cast("str | None", guest.get("image_digest"))
        if digest is not None:
            actual = f"sha256:{_sha256(image)}"
            if actual != digest:
                raise UpError(
                    "verify-images",
                    f"image {guest['image_file']} digest {actual} does not match the bundle's {digest}",
                    guest=cast(str, guest["name"]),
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

    def fail(stage: str, message: str, guest: str | None = None) -> UpError:
        log.log(stage, "fail", error=message, **({"guest": guest} if guest else {}))
        if not options.keep_on_failure:
            from .down import down as teardown

            teardown(project, state_dir=options.state_dir, runner=run, keep_state=True)
        return UpError(stage, message, guest=guest)

    log.log("range-container", "start")
    result = run(_compose_argv(project, bundle, "up", "-d", "--wait"), env=env)
    if result.returncode != 0:
        raise fail(
            "range-container", f"compose up failed: {result.stderr.strip()[-800:]}"
        )
    log.log("range-container", "ok")

    log.log("guest-boot", "start", guests=[g["name"] for g in guests])
    boot_result = run(
        _compose_argv(project, bundle, "exec", "-T", "range", "bash", "-s"),
        env=env,
        input=boot_script(boot),
    )
    if boot_result.returncode != 0:
        raise fail(
            "guest-boot", f"guest boot failed: {boot_result.stderr.strip()[-800:]}"
        )
    log.log("guest-boot", "ok")

    states: list[GuestState] = []
    deadline = time.monotonic() + options.readiness_timeout
    for guest in guests:
        name = cast(str, guest["name"])
        cid = cast(int, guest["cid"])
        log.log("readiness", "start", guest=name, cid=cid)
        ready = probe.wait_daemon(cid, deadline)
        if ready and cast(str, guest["readiness"]) == "cloud-init":
            remaining = max(10.0, deadline - time.monotonic())
            try:
                rc, _, _ = probe.guest_exec(
                    cid,
                    "cloud-init status --wait >/dev/null 2>&1; echo done",
                    remaining,
                )
                ready = rc == 0
            except (OSError, ValueError):
                ready = False
        states.append(GuestState(name=name, cid=cid, ready=ready))
        log.log("readiness", "ok" if ready else "fail", guest=name)
    failed = [state.name for state in states if not state.ready]
    if failed:
        _pull_consoles(run, project, bundle, env, options, failed)
        raise fail(
            "readiness",
            f"guests not ready within {options.readiness_timeout:.0f}s: {', '.join(failed)} "
            f"(console logs under {project_dir(options.state_dir, project) / 'consoles'})",
            guest=failed[0],
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

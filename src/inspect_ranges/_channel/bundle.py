"""The daemon artifact: `inspect-ranges daemon-bundle` builds the versioned, byte-deterministic tarball the realizer bakes into goldens.

Contents: the static Go Linux daemon (amd64) with its installer and systemd unit, the Windows daemon placeholder (source arrives with channel-v1 slice 6), and nothing else. The sidecar `daemon.json` carries the protocol version, the daemon version, per-file sha256 digests, and the bundle digest.

Trust model: the sidecar written beside the tarball is a convenience copy. A consumer that must trust the artifact (the realizer, the build manifest) pins `bundle_sha256` out of band and passes the pinned `DaemonBundleInfo` to `verify_daemon_bundle`; verifying against a sidecar fetched from the same directory as the tarball proves only internal consistency, which an attacker controlling both files can fake.

Determinism: the Go build runs under the pinned toolchain (verified by `go version`, never silently substituted) in a scrubbed environment, and the artifact is an UNCOMPRESSED tar normalized completely (sorted members, zeroed timestamps and ownership, fixed modes), so the digest binds bytes the build fully controls; compression would additionally bind the zlib implementation, which varies across hosts.
"""

import hashlib
import io
import os
import shutil
import subprocess
import tarfile
from pathlib import Path

from pydantic import BaseModel, ConfigDict

from .protocol import PROTOCOL_VERSION

DAEMON_VERSION = "3.0.0"

GO_PIN = "go1.23.6"
PINNED_GO = Path.home() / ".local/go-toolchains" / GO_PIN / "bin/go"
GO_SOURCE = Path(__file__).parent / "daemon" / "linux"

_INSTALL_SH = """#!/bin/sh
# Install vsockd v3 into a Linux guest (run from the extracted bundle dir).
set -eu
install -D -m 0755 linux/vsockd /opt/inspect-ranges/vsockd
install -D -m 0644 linux/vsockd.service /etc/systemd/system/vsockd.service
systemctl enable vsockd.service
"""

_UNIT = """[Unit]
Description=inspect-ranges guest control daemon (v3)
[Service]
ExecStart=/opt/inspect-ranges/vsockd
Restart=always
[Install]
WantedBy=multi-user.target
"""

_WINDOWS_PLACEHOLDER = """The Windows daemon (C# codec swap plus listener supervision) arrives with
channel-v1 slice 6; this placeholder reserves the bundle layout. The protocol
contract it must satisfy is pinned by tests/wire_vectors/v3.json.
"""


class BundleError(Exception):
    """Bundle build or verification failure, naming the stage."""

    def __init__(self, stage: str, message: str) -> None:
        self.stage = stage
        super().__init__(f"[{stage}] {message}")


class DaemonBundleInfo(BaseModel):
    """The `daemon.json` sidecar: what the realizer pins and the manifest records."""

    model_config = ConfigDict(frozen=True)

    name: str
    version: str
    protocol: int
    files: dict[str, str]
    bundle_sha256: str


def locate_go() -> Path | None:
    """The pinned Go toolchain if installed, else whatever is on PATH (tests may skip on None)."""
    if PINNED_GO.exists():
        return PINNED_GO
    located = shutil.which("go")
    return Path(located) if located else None


def _pinned_go_binary() -> Path:
    """The toolchain for ARTIFACT builds: whatever is found must match the pin exactly."""
    go = locate_go()
    if go is None:
        raise BundleError(
            "toolchain",
            f"no Go toolchain: install {GO_PIN} per {GO_SOURCE / 'README.md'}",
        )
    probe = subprocess.run([str(go), "version"], capture_output=True, text=True)
    if probe.returncode != 0 or f" {GO_PIN} " not in probe.stdout:
        raise BundleError(
            "toolchain",
            f"artifact builds require the pinned toolchain {GO_PIN}; "
            f"{go} reports: {probe.stdout.strip() or probe.stderr.strip()}",
        )
    return go


def build_daemon_binary(out: Path) -> None:
    """Build the static Linux daemon reproducibly into `out`.

    The environment is scrubbed: only PATH, HOME, and the Go cache variables survive, so ambient `GOFLAGS`/`GOEXPERIMENT`/`GOAMD64` cannot silently change the bytes.

    Raises:
        BundleError: Toolchain missing, not the pin, or the build failed.
    """
    go = _pinned_go_binary()
    home = os.environ.get("HOME", str(Path.home()))
    env = {
        "PATH": f"{go.parent}:/usr/bin:/bin",
        "HOME": home,
        "GOCACHE": os.environ.get("GOCACHE", f"{home}/.cache/go-build"),
        "GOPATH": os.environ.get("GOPATH", f"{home}/go"),
        "CGO_ENABLED": "0",
        "GOOS": "linux",
        "GOARCH": "amd64",
        "GOFLAGS": "",
    }
    result = subprocess.run(
        [
            str(go),
            "build",
            "-trimpath",
            "-buildvcs=false",
            "-ldflags=-s -w",
            "-o",
            str(out),
            ".",
        ],
        cwd=GO_SOURCE,
        env=env,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise BundleError("build", result.stderr.strip() or result.stdout.strip())


def _tar_bytes(members: dict[str, bytes]) -> bytes:
    """A normalized, uncompressed tar: sorted members, zeroed times and ownership, fixed modes."""
    tar_buffer = io.BytesIO()
    with tarfile.open(fileobj=tar_buffer, mode="w", format=tarfile.USTAR_FORMAT) as tar:
        for name in sorted(members):
            data = members[name]
            info = tarfile.TarInfo(name=name)
            info.size = len(data)
            info.mtime = 0
            info.uid = info.gid = 0
            info.uname = info.gname = ""
            info.mode = 0o755 if name.endswith((".sh", "vsockd")) else 0o644
            tar.addfile(info, io.BytesIO(data))
    return tar_buffer.getvalue()


def bundle_file_name(version: str = DAEMON_VERSION) -> str:
    """The bundle tarball's file name for a daemon version (the single naming scheme producers and consumers share)."""
    return f"vsockd-bundle-{version}.tar"


def build_daemon_bundle(out_dir: Path) -> DaemonBundleInfo:
    """Build the daemon bundle and its `daemon.json` sidecar into `out_dir`.

    Returns:
        The sidecar content, including the bundle digest.

    Raises:
        BundleError: Toolchain, build, or write failure.
    """
    # the go build runs with its own cwd, so a relative out_dir (including
    # the CLI default dist/daemon) must resolve before the build writes to it
    out_dir = out_dir.resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    binary_path = out_dir / ".vsockd-build"
    try:
        build_daemon_binary(binary_path)
        binary = binary_path.read_bytes()
    finally:
        binary_path.unlink(missing_ok=True)
    return write_bundle(out_dir, binary)


def write_bundle(
    out_dir: Path, binary: bytes, version: str = DAEMON_VERSION
) -> DaemonBundleInfo:
    """Assemble and write the bundle tar and sidecar from a daemon binary's bytes.

    The one place that knows the bundle member layout; `build_daemon_bundle` calls it with the real build, and tests call it with stand-in bytes so fixtures cannot drift from the layout production emits.
    """
    members = {
        "linux/vsockd": binary,
        "linux/install.sh": _INSTALL_SH.encode(),
        "linux/vsockd.service": _UNIT.encode(),
        "windows/PLACEHOLDER.md": _WINDOWS_PLACEHOLDER.encode(),
    }
    blob = _tar_bytes(members)
    info = DaemonBundleInfo(
        name="vsockd",
        version=version,
        protocol=PROTOCOL_VERSION,
        files={
            name: hashlib.sha256(data).hexdigest() for name, data in members.items()
        },
        bundle_sha256=hashlib.sha256(blob).hexdigest(),
    )
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / bundle_file_name(version)).write_bytes(blob)
    (out_dir / "daemon.json").write_text(info.model_dump_json(indent=2) + "\n")
    return info


def _safe_member_name(name: str) -> bool:
    return (
        not name.startswith("/")
        and ".." not in Path(name).parts
        and not Path(name).is_absolute()
    )


def verify_daemon_bundle(bundle_path: Path, info: DaemonBundleInfo) -> None:
    """Verify a bundle against a TRUSTED `info` (see the module trust model).

    Checks the bundle digest, then every member: regular files only, safe relative names, no duplicates, digests matching the sidecar exactly. A verified bundle is safe to extract.

    Raises:
        BundleError: Any mismatch or unsafe member.
    """
    blob = bundle_path.read_bytes()
    digest = hashlib.sha256(blob).hexdigest()
    if digest != info.bundle_sha256:
        raise BundleError(
            "verify-bundle", f"bundle digest {digest} != pinned {info.bundle_sha256}"
        )
    seen: dict[str, str] = {}
    with tarfile.open(fileobj=io.BytesIO(blob), mode="r:") as tar:
        for member in tar.getmembers():
            if not member.isreg():
                raise BundleError(
                    "verify-members", f"non-regular member {member.name!r}"
                )
            if not _safe_member_name(member.name):
                raise BundleError(
                    "verify-members", f"unsafe member name {member.name!r}"
                )
            if member.name in seen:
                raise BundleError("verify-members", f"duplicate member {member.name!r}")
            handle = tar.extractfile(member)
            if handle is None:
                raise BundleError("verify-members", f"unreadable member {member.name}")
            seen[member.name] = hashlib.sha256(handle.read()).hexdigest()
    if seen != info.files:
        raise BundleError(
            "verify-members",
            f"member digests diverge: {sorted(set(seen) ^ set(info.files)) or 'content changed'}",
        )

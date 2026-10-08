"""The daemon artifact: `inspect-ranges daemon-bundle` builds the versioned, byte-deterministic tarball the realizer bakes into goldens.

Contents: the static Go Linux daemon (amd64) with its installer and systemd unit, the Windows daemon placeholder (source arrives with channel-v1 slice 6), and nothing else. The sidecar `daemon.json` carries the protocol version, the daemon version, per-file sha256 digests, and the bundle digest; the realizer consumes the bundle strictly by digest, and `verify_daemon_bundle` refuses any tampered member.

Determinism: the Go build runs `-trimpath -buildvcs=false CGO_ENABLED=0` under the pinned toolchain, and the tar is normalized (sorted members, zeroed timestamps and ownership, fixed modes, gzip with zeroed mtime), so building twice yields the identical digest.
"""

import gzip
import hashlib
import io
import os
import shutil
import subprocess
import tarfile
from pathlib import Path

from pydantic import BaseModel, ConfigDict

DAEMON_VERSION = "3.0.0"
PROTOCOL_VERSION = 3

PINNED_GO = Path.home() / ".local/go-toolchains/go1.23.6/bin/go"
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


def _go_binary() -> Path:
    if PINNED_GO.exists():
        return PINNED_GO
    located = shutil.which("go")
    if located:
        return Path(located)
    raise BundleError(
        "toolchain",
        f"no Go toolchain: install the pin per {GO_SOURCE / 'README.md'}",
    )


def build_daemon_binary(out: Path) -> None:
    """Build the static Linux daemon reproducibly into `out`.

    Raises:
        BundleError: Toolchain missing or the build failed.
    """
    go = _go_binary()
    env = dict(os.environ)
    env.update(CGO_ENABLED="0", GOARCH="amd64", GOOS="linux")
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
    """A normalized tar.gz: sorted members, zeroed times and ownership, fixed modes."""
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
    gz_buffer = io.BytesIO()
    with gzip.GzipFile(fileobj=gz_buffer, mode="wb", mtime=0) as gz:
        gz.write(tar_buffer.getvalue())
    return gz_buffer.getvalue()


def build_daemon_bundle(out_dir: Path) -> DaemonBundleInfo:
    """Build the daemon bundle and sidecar into `out_dir`.

    Returns:
        The sidecar content, including the bundle digest.

    Raises:
        BundleError: Toolchain, build, or write failure.
    """
    out_dir.mkdir(parents=True, exist_ok=True)
    binary_path = out_dir / ".vsockd-build"
    try:
        build_daemon_binary(binary_path)
        members = {
            "linux/vsockd": binary_path.read_bytes(),
            "linux/install.sh": _INSTALL_SH.encode(),
            "linux/vsockd.service": _UNIT.encode(),
            "windows/PLACEHOLDER.md": _WINDOWS_PLACEHOLDER.encode(),
        }
    finally:
        binary_path.unlink(missing_ok=True)
    blob = _tar_bytes(members)
    digest = hashlib.sha256(blob).hexdigest()
    info = DaemonBundleInfo(
        name="vsockd",
        version=DAEMON_VERSION,
        protocol=PROTOCOL_VERSION,
        files={
            name: hashlib.sha256(data).hexdigest() for name, data in members.items()
        },
        bundle_sha256=digest,
    )
    bundle_path = out_dir / f"vsockd-bundle-{DAEMON_VERSION}.tar.gz"
    sidecar_path = out_dir / f"vsockd-bundle-{DAEMON_VERSION}.json"
    bundle_path.write_bytes(blob)
    sidecar_path.write_text(info.model_dump_json(indent=2) + "\n")
    return info


def verify_daemon_bundle(bundle_path: Path, info: DaemonBundleInfo) -> None:
    """Verify a bundle against its sidecar: bundle digest, then every member digest.

    Raises:
        BundleError: Digest mismatch (tamper) or a missing/extra member.
    """
    blob = bundle_path.read_bytes()
    digest = hashlib.sha256(blob).hexdigest()
    if digest != info.bundle_sha256:
        raise BundleError(
            "verify-bundle", f"bundle digest {digest} != sidecar {info.bundle_sha256}"
        )
    seen: dict[str, str] = {}
    with tarfile.open(fileobj=io.BytesIO(blob), mode="r:gz") as tar:
        for member in tar.getmembers():
            handle = tar.extractfile(member)
            if handle is None:
                raise BundleError("verify-members", f"unreadable member {member.name}")
            seen[member.name] = hashlib.sha256(handle.read()).hexdigest()
    if seen != info.files:
        raise BundleError(
            "verify-members",
            f"member digests diverge: {sorted(set(seen) ^ set(info.files)) or 'content changed'}",
        )

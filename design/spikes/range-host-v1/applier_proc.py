"""Shared applier-process management for the range-host battery scripts (one copy; the two batteries must never drift in startup semantics)."""

import os
import socket
import subprocess
import time
from pathlib import Path


def socket_dir() -> Path:
    """A short, user-private socket dir: `XDG_RUNTIME_DIR` when present (kernel-provided, 0700, user-owned), else a uid-keyed /tmp dir (fine on the single-user devbox; a shared host should always have XDG_RUNTIME_DIR). `AF_UNIX` paths cap at ~107 bytes, which a spike-tree path exceeds from a worktree."""
    runtime = os.environ.get("XDG_RUNTIME_DIR")
    base = Path(runtime) if runtime else Path(f"/tmp/ir-rh-{os.getuid()}")
    return base / "ir-rh-battery"


SOCKET = socket_dir() / "applier.sock"


def start_applier(root: Path, state_dir: Path, log_path: Path) -> "subprocess.Popen[bytes]":
    """Spawn the applier (the venv binary DIRECTLY: a `uv run` wrapper absorbs kill(), which SIGKILL cannot forward) and wait until its socket is CONNECTABLE, not merely present. A failed wait kills the half-started process rather than leaking it past the raise."""
    SOCKET.parent.mkdir(parents=True, exist_ok=True)
    os.chmod(SOCKET.parent, 0o700)
    SOCKET.unlink(missing_ok=True)  # a stale file would fake readiness below
    with open(log_path, "ab") as log:  # the child dups the fd; ours can close
        proc = subprocess.Popen(
            [
                str(root / ".venv" / "bin" / "inspect-ranges"), "applier",
                "--socket", str(SOCKET),
                "--state-dir", str(state_dir),
                "--image-cache", os.environ["INSPECT_RANGES_IMAGE_CACHE"],
            ],
            cwd=root,
            stdout=log,
            stderr=subprocess.STDOUT,
        )
    deadline = time.monotonic() + 60
    try:
        while True:
            if proc.poll() is not None or time.monotonic() > deadline:
                raise RuntimeError(f"applier never came up (see {log_path})")
            if SOCKET.exists():
                probe = socket.socket(socket.AF_UNIX)
                try:
                    probe.connect(str(SOCKET))
                    return proc
                except OSError:
                    pass
                finally:
                    probe.close()
            time.sleep(0.1)
    except BaseException:
        if proc.poll() is None:
            proc.kill()
            proc.wait(timeout=10)
        raise

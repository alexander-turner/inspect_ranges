"""Drive the Go daemon's checks from the Python suite (the cross-codec drift guard).

Skips when no Go toolchain is available (dev convenience); CI must provide the pinned toolchain (`src/inspect_ranges/_channel/daemon/linux/README.md`) so the guard is enforced there, never silently skipped.
"""

import os
import shutil
import subprocess
from pathlib import Path

import pytest

DAEMON_DIR = Path(__file__).parent.parent / "src/inspect_ranges/_channel/daemon/linux"
PINNED_GO = Path.home() / ".local/go-toolchains/go1.23.6/bin/go"


def _go() -> str | None:
    if PINNED_GO.exists():
        return str(PINNED_GO)
    return shutil.which("go")


go_binary = _go()
pytestmark = pytest.mark.skipif(
    go_binary is None, reason="no Go toolchain (see daemon/linux/README.md for the pin)"
)


def _run(*argv: str) -> subprocess.CompletedProcess[str]:
    assert go_binary is not None
    env = dict(os.environ)
    env["PATH"] = str(Path(go_binary).parent) + os.pathsep + env.get("PATH", "")
    return subprocess.run(
        argv, cwd=DAEMON_DIR, env=env, capture_output=True, text=True, timeout=300
    )


def test_gofmt_clean() -> None:
    assert go_binary is not None
    gofmt = str(Path(go_binary).parent / "gofmt")
    result = _run(gofmt, "-l", ".")
    assert result.returncode == 0 and result.stdout.strip() == "", (
        f"gofmt-dirty files: {result.stdout}"
    )


def test_go_vet_clean() -> None:
    assert go_binary is not None
    result = _run(go_binary, "vet", "./...")
    assert result.returncode == 0, result.stderr


def test_go_wire_vectors_round_trip() -> None:
    """The drift guard: the Go codec must round-trip the shared vectors byte-exactly."""
    assert go_binary is not None
    result = _run(go_binary, "test", "./...")
    assert result.returncode == 0, f"{result.stdout}\n{result.stderr}"

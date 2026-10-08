"""Drive the Go daemon's checks from the Python suite (the cross-codec drift guard).

Skips when no Go toolchain is available (dev convenience); CI must provide the pinned toolchain (`src/inspect_ranges/_channel/daemon/linux/README.md`) so the guard is enforced there, never silently skipped.
"""

import os
import subprocess
from pathlib import Path

import pytest
from inspect_ranges._channel.bundle import locate_go

DAEMON_DIR = Path(__file__).parent.parent / "src/inspect_ranges/_channel/daemon/linux"

_located = locate_go()
go_binary = str(_located) if _located is not None else None
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

"""Drive the C# codec's vector round-trip (the third-codec drift guard).

Linux CI has no C# toolchain: this skips there with a visible reason and fails loudly under `INSPECT_RANGES_REQUIRE_DOTNET=1`, which the Windows battery sets (see `daemon/windows/README.md` for the pin and the CI story).
"""

import os
import shutil
import subprocess
from pathlib import Path

import pytest

WINDOWS_DIR = (
    Path(__file__).parent.parent / "src/inspect_ranges/_channel/daemon/windows"
)
VECTORS = Path(__file__).parent / "wire_vectors" / "v3.json"
PINNED_DOTNET = Path.home() / ".local/dotnet/dotnet"

REQUIRE_DOTNET = os.environ.get("INSPECT_RANGES_REQUIRE_DOTNET") == "1"


def _dotnet() -> str | None:
    if PINNED_DOTNET.exists():
        return str(PINNED_DOTNET)
    return shutil.which("dotnet")


dotnet_binary = _dotnet()
pytestmark = pytest.mark.skipif(
    dotnet_binary is None and not REQUIRE_DOTNET,
    reason="no .NET SDK (see daemon/windows/README.md for the pin and CI story)",
)


def test_dotnet_present_when_required() -> None:
    if REQUIRE_DOTNET:
        assert dotnet_binary is not None, (
            "INSPECT_RANGES_REQUIRE_DOTNET=1 but no SDK: install the pin per "
            "src/inspect_ranges/_channel/daemon/windows/README.md"
        )


def test_cs_wire_vectors_round_trip() -> None:
    """The C# codec must round-trip the shared vectors byte-exactly and reject the hardening table."""
    assert dotnet_binary is not None
    env = dict(os.environ)
    env["DOTNET_CLI_TELEMETRY_OPTOUT"] = "1"
    env["DOTNET_NOLOGO"] = "1"
    result = subprocess.run(
        [dotnet_binary, "run", "--project", ".", "--", str(VECTORS)],
        cwd=WINDOWS_DIR,
        env=env,
        capture_output=True,
        text=True,
        timeout=600,
    )
    assert result.returncode == 0, f"{result.stdout}\n{result.stderr}"
    assert "failures: 0" in result.stdout

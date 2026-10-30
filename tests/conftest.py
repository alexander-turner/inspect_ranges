"""Shared test isolation.

The registry search path's default tail is the public org, and eval init now pulls catalog images implicitly (standard-images-v1 slice 4), so a unit test that resolves images without configuring `INSPECT_RANGES_REGISTRY` would consult docker.io. Every test gets a hermetic empty layout instead: a missing image refuses locally and deterministically, never over the network. Fleet pins get the same hermeticity: `pins.json` discovers from the working directory up, so without the empty-string override a test run inside this repo (or any repo tracking pins) would pin fixture pulls against the developer's real catalog state. The attack box gets the same treatment: an unset `INSPECT_RANGES_ATTACK_BOX` selects the pinned glovebox, whose eval init downloads a release, so every test starts on `builtin`. Tests that exercise the env contract itself delenv/setenv over this.
"""

from pathlib import Path

import pytest


@pytest.fixture(autouse=True)
def hermetic_registry_search_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from inspect_ranges._dist.oci import OciLayout

    location = tmp_path / "hermetic-empty-registry"
    OciLayout(location).ensure()
    monkeypatch.setenv("INSPECT_RANGES_REGISTRY", str(location))
    monkeypatch.setenv("INSPECT_RANGES_PIN_FILE", "")
    monkeypatch.setenv("INSPECT_RANGES_ATTACK_BOX", "builtin")

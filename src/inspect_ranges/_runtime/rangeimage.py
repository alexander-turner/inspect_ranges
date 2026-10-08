"""The hardened range container image: built from package data, hard-required by `up`.

Per the realizer-v1 Decisions, `up` always runs the hardened profile (non-root QEMU, mount namespaces off, docker-default AppArmor/seccomp, the render-emitted capability floor) with no bypass flag; prototype images remain spike-harness material only.
"""

import subprocess
from collections.abc import Callable
from pathlib import Path

from .. import __version__

RANGE_IMAGE_TAG = f"inspect-ranges-range:v{__version__}"
"""The tag `up` builds and pins into the compose environment."""

DockerRunner = Callable[[list[str]], "subprocess.CompletedProcess[str]"]
"""Executes a docker command, capturing text output; injectable for tests."""


def range_image_context() -> Path:
    """The in-package docker build context (Dockerfile plus entrypoint)."""
    return Path(__file__).parent / "range_image"


def ensure_range_image(
    runner: DockerRunner | None = None, tag: str = RANGE_IMAGE_TAG
) -> str:
    """Build the hardened range image if this host does not have it; returns the tag.

    Raises:
        subprocess.CalledProcessError: The docker build failed (stderr attached).
        FileNotFoundError: docker is not on this host.
    """
    run = runner or run_docker
    inspect = run(["docker", "image", "inspect", tag])
    if inspect.returncode == 0:
        return tag
    build = run(["docker", "build", "-q", "-t", tag, str(range_image_context())])
    if build.returncode != 0:
        raise subprocess.CalledProcessError(
            build.returncode, build.args, build.stdout, build.stderr
        )
    return tag


def run_docker(argv: list[str]) -> "subprocess.CompletedProcess[str]":
    """The default runner: `subprocess.run` with captured text output, no check."""
    return subprocess.run(argv, capture_output=True, text=True)

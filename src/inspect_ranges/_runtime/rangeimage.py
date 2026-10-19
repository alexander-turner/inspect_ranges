"""The hardened range container image: built from package data, hard-required by `up`.

Per the realizer-v1 Decisions, `up` always runs the hardened profile (non-root QEMU, mount namespaces off, docker-default AppArmor/seccomp, the render-emitted capability floor) with no bypass flag; prototype images remain spike-harness material only.
"""

import hashlib
import os
import re
import subprocess
from collections.abc import Callable
from pathlib import Path

from .. import __version__

RANGE_IMAGE_TAG = f"inspect-ranges-range:v{__version__}"
"""The tag `up` builds and pins into the compose environment."""

RANGE_IMAGE_ENV = "INSPECT_RANGES_RANGE_IMAGE"
"""A digest-pinned published range image (`repo@sha256:<hex>`, the catalog's conventional Docker repo): set, `up` pulls and uses it instead of building locally (standard-images-v1 slice 3). The pin is mandatory: a mutable tag could swap the hardened jail under a fleet, so unpinned values refuse. The local build remains the default and the dev loop."""

_PINNED_REF = re.compile(r"\A[a-z0-9][a-z0-9._/:-]*@sha256:[0-9a-f]{64}\Z")


class RangeImageError(RuntimeError):
    """A pinned range image could not be used; the message names the pin and the cause."""


DockerRunner = Callable[[list[str]], "subprocess.CompletedProcess[str]"]
"""Executes a docker command, capturing text output; injectable for tests."""


def range_image_context() -> Path:
    """The in-package docker build context (Dockerfile plus entrypoint)."""
    return Path(__file__).parent / "range_image"


CONTENT_LABEL = "inspect-ranges.range-image-content"


def _content_hash() -> str:
    """Hash of the package version and the build context, so a stale or substituted image rebuilds."""
    hasher = hashlib.sha256(__version__.encode())
    for name in ("Dockerfile", "entrypoint.sh"):
        hasher.update((range_image_context() / name).read_bytes())
    return hasher.hexdigest()


def ensure_range_image(
    runner: DockerRunner | None = None, tag: str = RANGE_IMAGE_TAG
) -> str:
    """Build the hardened range image unless this host has one whose content label matches; returns the tag.

    Tag presence alone is not trusted: the image must carry the content label for the current package version and build context, so `docker tag` substitution or an edited Dockerfile within one version both trigger a rebuild.

    With `INSPECT_RANGES_RANGE_IMAGE` set to a digest-pinned published image, the pin is pulled (once) and used verbatim: the digest is the content key, so the local content-label discipline does not apply to it.

    Raises:
        RangeImageError: The env pin is not digest-pinned, or its pull failed.
        subprocess.CalledProcessError: The docker build failed (stderr attached).
        FileNotFoundError: docker is not on this host.
    """
    run = runner or run_docker
    pinned = os.environ.get(RANGE_IMAGE_ENV)
    if pinned:
        if _PINNED_REF.fullmatch(pinned) is None:
            raise RangeImageError(
                f"{RANGE_IMAGE_ENV} must be digest-pinned (repo@sha256:<hex>); "
                f"got {pinned!r}: a mutable tag could swap the hardened jail"
            )
        inspect = run(["docker", "image", "inspect", pinned, "--format", "ok"])
        if inspect.returncode != 0:
            pull = run(["docker", "pull", pinned])
            if pull.returncode != 0:
                raise RangeImageError(
                    f"pulling the pinned range image {pinned!r} failed: "
                    f"{pull.stderr.strip()[-300:]}"
                )
        return pinned
    content = _content_hash()
    inspect = run(
        [
            "docker",
            "image",
            "inspect",
            tag,
            "--format",
            f'{{{{index .Config.Labels "{CONTENT_LABEL}"}}}}',
        ]
    )
    if inspect.returncode == 0 and inspect.stdout.strip() == content:
        return tag
    build = run(
        [
            "docker",
            "build",
            "-q",
            "-t",
            tag,
            "--label",
            f"{CONTENT_LABEL}={content}",
            str(range_image_context()),
        ]
    )
    if build.returncode != 0:
        raise subprocess.CalledProcessError(
            build.returncode, build.args, build.stdout, build.stderr
        )
    return tag


def run_docker(argv: list[str]) -> "subprocess.CompletedProcess[str]":
    """The default runner: `subprocess.run` with captured text output, no check."""
    return subprocess.run(argv, capture_output=True, text=True)

"""A pinned external program as the attack-box provider: download, verify, cache, and run one release through `<program> attackbox` (protocol 1, `external.py`).

Each provider is data: a pin file `<name>.pin.json` in this package names one release by tag, source-tarball URL, and SHA-256, plus where the program sits in the extracted tree and the oldest version that speaks the protocol. The first use downloads the tarball, checks its digest before extracting anything, and moves the extracted tree into a per-user, per-tag cache with one atomic rename. `INSPECT_RANGES_ATTACK_BOX_PROGRAM` names an installed program instead, for hosts that cannot download. Either way, the program must report at least the pin's `min_version` before any verb runs.

The origin stamped into the attack-box record names the provider, tag, and digest (`<factory>:<name>/<tag>@sha256:<hex>`), so `down` and the reaper tear a box down with the release that booted it, even after the pin moves. Resolution stays cheap: the download and the `probe` run at eval init (`prepare_attack_box`) or, on paths with no eval init, inside the provider's first verb.
"""

import asyncio
import hashlib
import json
import logging
import os
import re
import tarfile
import tempfile
import urllib.request
from dataclasses import dataclass, replace
from importlib.resources import files
from pathlib import Path
from typing import Any

from .backend import (
    ENV_VAR,
    AttackBoxBackend,
    AttackBoxContext,
    parse_attack_box,
)
from .external import ExternalBoxError, ExternalProgramProvider

logger = logging.getLogger("inspect_ranges.attackbox")

PROGRAM_ENV = "INSPECT_RANGES_ATTACK_BOX_PROGRAM"
"""Overrides the downloaded release with an installed provider program (offline or air-gapped hosts)."""

FACTORY_PATH = f"{__name__}.pinned_attack_box"

BUILTIN_HINT = f"unset {ENV_VAR} to use the built-in box"

_NAME = re.compile(r"[a-z0-9][a-z0-9-]*")
_TAG = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*")
_SHA256 = re.compile(r"[0-9a-f]{64}")
_VERSION = re.compile(r"(\d+)\.(\d+)\.(\d+)")
_DOWNLOAD_TIMEOUT_S = 60.0
_VERSION_TIMEOUT_S = 30.0


def _version(text: str) -> tuple[int, int, int]:
    match = _VERSION.fullmatch(text)
    if match is None:
        raise ValueError(f"{text!r} is not a MAJOR.MINOR.PATCH version")
    major, minor, patch = match.groups()
    return int(major), int(minor), int(patch)


@dataclass(frozen=True)
class ProgramPin:
    """One release of an external attack-box provider program, and how to find and check the program in it."""

    name: str
    """The provider's name: its pin file's stem, and the first word of its `--version` line."""
    tag: str
    url: str
    """The release's source tarball."""
    sha256: str
    """The tarball's SHA-256, checked before anything is extracted."""
    entry: str
    """The program's path inside the tarball's one top-level directory."""
    min_version: str
    """The oldest version that speaks attack-box protocol 1."""
    url_template: str
    """The tarball URL for any tag (`{tag}`), so a recorded tag still downloads after the pin moves."""

    def __post_init__(self) -> None:
        # name and tag name cache directories, and entry a path under one:
        # none of them may climb out
        if not _NAME.fullmatch(self.name):
            raise ValueError(f"provider name {self.name!r} is not [a-z0-9-]+")
        if not _TAG.fullmatch(self.tag) or ".." in self.tag:
            raise ValueError(f"{self.name} tag {self.tag!r} is not a release tag")
        if not _SHA256.fullmatch(self.sha256):
            raise ValueError(
                f"{self.name} sha256 {self.sha256!r} is not 64 lowercase hex digits"
            )
        entry = Path(self.entry)
        if entry.is_absolute() or ".." in entry.parts:
            raise ValueError(f"{self.name} entry {self.entry!r} leaves the release")
        _version(self.min_version)

    @property
    def origin(self) -> str:
        """The `INSPECT_RANGES_ATTACK_BOX` value that selects exactly this release."""
        return f"{FACTORY_PATH}:{self.name}/{self.tag}@sha256:{self.sha256}"


def load_pin(name: str) -> ProgramPin:
    """The release this inspect-ranges version pins for provider `name` (`<name>.pin.json`).

    Raises:
        ValueError: No pin file has that name, or the file does not describe a pin.
    """
    if not _NAME.fullmatch(name):
        raise ValueError(f"provider name {name!r} is not [a-z0-9-]+")
    resource = files("inspect_ranges._attackbox").joinpath(f"{name}.pin.json")
    if not resource.is_file():
        raise ValueError(f"inspect-ranges pins no attack-box provider named {name!r}")
    data: dict[str, Any] = json.loads(resource.read_text())
    return ProgramPin(name=name, **data)


def pin_from_config(config: str | None) -> ProgramPin:
    """The release an origin's config names (`<name>/<tag>@sha256:<hex>`).

    A recorded tag that is no longer the pin keeps working: its URL follows from the pin file's template, and the recorded digest still guards the download.

    Raises:
        ValueError: The config is not `<name>/<tag>@sha256:<hex>`, or names no pinned provider.
    """
    name, slash, release = (config or "").partition("/")
    tag, at, digest = release.partition("@sha256:")
    if not (slash and at):
        raise ValueError(
            f"pinned attack-box config {config!r} is not '<name>/<tag>@sha256:<hex>'"
        )
    pinned = load_pin(name)
    if (tag, digest) == (pinned.tag, pinned.sha256):
        return pinned
    return replace(
        pinned, tag=tag, sha256=digest, url=pinned.url_template.format(tag=tag)
    )


def is_pinned_origin(origin: str | None) -> bool:
    """Whether `origin` selects a pinned release through this module's factory."""
    if origin is None:
        return False
    try:
        return parse_attack_box(origin).head == FACTORY_PATH
    except ValueError:
        return False


def default_program_cache() -> Path:
    """`~/.cache/inspect-ranges/programs`: one `<name>/<tag>` directory per release."""
    return Path.home() / ".cache" / "inspect-ranges" / "programs"


class ProgramTooOld(ExternalBoxError):
    """The program reports a version older than the pin's `min_version`, so it speaks no attack-box protocol."""


def ensure_program(pin: ProgramPin, *, cache_root: Path | None = None) -> Path:
    """The provider program for `pin`: the `INSPECT_RANGES_ATTACK_BOX_PROGRAM` override, the cached release, or a fresh verified download; checked against `min_version` before it is returned.

    Raises:
        ExternalBoxError: The override names no file, the download is refused (`INSPECT_RANGES_NEVER_PULL`) or fails, or the digest does not match (nothing is cached).
        ProgramTooOld: The program reports a version below `min_version`.
    """
    override = os.environ.get(PROGRAM_ENV)
    if override:
        program = Path(override)
        if not program.is_file():
            raise ExternalBoxError(f"{PROGRAM_ENV}={override!r} names no file")
    else:
        root = cache_root if cache_root is not None else default_program_cache()
        program = root / pin.name / pin.tag / pin.entry
        if not program.is_file():
            from .._dist.resolve import NEVER_PULL_ENV

            if os.environ.get(NEVER_PULL_ENV):
                raise ExternalBoxError(
                    f"{pin.name} {pin.tag} is not cached under {root}, and "
                    f"{NEVER_PULL_ENV} forbids downloading it",
                    remedy=f"set {PROGRAM_ENV} to an installed {pin.name} program",
                )
            _download_verified(pin, root / pin.name)
    require_min_version(program, pin, override=bool(override))
    return program


def require_min_version(program: Path, pin: ProgramPin, *, override: bool) -> None:
    """Refuse a program older than the pin's `min_version`, judged by `<program> --version` alone.

    The version flag is the one question every release answers before dispatching a verb, so asking it never reaches an older release's own handling of an unknown `attackbox` verb (glovebox's hands it to its agent launcher). The answer must be one line, `<name> <MAJOR.MINOR.PATCH>`, optionally followed by a parenthesized note.

    Raises:
        ExternalBoxError: The program does not answer, or answers outside that shape.
        ProgramTooOld: The version is below `min_version`.
    """
    reported = asyncio.run(_version_line(program))
    pattern = re.compile(rf"{re.escape(pin.name)} v?(\d+\.\d+\.\d+)(?: \([^\n]*\))?\n?")
    match = pattern.fullmatch(reported)
    if match is None:
        raise ExternalBoxError(
            f"`{program} --version` printed {reported!r}, not "
            f"'{pin.name} MAJOR.MINOR.PATCH'"
        )
    if _version(match.group(1)) < _version(pin.min_version):
        raise ProgramTooOld(
            f"{program} is {pin.name} {match.group(1)}, but the attack box needs "
            f"{pin.name} {pin.min_version} or newer (the first release that speaks "
            "attack-box protocol 1)",
            remedy=(
                f"point {PROGRAM_ENV} at {pin.name} {pin.min_version} or newer"
                if override
                else None
            ),
        )


async def _version_line(program: Path) -> str:
    """`<program> --version`'s stdout, bounded; the process never outlives the call."""
    try:
        process = await asyncio.create_subprocess_exec(
            str(program),
            "--version",
            stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
    except OSError as error:
        raise ExternalBoxError(
            f"`{program} --version` did not start: {error}"
        ) from error
    try:
        stdout, _ = await asyncio.wait_for(
            process.communicate(), timeout=_VERSION_TIMEOUT_S
        )
    except TimeoutError as error:
        raise ExternalBoxError(
            f"`{program} --version` did not answer within {_VERSION_TIMEOUT_S}s"
        ) from error
    finally:
        if process.returncode is None:
            process.kill()
            await process.wait()
    if process.returncode != 0:
        raise ExternalBoxError(f"`{program} --version` exited {process.returncode}")
    return stdout.decode(errors="replace")


def _download_verified(pin: ProgramPin, root: Path) -> None:
    """Download the release tarball, verify its SHA-256, and only then extract it into `root/<tag>` with one atomic rename.

    Raises:
        ExternalBoxError: The download failed, the digest does not match, the tarball does not extract safely, or its layout is not one top-level directory. Nothing is cached on any of these.
    """
    root.mkdir(parents=True, exist_ok=True)
    # staged inside the cache root so the final rename never crosses a filesystem
    with tempfile.TemporaryDirectory(dir=root, prefix=f".fetch-{pin.tag}-") as temp:
        staging = Path(temp)
        archive = staging / "release.tar.gz"
        digest = hashlib.sha256()
        try:
            with (
                urllib.request.urlopen(
                    pin.url, timeout=_DOWNLOAD_TIMEOUT_S
                ) as response,
                archive.open("wb") as sink,
            ):
                while chunk := response.read(1 << 20):
                    digest.update(chunk)
                    sink.write(chunk)
        except OSError as error:
            raise ExternalBoxError(
                f"downloading {pin.name} {pin.tag} from {pin.url} failed: {error}",
                remedy=f"set {PROGRAM_ENV} to an installed {pin.name} program",
            ) from error
        actual = digest.hexdigest()
        if actual != pin.sha256:
            raise ExternalBoxError(
                f"{pin.name} {pin.tag} from {pin.url} has sha256 {actual}, but the "
                f"pin requires {pin.sha256}; refusing it, and nothing was cached"
            )
        tree = staging / "tree"
        try:
            with tarfile.open(archive, "r:gz") as tar:
                tar.extractall(tree, filter="data")
        except tarfile.TarError as error:
            # the data filter refuses links out of the tree, device files and
            # absolute paths; a refusal leaves nothing cached
            raise ExternalBoxError(
                f"{pin.name} {pin.tag} from {pin.url} does not extract safely: {error}"
            ) from error
        tops = list(tree.iterdir())
        if len(tops) != 1 or not tops[0].is_dir():
            raise ExternalBoxError(
                f"{pin.name} {pin.tag} from {pin.url} does not hold exactly one "
                f"top-level directory ({len(tops)} entries)"
            )
        target = root / pin.tag
        try:
            os.rename(tops[0], target)
        except OSError:
            # a concurrent first use renamed its own complete tree in first
            if not (target / pin.entry).is_file():
                raise


class PinnedProgramProvider(ExternalProgramProvider):
    """The external-program provider over a pinned release."""

    async def teardown(self, project: str, reclaim_token: str) -> None:
        """Tear down `project`'s boxes; a release older than `min_version` never booted one, so there is nothing to tear down.

        The exception is an `INSPECT_RANGES_ATTACK_BOX_PROGRAM` override that is too old: the box may have booted through a different program, so that refusal stands.

        Raises:
            ExternalBoxError: As `ExternalProgramProvider.teardown`.
        """
        try:
            await super().teardown(project, reclaim_token)
        except ProgramTooOld:
            if os.environ.get(PROGRAM_ENV):
                raise
            # without this, every `up` that failed at boot under such a pin
            # would leave a project whose `down` refuses forever
            logger.warning(
                "attack-box teardown for %s: the recorded release predates "
                "attack-box protocol 1, so it booted no box; nothing to tear "
                "down (a box booted through %s needs that variable set where "
                "down runs)",
                project,
                PROGRAM_ENV,
            )


def _provider(pin: ProgramPin) -> PinnedProgramProvider:
    return PinnedProgramProvider(lambda: ensure_program(pin), builtin_hint=BUILTIN_HINT)


def pinned_attack_box(context: AttackBoxContext) -> AttackBoxBackend:
    """The `AttackBoxFactory` for a pinned release. Cheap: it neither downloads nor runs anything.

    Raises:
        ValueError: The config is not `<name>/<tag>@sha256:<hex>`, or names no pinned provider.
    """
    provider = _provider(pin_from_config(context.config))
    return AttackBoxBackend(provider=provider, doctor_probe=provider.doctor_probe)


def prepare_attack_box(origin: str) -> None:
    """Eval init's slow work for a pinned origin: fetch the release and `probe` the host. Blocking.

    Raises:
        ExternalBoxError: The host cannot boot the box; the message ends with the way to the built-in box.
    """
    pin = pin_from_config(parse_attack_box(origin).config)
    try:
        _provider(pin).probe()
    except ExternalBoxError as error:
        raise error.with_hint(BUILTIN_HINT) from error

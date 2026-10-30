"""A pinned external program as the attack-box provider: download, verify, cache, and run one release through `<program> attackbox` (protocol 1, `external.py`).

Each provider is data: a pin file (JSON, written by the deployment) names one release by name, tag, source-tarball URL, and SHA-256, plus where the program sits in the extracted tree. `INSPECT_RANGES_ATTACK_BOX=<factory>:<pin file path>` selects it. The first use downloads the tarball, checks its digest before extracting anything, and moves the extracted tree into a per-user, per-release cache with one atomic rename. `INSPECT_RANGES_ATTACK_BOX_PROGRAM` names an installed program instead, for hosts that cannot download. A release that predates the protocol refuses the unknown `attackbox` command at its first verb, and that refusal surfaces as the cause (`external.py`).

The origin stamped into the attack-box record carries the pin's contents, not its path (`attack_box_origin` canonicalizes the selected path into `<factory>:<pin JSON>`), so `down` and the reaper tear a box down with the release that booted it, even after the file changes. Resolution stays cheap: the download and the `probe` run at eval init (`prepare_attack_box`) or, on paths with no eval init, inside the provider's first verb.
"""

import hashlib
import json
import os
import re
import tarfile
import tempfile
import urllib.request
from dataclasses import asdict, dataclass
from importlib.resources import files
from pathlib import Path
from typing import Any, TextIO, cast

from .backend import (
    ENV_VAR,
    AttackBoxBackend,
    AttackBoxContext,
    parse_attack_box,
)
from .external import ExternalBoxError, ExternalProgramProvider

PROGRAM_ENV = "INSPECT_RANGES_ATTACK_BOX_PROGRAM"
"""Overrides the downloaded release with an installed provider program (offline or air-gapped hosts)."""

FACTORY_PATH = f"{__name__}.pinned_attack_box"

BUILTIN_HINT = f"set {ENV_VAR}=builtin to use the built-in box"

FALLBACK_QUESTION = "Fall back to the built-in attack box for this run? [y/N] "

DEFAULT_PIN = "glovebox.pin.json"
"""The packaged pin file an unset `INSPECT_RANGES_ATTACK_BOX` selects: the default provider, glovebox."""

_NAME = re.compile(r"[a-z0-9][a-z0-9-]*")
_TAG = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*")
_SHA256 = re.compile(r"[0-9a-f]{64}")
_DOWNLOAD_TIMEOUT_S = 60.0


@dataclass(frozen=True)
class ProgramPin:
    """One release of an external attack-box provider program, and how to find and check the program in it."""

    name: str
    """The provider's name, for messages and its cache directory."""
    tag: str
    url: str
    """The release's source tarball."""
    sha256: str
    """The tarball's SHA-256, checked before anything is extracted."""
    entry: str
    """The program's path inside the tarball's one top-level directory."""

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

    @property
    def origin(self) -> str:
        """The origin that selects exactly this release whatever later happens to its pin file: the pin's own contents, as compact JSON."""
        contents = json.dumps(asdict(self), sort_keys=True, separators=(",", ":"))
        return f"{FACTORY_PATH}:{contents}"

    @property
    def release_dir(self) -> str:
        """The release's cache directory under its provider's: tag plus a digest prefix, so two pins that reuse a tag never share a tree."""
        return f"{self.tag}-{self.sha256[:16]}"


def _pin_from_json(text: str, source: str) -> ProgramPin:
    try:
        data: Any = json.loads(text)
        if not isinstance(data, dict):
            raise ValueError("not a JSON object")
        fields = cast(dict[str, Any], data)
        if not all(isinstance(value, str) for value in fields.values()):
            raise ValueError("every field must be a string")
        return ProgramPin(**cast(dict[str, str], fields))
    except (ValueError, TypeError) as error:
        raise ValueError(f"{source} is not a pin ({error})") from error


def load_pin(path: Path) -> ProgramPin:
    """The release a deployment's pin file names.

    Raises:
        ValueError: The file is unreadable or does not describe a pin (`name`, `tag`, `url`, `sha256`, `entry`, nothing else).
    """
    try:
        text = path.read_text()
    except OSError as error:
        raise ValueError(f"pin file {path} is unreadable ({error})") from error
    return _pin_from_json(text, f"pin file {path}")


def default_attack_box_origin() -> str:
    """The origin an unset `INSPECT_RANGES_ATTACK_BOX` selects: the release the packaged `glovebox.pin.json` names."""
    resource = files("inspect_ranges._attackbox").joinpath(DEFAULT_PIN)
    return _pin_from_json(resource.read_text(), f"the packaged {DEFAULT_PIN}").origin


def pin_from_config(config: str | None) -> ProgramPin:
    """The release an origin's config names: a pin file's path, or (in a recorded origin) the pin's contents as JSON.

    Raises:
        ValueError: The config is absent, or names no readable pin.
    """
    if not config:
        raise ValueError(
            f"{FACTORY_PATH} needs a pin file: '{FACTORY_PATH}:<path to pin.json>'"
        )
    if config.startswith("{"):
        return _pin_from_json(config, "the recorded pin")
    return load_pin(Path(config))


def canonical_origin(origin: str) -> str:
    """`origin`, with a pinned program's pin file path replaced by the pin's contents; any other origin unchanged.

    Raises:
        ValueError: The origin selects a pinned program whose pin does not load.
    """
    parsed = parse_attack_box(origin)
    if parsed.head != FACTORY_PATH:
        return origin
    return pin_from_config(parsed.config).origin


def is_pinned_origin(origin: str | None) -> bool:
    """Whether `origin` selects a pinned release through this module's factory."""
    if origin is None:
        return False
    try:
        return parse_attack_box(origin).head == FACTORY_PATH
    except ValueError:
        return False


def default_program_cache() -> Path:
    """`~/.cache/inspect-ranges/programs`: one `<name>/<tag>-<digest prefix>` directory per release."""
    return Path.home() / ".cache" / "inspect-ranges" / "programs"


def ensure_program(pin: ProgramPin, *, cache_root: Path | None = None) -> Path:
    """The provider program for `pin`: the `INSPECT_RANGES_ATTACK_BOX_PROGRAM` override, the cached release, or a fresh verified download.

    Raises:
        ExternalBoxError: The override names no file, the download is refused (`INSPECT_RANGES_NEVER_PULL`) or fails, or the digest does not match (nothing is cached).
    """
    override = os.environ.get(PROGRAM_ENV)
    if override:
        program = Path(override)
        if not program.is_file():
            raise ExternalBoxError(f"{PROGRAM_ENV}={override!r} names no file")
    else:
        root = cache_root if cache_root is not None else default_program_cache()
        program = root / pin.name / pin.release_dir / pin.entry
        if not program.is_file():
            from .._dist.resolve import NEVER_PULL_ENV

            if os.environ.get(NEVER_PULL_ENV):
                raise ExternalBoxError(
                    f"{pin.name} {pin.tag} is not cached under {root}, and "
                    f"{NEVER_PULL_ENV} forbids downloading it",
                    remedy=f"set {PROGRAM_ENV} to an installed {pin.name} program",
                )
            _download_verified(pin, root / pin.name)
    return program


def _download_verified(pin: ProgramPin, root: Path) -> None:
    """Download the release tarball, verify its SHA-256, and only then extract it into `root/<release_dir>` with one atomic rename.

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
        target = root / pin.release_dir
        try:
            os.rename(tops[0], target)
        except OSError:
            # a concurrent first use renamed its own complete tree in first
            if not (target / pin.entry).is_file():
                raise


def _provider(pin: ProgramPin) -> ExternalProgramProvider:
    return ExternalProgramProvider(
        lambda: ensure_program(pin), builtin_hint=BUILTIN_HINT
    )


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


def confirm_fallback(
    error: ExternalBoxError, *, name: str, stdin: TextIO, stdout: TextIO
) -> bool:
    """Ask whether this run should use the built-in box instead; `False` without asking unless stdin and stdout are both terminals."""
    if not (stdin.isatty() and stdout.isatty()):
        return False
    stdout.write(f"The {name} attack box cannot run on this host:\n")
    stdout.write("".join(f"  {line}\n" for line in error.detail_lines()))
    stdout.write(FALLBACK_QUESTION)
    stdout.flush()
    return stdin.readline().strip().lower() in {"y", "yes"}


def prepare_with_fallback(origin: str, *, stdin: TextIO, stdout: TextIO) -> str | None:
    """`prepare_attack_box`, with the built-in box offered to a person at a terminal when the host cannot boot this one. Blocking.

    Returns:
        `origin` when the host can boot the box; `None` when it cannot and the person chose the built-in box for this run.

    Raises:
        ExternalBoxError: The host cannot boot the box and nobody chose the fallback (no terminal, or the answer was no).
    """
    try:
        prepare_attack_box(origin)
    except ExternalBoxError as error:
        name = pin_from_config(parse_attack_box(origin).config).name
        if confirm_fallback(error, name=name, stdin=stdin, stdout=stdout):
            return None
        raise
    return origin

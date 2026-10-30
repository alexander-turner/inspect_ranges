"""Locations: the one type with four forms (public hub, private OCI registry, one repository of a registry, image-layout directory), interchangeable everywhere a registry location appears (Journey B, ratified 2026-10-17).

A location maps an artifact name to a store: on a registry, each name is a repository under the location's path prefix (`registry.acme.net/ranges` plus `vulhub-zabbix` is `ranges/vulhub-zabbix`); the two-level hub form instead takes an optional repo-NAME prefix as its third segment (`docker.io/meridianlabsai/inspect-ranges` plus `attack` is the repo `meridianlabsai/inspect-ranges-attack`, keeping a shared org's namespace clean); the single-repository form (`registry.acme.net/mirror:ranges`, a tag prefix after the repository path) keeps every name in that one repository with the name in the tag, for registries where a repository is an allowlisted, pre-created resource (Amazon ECR); in a directory layout, every name shares one layout and refs carry the name. Reference naming per form: a registry repo tags its current root `latest` and each build's root `spec-<spec sha256>`; the single-repository form tags them `<prefix>--<name>` and `<prefix>--<name>--spec-<hash>`; a layout names them `<name>` and `<name>:spec-<hash>`. Resolution order is the spine's Q1: an explicit digest pin short-circuits, then the local cache, then the ordered search path, first match wins, so a deployment's own registry shadows public names deterministically.

The search path comes from `INSPECT_RANGES_REGISTRY` (comma-separated locations, first match wins) and defaults to the public org. Nothing in any spec or manifest names a registry host: redirection is configuration, never spec content.
"""

import os
import re
import urllib.parse
from pathlib import Path

from .errors import DistError
from .oci import ContentStore, OciLayout
from .registry import RegistryRepo

__all__ = [
    "DEFAULT_REGISTRY",
    "REGISTRY_ENV",
    "Location",
    "parse_location",
    "registry_locations",
]

DEFAULT_REGISTRY = "docker.io/meridianlabsai/inspect-ranges"
"""The public org location: the out-of-box search-path fallback carrying the reusable base tier. The third segment is the hub form's repo-name prefix (user decision, 2026-10-19): the hub is two-level, so project artifacts keep the org's namespace clean by spelling name `attack` as repo `meridianlabsai/inspect-ranges-attack`."""

REGISTRY_ENV = "INSPECT_RANGES_REGISTRY"
"""Ordered, comma-separated registry locations; prepending a deployment's own registry shadows public names deterministically."""

_HUB_REGISTRY = "https://registry-1.docker.io"


class Location:
    """One parsed location; `store_for(name)` yields the name's store, `ref_names(name, spec)` the form's reference naming."""

    def __init__(
        self,
        raw: str,
        *,
        directory: Path | None = None,
        registry_url: str | None = None,
        prefix: str = "",
        name_prefix: str = "",
        tag_prefix: str = "",
    ) -> None:
        self.raw = raw
        self._directory = directory
        self._registry_url = registry_url
        self._prefix = prefix.strip("/")
        self._name_prefix = name_prefix
        self._tag_prefix = tag_prefix

    @property
    def tag_prefix(self) -> str:
        """The single-repository form's tag prefix; empty for every other form."""
        return self._tag_prefix

    @property
    def is_directory(self) -> bool:
        return self._directory is not None

    @property
    def directory(self) -> Path | None:
        return self._directory

    def registry_base_and_prefix(self) -> tuple[str, str]:
        """The registry origin and path prefix (registry forms only)."""
        if self._registry_url is None:
            raise DistError(
                "location-invalid", f"{self.raw!r} is a directory, not a registry"
            )
        return self._registry_url, self._prefix

    def store_for(self, name: str, *, create: bool = False) -> ContentStore:
        """The store serving `name` at this location.

        Raises:
            DistError: `layout-invalid` for a missing/invalid directory form, `registry-protocol` for an illegal repo name (a one-slash published name against the two-level hub refuses here: group content lives in its own org or a nested-path registry, per the spine).
        """
        if self._directory is not None:
            layout = OciLayout(self._directory)
            return layout.ensure() if create else layout.open()
        assert self._registry_url is not None
        if self._tag_prefix:
            # one repository for every name: the name rides in the tag
            return RegistryRepo(self._registry_url, self._prefix)
        spelled = f"{self._name_prefix}-{name}" if self._name_prefix else name
        repo = f"{self._prefix}/{spelled}" if self._prefix else spelled
        if self._registry_url == _HUB_REGISTRY and repo.count("/") > 1:
            raise DistError(
                "registry-protocol",
                f"{name!r} under {self.raw!r} would need the nested repository {repo!r}, but the hub is two-level; group content lives in its own org or a nested-path registry (spine Q1)",
            )
        return RegistryRepo(self._registry_url, repo)

    def latest_ref(self, name: str) -> str:
        """The reference naming a name's current root at this location."""
        if self._directory is not None:
            return name
        if self._tag_prefix:
            return f"{self._tag_prefix}--{name}"
        return "latest"

    def spec_ref(self, name: str, spec_sha256: str) -> str:
        """The reference naming the build of `name` for an exact normalized-spec hash."""
        if self._directory is not None:
            return f"{name}:spec-{spec_sha256}"
        if self._tag_prefix:
            return f"{self._tag_prefix}--{name}--spec-{spec_sha256}"
        return f"spec-{spec_sha256}"

    def spec_hash_of(self, name: str, ref: str) -> str | None:
        """The normalized-spec hash a registry reference of `name` names, if it is a `spec_ref` (the inverse of `spec_ref`; registry forms only)."""
        marker = f"{self._tag_prefix}--{name}--spec-" if self._tag_prefix else "spec-"
        return ref.removeprefix(marker) if ref.startswith(marker) else None

    def name_of(self, ref: str) -> str | None:
        """The artifact name a single-repository tag names its current root for, or `None` for a build tag or a tag outside this location's prefix."""
        marker = f"{self._tag_prefix}--"
        if not self._tag_prefix or not ref.startswith(marker):
            return None
        name = ref.removeprefix(marker)
        return None if "--spec-" in name else name

    def describe(self) -> str:
        return self.raw


def parse_location(raw: str) -> Location:
    """Parse one location string into its form.

    Forms: an existing or absolute/relative directory path (`./archive`, `/mnt/mirror`), an explicit URL (`http://127.0.0.1:5056/ranges`), the hub shorthand (`docker.io/<org>`), or a bare `host/path` (served over https). A registry path may end in `:<tag prefix>` (`registry.acme.net/mirror:ranges`), the single-repository form: every name lives in that one repository, spelled into its tags.

    Raises:
        DistError: `location-invalid` for an empty or unparseable location.
    """
    raw = raw.strip()
    if not raw:
        raise DistError("location-invalid", "a registry location cannot be empty")
    if raw.startswith(("/", "./", "../", "~")):
        return Location(raw, directory=Path(raw).expanduser())
    if "://" in raw:
        parsed = urllib.parse.urlparse(raw)
        if parsed.scheme not in ("http", "https") or not parsed.netloc:
            raise DistError("location-invalid", f"{raw!r} is not a usable registry URL")
        prefix, tag_prefix = _split_tag_prefix(raw, parsed.path)
        return Location(
            raw,
            registry_url=f"{parsed.scheme}://{parsed.netloc}",
            prefix=prefix,
            tag_prefix=tag_prefix,
        )
    host, _, prefix = raw.partition("/")
    if host in ("docker.io", "index.docker.io", "registry-1.docker.io"):
        if ":" in prefix:
            raise DistError(
                "location-invalid",
                f"{raw!r}: the hub form has no single-repository prefix; "
                "write docker.io/<org> or docker.io/<org>/<repo-name-prefix>",
            )
        if not prefix:
            raise DistError(
                "location-invalid",
                "the hub form needs an org or user namespace (docker.io/<org>)",
            )
        # the hub is two-level, so a third segment is a REPO-NAME prefix, not
        # a path: docker.io/<org>/<prefix> spells name `attack` as the repo
        # `<org>/<prefix>-attack`, keeping a shared org's namespace clean
        # (user decision, 2026-10-19)
        org, slash, name_prefix = prefix.partition("/")
        if slash and not name_prefix:
            raise DistError(
                "location-invalid",
                f"{raw!r} has an empty repo-name prefix; write docker.io/<org> "
                "or docker.io/<org>/<repo-name-prefix>",
            )
        if "/" in name_prefix:
            raise DistError(
                "location-invalid",
                f"{raw!r} nests too deep for the hub form "
                "(docker.io/<org> or docker.io/<org>/<repo-name-prefix>)",
            )
        return Location(
            raw, registry_url=_HUB_REGISTRY, prefix=org, name_prefix=name_prefix
        )
    if "." not in host and ":" not in host and host != "localhost":
        # never cwd-dependent (round-3 N4): a directory location must LOOK like
        # a path (/, ./, ../, ~), so the same configured value parses the same
        # way everywhere
        raise DistError(
            "location-invalid",
            f"{raw!r} is not a registry host; directory locations start with /, ./, ../ or ~",
        )
    prefix, tag_prefix = _split_tag_prefix(raw, prefix)
    return Location(
        raw, registry_url=f"https://{host}", prefix=prefix, tag_prefix=tag_prefix
    )


_TAG_PREFIX = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,63}")


def _split_tag_prefix(raw: str, path: str) -> tuple[str, str]:
    """A registry path and its single-repository tag prefix (`mirror:ranges` is `("mirror", "ranges")`; no colon means the per-name form)."""
    repo, colon, tag_prefix = path.partition(":")
    if not colon:
        return path, ""
    if not repo.strip("/"):
        raise DistError(
            "location-invalid",
            f"{raw!r} names a tag prefix but no repository; write <host>/<repository>:<prefix>",
        )
    if not _TAG_PREFIX.fullmatch(tag_prefix) or "--" in tag_prefix:
        raise DistError(
            "location-invalid",
            f"{raw!r} has tag prefix {tag_prefix!r}; expected tag characters "
            "(letters, digits, '_', '.', '-') without '--', which separates the "
            "prefix from the name",
        )
    return repo, tag_prefix


def registry_locations(explicit: str | None = None) -> list[Location]:
    """The ordered search path: an explicit override, else `INSPECT_RANGES_REGISTRY`, else the public org."""
    raw = explicit if explicit is not None else os.environ.get(REGISTRY_ENV)
    if raw is None or not raw.strip():
        raw = DEFAULT_REGISTRY
    return [parse_location(part) for part in raw.split(",") if part.strip()]

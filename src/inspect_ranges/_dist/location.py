"""Locations: the one type with three forms (public hub, private OCI registry, image-layout directory), interchangeable everywhere a registry location appears (Journey B, ratified 2026-10-17).

A location maps an artifact name to a store: on a registry, each name is a repository under the location's path prefix (`docker.io/meridianlabsai` plus `ubuntu-focal` is the repo `meridianlabsai/ubuntu-focal`; `registry.acme.net/ranges` plus `vulhub-zabbix` is `ranges/vulhub-zabbix`); in a directory layout, every name shares one layout and refs carry the name. Reference naming per form: a registry repo tags its current root `latest` and each build's root `spec-<spec sha256>`; a layout names them `<name>` and `<name>:spec-<hash>`. Resolution order is the spine's Q1: an explicit digest pin short-circuits, then the local cache, then the ordered search path, first match wins, so a deployment's own registry shadows public names deterministically.

The search path comes from `INSPECT_RANGES_REGISTRY` (comma-separated locations, first match wins) and defaults to the public org. Nothing in any spec or manifest names a registry host: redirection is configuration, never spec content.
"""

import os
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

DEFAULT_REGISTRY = "docker.io/meridianlabsai"
"""The public org: the out-of-box search-path fallback carrying the reusable base tier."""

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
    ) -> None:
        self.raw = raw
        self._directory = directory
        self._registry_url = registry_url
        self._prefix = prefix.strip("/")

    @property
    def is_directory(self) -> bool:
        return self._directory is not None

    def store_for(self, name: str, *, create: bool = False) -> ContentStore:
        """The store serving `name` at this location.

        Raises:
            DistError: `layout-invalid` for a missing/invalid directory form, `registry-protocol` for an illegal repo name (a one-slash published name against the two-level hub refuses here: group content lives in its own org or a nested-path registry, per the spine).
        """
        if self._directory is not None:
            layout = OciLayout(self._directory)
            return layout.ensure() if create else layout.open()
        assert self._registry_url is not None
        repo = f"{self._prefix}/{name}" if self._prefix else name
        if self._registry_url == _HUB_REGISTRY and repo.count("/") > 1:
            raise DistError(
                "registry-protocol",
                f"{name!r} under {self.raw!r} would need the nested repository {repo!r}, but the hub is two-level; group content lives in its own org or a nested-path registry (spine Q1)",
            )
        return RegistryRepo(self._registry_url, repo)

    def latest_ref(self, name: str) -> str:
        """The reference naming a name's current root at this location."""
        return name if self._directory is not None else "latest"

    def spec_ref(self, name: str, spec_sha256: str) -> str:
        """The reference naming the build of `name` for an exact normalized-spec hash."""
        if self._directory is not None:
            return f"{name}:spec-{spec_sha256}"
        return f"spec-{spec_sha256}"

    def describe(self) -> str:
        return self.raw


def parse_location(raw: str) -> Location:
    """Parse one location string into its form.

    Forms: an existing or absolute/relative directory path (`./archive`, `/mnt/mirror`), an explicit URL (`http://127.0.0.1:5056/ranges`), the hub shorthand (`docker.io/<org>`), or a bare `host/path` (served over https).

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
        return Location(
            raw,
            registry_url=f"{parsed.scheme}://{parsed.netloc}",
            prefix=parsed.path,
        )
    host, _, prefix = raw.partition("/")
    if host in ("docker.io", "index.docker.io", "registry-1.docker.io"):
        if not prefix:
            raise DistError(
                "location-invalid",
                "the hub form needs an org or user namespace (docker.io/<org>)",
            )
        return Location(raw, registry_url=_HUB_REGISTRY, prefix=prefix)
    if "." not in host and ":" not in host and host != "localhost":
        # never cwd-dependent (round-3 N4): a directory location must LOOK like
        # a path (/, ./, ../, ~), so the same configured value parses the same
        # way everywhere
        raise DistError(
            "location-invalid",
            f"{raw!r} is not a registry host; directory locations start with /, ./, ../ or ~",
        )
    return Location(raw, registry_url=f"https://{host}", prefix=prefix)


def registry_locations(explicit: str | None = None) -> list[Location]:
    """The ordered search path: an explicit override, else `INSPECT_RANGES_REGISTRY`, else the public org."""
    raw = explicit if explicit is not None else os.environ.get(REGISTRY_ENV)
    if raw is None or not raw.strip():
        raw = DEFAULT_REGISTRY
    return [parse_location(part) for part in raw.split(",") if part.strip()]

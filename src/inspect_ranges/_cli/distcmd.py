"""`inspect-ranges push` / `pull`: publish a built range's closure; resolve and fetch the build matching this spec.

Verb composition (the phase's Q8 decision, recorded here): `push` and `pull` are the RANGE closure verbs, spec-driven by default in the Journey A/B tradition (bare in a range directory, `.` semantics everywhere); the catalog-image verbs live under `images` (`images pull` fetches a bare name into the cache, `images refresh` is the explicit move-forward act), so `pull` never means two different things. `mirror` arrives in slice 5.
"""

import re
from pathlib import Path

import click

from .._build.manifest import default_build_cache, load_manifest
from .._build.recipes import default_recipe_cache
from .._compiler.plan import spec_sha256
from .._dist import DistError
from .._dist.location import parse_location, registry_locations
from .._dist.progress import TransferDisplay
from .._dist.resolve import PullReport, pull_pinned, pull_range, push_range
from .._runtime.images import default_image_cache
from ..schema import load_range
from ..types import IssueError
from .specpath import resolve_spec_path


def _caches(
    image_cache: Path | None, build_cache: Path | None, recipe_cache: Path | None
) -> tuple[Path, Path, Path]:
    return (
        image_cache or default_image_cache(),
        build_cache or default_build_cache(),
        recipe_cache or default_recipe_cache(),
    )


@click.command()
@click.argument("spec", required=False, type=click.Path(path_type=Path))
@click.option(
    "--to",
    "to_location",
    default=None,
    help="Destination location (registry or OCI-layout directory). Default: the first configured registry (INSPECT_RANGES_REGISTRY). Pushing to the public org is the project publisher's job, not a user move.",
)
@click.option("--image-cache", type=click.Path(path_type=Path), default=None)
@click.option("--build-cache", type=click.Path(path_type=Path), default=None)
@click.option("--recipe-cache", type=click.Path(path_type=Path), default=None)
def push(
    spec: Path | None,
    to_location: str | None,
    image_cache: Path | None,
    build_cache: Path | None,
    recipe_cache: Path | None,
) -> None:
    """Publish the current range's build (its manifest's transitive closure) to a location."""
    spec_path = resolve_spec_path(spec)
    try:
        # the destination resolves first: a missing destination is a config
        # refusal that must not depend on cache state (round-3 N5)
        if to_location is not None:
            location = parse_location(to_location)
        else:
            import os

            configured = os.environ.get("INSPECT_RANGES_REGISTRY", "").strip()
            if not configured:
                # pushing to the public org is the publisher's job, never a
                # default (round-3 N5): user ranges must not aim anywhere
                # public without an explicit destination
                raise click.ClickException(
                    "[no-push-location] no destination configured; pass --to "
                    "or set INSPECT_RANGES_REGISTRY to your deployment's "
                    "registry (the public org is never a push default)"
                )
            location = registry_locations(configured)[0]
        validated = load_range(spec_path)
        images, builds, recipes = _caches(image_cache, build_cache, recipe_cache)
        manifest = load_manifest(builds, validated.meta.name)
        if manifest is None:
            raise click.ClickException(
                f"[range-not-built] no build manifest for "
                f"{validated.meta.name!r} in {builds}; run 'inspect-ranges build' first"
            )
        click.echo(
            f"manifest  {manifest.range_name} (spec sha256:{manifest.spec_sha256[:6]}...) "
            f"-> {location.describe()}"
        )
        root = push_range(
            manifest,
            location,
            image_cache=images,
            build_cache=builds,
            range_dir=spec_path.parent,
            recipe_cache=recipes,
            progress=TransferDisplay(),
        )
        click.echo(f"push OK   {manifest.range_name}@{root.digest}")
    except DistError as error:
        raise click.ClickException(str(error)) from error
    except IssueError as error:
        raise click.ClickException(str(error)) from error


@click.command()
@click.argument("target", required=False)
@click.option(
    "--pin",
    default=None,
    help="Pull an exact published root by digest (name@sha256 form: pass the sha256:... digest) instead of resolving by this spec's hash.",
)
@click.option(
    "--from",
    "from_location",
    default=None,
    help="Location override; default is the configured search path (INSPECT_RANGES_REGISTRY, first match wins).",
)
@click.option("--image-cache", type=click.Path(path_type=Path), default=None)
@click.option("--build-cache", type=click.Path(path_type=Path), default=None)
@click.option("--recipe-cache", type=click.Path(path_type=Path), default=None)
def pull(
    target: str | None,
    pin: str | None,
    from_location: str | None,
    image_cache: Path | None,
    build_cache: Path | None,
    recipe_cache: Path | None,
) -> None:
    """Resolve and fetch a published build: bare (this directory's range.yaml, matched by its exact normalized-spec hash), a spec path, or the no-spec `name@sha256:...` form (Journey B's pulling-without-a-spec-in-hand)."""
    try:
        images, builds, recipes = _caches(image_cache, build_cache, recipe_cache)
        locations = registry_locations(from_location)
        pinned = _parse_pinned(target)
        if pinned is not None:
            name, digest = pinned
            report = pull_pinned(
                name,
                digest,
                locations,
                image_cache=images,
                build_cache=builds,
                recipe_cache=recipes,
                progress=TransferDisplay(),
            )
            click.echo(f"resolve   {name}@{report.root} ({report.location})")
            _echo_fetch(report)
            return
        spec_path = resolve_spec_path(Path(target) if target else None)
        validated = load_range(spec_path)
        report = pull_range(
            validated,
            locations,
            image_cache=images,
            build_cache=builds,
            recipe_cache=recipes,
            pin=pin,
            progress=TransferDisplay(),
        )
        click.echo(
            f"resolve   spec sha256:{spec_sha256(validated)[:6]}... -> "
            f"{validated.meta.name}@{report.root} ({report.location})"
        )
        _echo_fetch(report)
    except DistError as error:
        raise click.ClickException(str(error)) from error
    except IssueError as error:
        raise click.ClickException(str(error)) from error


_PINNED = re.compile(r"\A([a-z0-9][a-z0-9_-]*)@(sha256:[0-9a-f]{64})\Z")


def _parse_pinned(target: str | None) -> tuple[str, str] | None:
    if target is None:
        return None
    match = _PINNED.fullmatch(target)
    return (match.group(1), match.group(2)) if match else None


def _echo_fetch(report: PullReport) -> None:
    fetched, present = len(report.result.fetched), len(report.result.present)
    click.echo(f"fetch     {fetched} fetched, {present} already present, verified")
    if report.result.superseded_built_at:
        click.echo(
            f"supersede local manifest built {report.result.superseded_built_at}"
        )
    click.echo("pull OK")

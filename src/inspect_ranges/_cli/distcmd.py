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
@click.option(
    "--image-cache",
    type=click.Path(path_type=Path),
    default=None,
    show_default="~/.cache/inspect-ranges/images (or INSPECT_RANGES_IMAGE_CACHE)",
    help="Image cache holding the build's artifacts.",
)
@click.option(
    "--build-cache",
    type=click.Path(path_type=Path),
    default=None,
    show_default="~/.cache/inspect-ranges/builds (or INSPECT_RANGES_BUILD_CACHE)",
    help="Builds cache holding the manifest to publish.",
)
@click.option(
    "--recipe-cache",
    type=click.Path(path_type=Path),
    default=None,
    show_default="~/.cache/inspect-ranges/recipes (or INSPECT_RANGES_RECIPE_CACHE)",
    help="Recipe cache for resolving the manifest's recipe bundles.",
)
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
        display = TransferDisplay()
        try:
            root = push_range(
                manifest,
                location,
                image_cache=images,
                build_cache=builds,
                range_dir=spec_path.parent,
                recipe_cache=recipes,
                progress=display,
            )
        finally:
            display.close()
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
@click.option(
    "--image-cache",
    type=click.Path(path_type=Path),
    default=None,
    show_default="~/.cache/inspect-ranges/images (or INSPECT_RANGES_IMAGE_CACHE)",
    help="Image cache artifacts materialize into.",
)
@click.option(
    "--build-cache",
    type=click.Path(path_type=Path),
    default=None,
    show_default="~/.cache/inspect-ranges/builds (or INSPECT_RANGES_BUILD_CACHE)",
    help="Builds cache the pulled manifest lands in.",
)
@click.option(
    "--recipe-cache",
    type=click.Path(path_type=Path),
    default=None,
    show_default="~/.cache/inspect-ranges/recipes (or INSPECT_RANGES_RECIPE_CACHE)",
    help="Recipe cache pulled bundles extract into.",
)
def pull(
    target: str | None,
    pin: str | None,
    from_location: str | None,
    image_cache: Path | None,
    build_cache: Path | None,
    recipe_cache: Path | None,
) -> None:
    """Resolve and fetch a published build: bare (this directory's range.yaml, matched by its exact normalized-spec hash), a spec path, or the no-spec `name@sha256:...` form (Journey B's pulling-without-a-spec-in-hand)."""
    display = TransferDisplay()
    try:
        images, builds, recipes = _caches(image_cache, build_cache, recipe_cache)
        locations = registry_locations(from_location)
        pinned = _parse_pinned(target)
        if pinned is not None:
            if pin is not None:
                raise click.UsageError(
                    "pass EITHER the name@sha256 form OR --pin, not both"
                )
            name, digest = pinned
            report = pull_pinned(
                name,
                digest,
                locations,
                image_cache=images,
                build_cache=builds,
                recipe_cache=recipes,
                progress=display,
            )
            display.close()
            click.echo(f"resolve   {name}@{report.root} ({report.location})")
            _echo_fetch(report)
            return
        if target is not None and "@sha256:" in target:
            # pin intent is unambiguous; a malformed pin must not fall through
            # to spec-path semantics with a misleading remedy (round-2 N8)
            raise click.ClickException(
                f"[malformed-pin] {target!r} is not a valid name@sha256 form "
                "(lowercase name, full 64-hex digest)"
            )
        spec_path = resolve_spec_path(Path(target) if target else None)
        validated = load_range(spec_path)
        report = pull_range(
            validated,
            locations,
            image_cache=images,
            build_cache=builds,
            recipe_cache=recipes,
            pin=pin,
            progress=display,
        )
        display.close()
        click.echo(
            f"resolve   spec sha256:{spec_sha256(validated)[:6]}... -> "
            f"{validated.meta.name}@{report.root} ({report.location})"
        )
        _echo_fetch(report)
    except DistError as error:
        display.close()
        raise click.ClickException(str(error)) from error
    except IssueError as error:
        display.close()
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


@click.command()
@click.argument("target", required=False)
@click.option("--from", "from_location", required=True, help="Source location.")
@click.option("--to", "to_location", required=True, help="Destination location.")
def mirror(
    target: str | None,
    from_location: str,
    to_location: str,
) -> None:
    """Mirror between locations: bare (whole source, the seed/sync move), a NAME, a `name@sha256:` pin, or a spec path (the cross-group move: the local range.yaml selects the source build exactly). A spec target must LOOK like a path (`.`, `./dir`, `/abs`, or `*.yaml`); a bare word is always a name, never a local directory, so dispatch is identical in every working directory."""
    from .._dist.mirror import mirror_names, mirror_one, source_names

    display = TransferDisplay()
    try:
        source = parse_location(from_location)
        destination = parse_location(to_location)
        pinned = _parse_pinned(target)
        if pinned is not None:
            name, digest = pinned
            from .._dist.oci import MEDIA_TYPE_INDEX, Descriptor

            result = mirror_one(
                name,
                source,
                destination,
                root=Descriptor(media_type=MEDIA_TYPE_INDEX, digest=digest, size=0),
                progress=display,
            )
            display.close()
            click.echo(
                f"mirror    {name}: {len(result.copied)} copied, "
                f"{len(result.present)} already present (verified) root {result.root}"
            )
            return
        if target is not None and (
            target == "."
            or target.endswith((".yaml", ".yml"))
            or target.startswith(("/", "./", "../", "~"))
        ):
            # path-looking targets only (never cwd-dependent, the round-3 N4
            # principle): `mirror distmini` is NAME semantics even when a
            # ./distmini checkout exists; the spec form is `mirror ./distmini`
            # the cross-group move: the local spec selects the source build
            spec_path = resolve_spec_path(Path(target))
            validated = load_range(spec_path)
            name = validated.meta.name
            store = source.store_for(name)
            root = store.ref(source.spec_ref(name, spec_sha256(validated)))
            result = mirror_one(name, source, destination, root=root, progress=display)
            display.close()
            click.echo(
                f"resolve   spec sha256:{spec_sha256(validated)[:6]}... -> "
                f"{name}@{result.root}"
            )
            click.echo(
                f"mirror    {name}: {len(result.copied)} copied, "
                f"{len(result.present)} already present (verified)"
            )
            return
        if target is not None:
            result = mirror_one(target, source, destination, progress=display)
            display.close()
            click.echo(
                f"mirror    {target}: {len(result.copied)} copied, "
                f"{len(result.present)} already present (verified)"
            )
            return
        names = source_names(source)
        report = mirror_names(names, source, destination, progress=display)
        display.close()
        click.echo(
            f"mirror    {len(names)} artifacts: {report.present} blobs already "
            f"present, {report.copied} copied (verified)"
        )
    except DistError as error:
        display.close()
        raise click.ClickException(str(error)) from error
    except IssueError as error:
        display.close()
        raise click.ClickException(str(error)) from error


@click.command()
@click.argument("spec", required=False, type=click.Path(path_type=Path))
@click.option(
    "--guest",
    default=None,
    help="Built guest whose realized image promotes (reads the range directory's manifest).",
)
@click.option(
    "--as", "catalog_name", default=None, help="The bare catalog name to publish under."
)
@click.option(
    "--golden",
    default=None,
    help="Promote a cache golden under its own name instead of a built guest.",
)
@click.option(
    "--to",
    "to_location",
    required=True,
    help="Destination location (the public org on publish day; any location form).",
)
@click.option(
    "--image-cache",
    type=click.Path(path_type=Path),
    default=None,
    show_default="~/.cache/inspect-ranges/images (or INSPECT_RANGES_IMAGE_CACHE)",
    help="Image cache holding the artifacts.",
)
@click.option(
    "--build-cache",
    type=click.Path(path_type=Path),
    default=None,
    show_default="~/.cache/inspect-ranges/builds (or INSPECT_RANGES_BUILD_CACHE)",
    help="Builds cache holding the factory manifest (guest promotion).",
)
def publish(
    spec: Path | None,
    guest: str | None,
    catalog_name: str | None,
    golden: str | None,
    to_location: str,
    image_cache: Path | None,
    build_cache: Path | None,
) -> None:
    """The deliberate promotion act: a built guest's realized image (or a cache golden) becomes a bare catalog name other ranges' `image:` lines consume; the location's catalog list updates with it."""
    from .._dist.catalog import publish_golden, publish_realized

    display = TransferDisplay()
    try:
        location = parse_location(to_location)
        images, builds, _ = _caches(image_cache, build_cache, None)
        if golden is not None:
            if guest is not None or catalog_name is not None or spec is not None:
                raise click.UsageError(
                    "--golden stands alone (its name is the catalog name; no spec argument)"
                )
            if not re.fullmatch(r"[a-z0-9][a-z0-9._-]*", golden):
                raise click.UsageError(
                    f"{golden!r} is not a catalog name (lowercase slug)"
                )
            root = publish_golden(golden, location, image_cache=images)
            display.close()
            click.echo(f"publish OK  {golden}@{root.digest} -> {location.describe()}")
            return
        if guest is None or catalog_name is None:
            raise click.UsageError("promotion needs --guest and --as (or --golden)")
        if not re.fullmatch(r"[a-z0-9][a-z0-9._-]*", catalog_name):
            raise click.UsageError(
                f"{catalog_name!r} is not a catalog name (lowercase slug: letters, digits, ., _, -)"
            )
        spec_path = resolve_spec_path(spec)
        validated = load_range(spec_path)
        manifest = load_manifest(builds, validated.meta.name)
        if manifest is None:
            raise click.ClickException(
                f"[range-not-built] no build manifest for {validated.meta.name!r}; "
                "run 'inspect-ranges build' first"
            )
        root = publish_realized(
            manifest, guest, catalog_name, location, image_cache=images
        )
        display.close()
        click.echo(
            f"publish OK  {catalog_name}@{root.digest} -> {location.describe()} "
            f"(from {validated.meta.name}/{guest})"
        )
    except DistError as error:
        display.close()
        raise click.ClickException(str(error)) from error
    except IssueError as error:
        display.close()
        raise click.ClickException(str(error)) from error

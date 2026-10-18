"""`inspect-ranges images`: golden derivation and cache listing."""

from pathlib import Path

import click

from .._build.manifest import default_build_cache, recorded_realized_files
from .._runtime import DeriveError, derive_golden, list_images
from .._runtime.images import RECIPE_VERSION, default_image_cache


@click.group()
def images() -> None:
    """Manage the golden image cache."""


@images.command()
@click.argument("vendor", type=click.Path(exists=True, path_type=Path))
@click.option(
    "--sha256",
    "vendor_sha256",
    required=True,
    help="Required digest pin for the vendor image (hex or sha256:-prefixed).",
)
@click.option(
    "--name", default=None, help="Golden name (default: <vendor stem>-golden)."
)
@click.option(
    "--image-cache",
    type=click.Path(path_type=Path),
    default=None,
    show_default="~/.cache/inspect-ranges/images (or INSPECT_RANGES_IMAGE_CACHE)",
    help="Image cache the golden is derived into.",
)
@click.option(
    "--daemon-bundle",
    "daemon_bundle",
    type=click.Path(path_type=Path),
    default=None,
    help="Directory holding the daemon-bundle artifact and its daemon.json (default: the shared artifact cache; publish one with `inspect-ranges daemon-bundle`).",
)
@click.option(
    "--daemon-sha256",
    "daemon_sha256",
    default=None,
    help="Out-of-band pin for the daemon bundle digest (printed by `inspect-ranges daemon-bundle` at publish). Without it, the sidecar proves internal consistency only.",
)
def derive(
    vendor: Path,
    vendor_sha256: str,
    name: str | None,
    image_cache: Path | None,
    daemon_bundle: Path | None,
    daemon_sha256: str | None,
) -> None:
    """Derive a daemon-baked golden from a digest-pinned vendor cloud image.

    Offline derivation (Ubuntu noble vendor images in v1): verifies the vendor digest, bakes the pinned control daemon, disables ssh and the resolved stub listener, and records provenance beside the golden. Idempotent: re-running with the same inputs is a cache hit.
    """
    if image_cache is None:
        image_cache = default_image_cache()
    try:
        metadata, hit = derive_golden(
            vendor,
            vendor_sha256,
            image_cache,
            name=name,
            artifact_dir=daemon_bundle,
            daemon_sha256=daemon_sha256,
        )
    except DeriveError as error:
        raise click.ClickException(str(error)) from error
    except OSError as error:
        raise click.ClickException(f"derive failed on this host: {error}") from error
    if daemon_sha256 is None:
        click.echo(
            "daemon artifact unpinned: sidecar-only verification; "
            "pass --daemon-sha256 for out-of-band pinning"
        )
    verb = "cache hit" if hit else "derived"
    click.echo(f"{verb}: {metadata.file}  sha256:{metadata.golden_sha256}")
    click.echo(
        f"  vendor {metadata.vendor_file} sha256:{metadata.vendor_sha256}"
        f"  daemon {metadata.daemon.name} v{metadata.daemon.version}"
    )


@images.command(name="list")
@click.option(
    "--image-cache",
    type=click.Path(path_type=Path),
    default=None,
    show_default="~/.cache/inspect-ranges/images (or INSPECT_RANGES_IMAGE_CACHE)",
    help="Image cache to list.",
)
def list_cmd(image_cache: Path | None) -> None:
    """List the cache: managed goldens with provenance, then unmanaged files."""
    if image_cache is None:
        image_cache = default_image_cache()
    try:
        managed, realized, unmanaged = list_images(image_cache)
    except OSError as error:
        raise click.ClickException(f"cannot read image cache: {error}") from error
    if not managed and not realized and not unmanaged:
        click.echo(f"image cache {image_cache} is empty")
        return
    for metadata in managed:
        flags = ""
        if not (image_cache / metadata.file).is_file():
            flags += "  MISSING GOLDEN (interrupted derive; re-run derive)"
        if metadata.recipe_version != RECIPE_VERSION:
            # mirror doctor's three-way split: an unparseable version must not
            # be labeled with an ordering that could not be computed
            try:
                cache_newer: bool | None = int(metadata.recipe_version) > int(
                    RECIPE_VERSION
                )
            except ValueError:
                cache_newer = None
            if cache_newer:
                flags += f"  RECIPE MISMATCH (cache v{metadata.recipe_version} vs tool v{RECIPE_VERSION}; upgrade the tool or re-derive)"
            elif cache_newer is None:
                flags += f"  RECIPE UNPARSEABLE (v{metadata.recipe_version}, not v{RECIPE_VERSION}; re-derive)"
            else:
                flags += f"  STALE RECIPE (v{metadata.recipe_version} < v{RECIPE_VERSION}; re-derive)"
        click.echo(
            f"{metadata.file}  sha256:{metadata.golden_sha256[:12]}  "
            f"vendor={metadata.vendor_file}  daemon={metadata.daemon.name} v{metadata.daemon.version}  "
            f"recipe=v{metadata.recipe_version}  created={metadata.created}{flags}"
        )
    from .._build.capture import live_project_files
    from .._runtime.ownership import default_state_dir

    recorded = recorded_realized_files(default_build_cache()) | live_project_files(
        default_state_dir()
    )
    reclaimable = 0
    for listing in realized:
        flags = ""
        if listing.file not in recorded:
            # no manifest references this generation: a superseded or orphaned
            # capture (parked-decisions item 1)
            try:
                reclaimable += (image_cache / listing.file).stat().st_size
            except OSError:
                pass
            flags = "  SUPERSEDED (no manifest references it; images prune reclaims)"
        click.echo(
            f"  {listing.file}  realized {listing.range_name}/{listing.guest}  key {listing.build_key[:12]}  ({listing.created}){flags}"
        )
    if reclaimable:
        click.echo(
            f"  {reclaimable / (1024 * 1024):.0f} MB reclaimable: inspect-ranges images prune"
        )
    for file in unmanaged:
        if file.endswith(".deriving"):
            note = (
                "stale derivation temp; a locked derive sweeps its own, remove by hand"
            )
        elif file.endswith((".img.qcow2", ".iso.qcow2")):
            note = (
                "legacy naming from before the image-name unification: "
                "references now resolve without the double suffix; re-derive or rename"
            )
        else:
            note = "unmanaged: no provenance metadata"
        click.echo(f"{file}  ({note})")


@images.command("pull")
@click.argument("name")
@click.option(
    "--from",
    "from_location",
    default=None,
    help="Location override; default is the configured search path (INSPECT_RANGES_REGISTRY).",
)
@click.option("--image-cache", type=click.Path(path_type=Path), default=None)
def images_pull(name: str, from_location: str | None, image_cache: Path | None) -> None:
    """Fetch a published catalog image's chain into the cache (sticky thereafter: later builds keep resolving the cached artifact until an explicit refresh)."""
    from .._dist import DistError
    from .._dist.location import registry_locations
    from .._dist.progress import TransferDisplay
    from .._dist.resolve import pull_image

    cache = image_cache or default_image_cache()
    display = TransferDisplay()
    try:
        pulled = pull_image(
            name,
            registry_locations(from_location),
            image_cache=cache,
            progress=display,
        )
    except DistError as error:
        display.close()
        raise click.ClickException(str(error)) from error
    display.close()
    if pulled is None:
        raise click.ClickException(
            f"[image-not-published] no configured location publishes {name!r}"
        )
    location, result = pulled
    click.echo(
        f"pull OK   {name} from {location} "
        f"({len(result.fetched)} fetched, {len(result.present)} already present)"
    )


@images.command("refresh")
@click.argument("names", nargs=-1, required=True)
@click.option(
    "--from",
    "from_location",
    default=None,
    help="Location override; default is the configured search path (INSPECT_RANGES_REGISTRY).",
)
@click.option("--image-cache", type=click.Path(path_type=Path), default=None)
def images_refresh(
    names: tuple[str, ...], from_location: str | None, image_cache: Path | None
) -> None:
    """The explicit move-forward act: re-resolve bare names against the search path and replace cached chains that moved; the next build's keys change accordingly."""
    from .._dist import DistError
    from .._dist.location import registry_locations
    from .._dist.progress import TransferDisplay
    from .._dist.resolve import refresh_image

    cache = image_cache or default_image_cache()
    locations = registry_locations(from_location)
    for name in names:
        display = TransferDisplay()
        try:
            refreshed = refresh_image(
                name, locations, image_cache=cache, progress=display
            )
        except DistError as error:
            display.close()
            raise click.ClickException(str(error)) from error
        display.close()
        assert refreshed is not None
        location, result = refreshed
        state = "updated" if result.fetched else "already current"
        click.echo(f"refresh   {name}: {state} (from {location})")


@images.command("prune")
@click.option(
    "--image-cache",
    type=click.Path(path_type=Path),
    default=None,
    show_default="~/.cache/inspect-ranges/images (or INSPECT_RANGES_IMAGE_CACHE)",
    help="Image cache to prune.",
)
@click.option(
    "--build-cache",
    type=click.Path(path_type=Path),
    default=None,
    show_default="~/.cache/inspect-ranges/builds (or INSPECT_RANGES_BUILD_CACHE)",
    help="Builds cache whose manifests define liveness.",
)
@click.option("--yes", is_flag=True, help="Delete instead of reporting.")
@click.option(
    "--force",
    is_flag=True,
    help="Prune even while registered projects exist (their referenced files are still excluded).",
)
def prune(
    image_cache: Path | None, build_cache: Path | None, yes: bool, force: bool
) -> None:
    """Reclaim realized images no manifest references, plus capture temps and orphan sidecars.

    Build success already garbage-collects its own range (keeping the previous generation for rollback); prune covers the rest: generations stranded by refused manifests or crashes, ranges whose builds are gone, `.capturing` temps, and sidecars whose image vanished. Reports by default; `--yes` deletes. Refuses while registered projects exist unless `--force` (running projects' files are excluded either way).
    """
    from .._build.capture import live_project_files
    from .._runtime.ownership import default_state_dir, list_projects

    if image_cache is None:
        image_cache = default_image_cache()
    state_dir = default_state_dir()
    live = recorded_realized_files(
        build_cache if build_cache is not None else default_build_cache()
    ) | live_project_files(state_dir)
    try:
        running = list_projects(state_dir)
    except OSError:
        running = []
    if running and not force:
        raise click.ClickException(
            f"{len(running)} registered project(s) exist ({', '.join(running[:3])}"
            f"{', ...' if len(running) > 3 else ''}); tear down first, or pass --force"
        )
    victims: list[tuple[Path, int, str]] = []
    for sidecar in sorted(image_cache.glob("*.realized.json")):
        image = image_cache / (sidecar.name.removesuffix(".realized.json") + ".qcow2")
        if image.name in live:
            continue
        if image.is_file():
            victims.append((image, image.stat().st_size, "superseded realized image"))
        victims.append(
            (
                sidecar,
                sidecar.stat().st_size,
                "its sidecar" if image.is_file() else "orphan sidecar (image gone)",
            )
        )
    # pathlib's `*` matches dotfiles, so one glob covers the hidden staging
    # shape; a second `.*.capturing` glob double-listed and double-counted
    for temp in sorted(image_cache.glob("*.capturing")):
        if temp.is_file():
            victims.append((temp, temp.stat().st_size, "stranded capture temp"))
    if not victims:
        click.echo("nothing to prune")
        return
    total = sum(size for _, size, _ in victims)
    for path, size, kind in victims:
        click.echo(f"{path.name}  {size / (1024 * 1024):.0f} MB  {kind}")
    if not yes:
        click.echo(
            f"{total / (1024 * 1024):.0f} MB reclaimable; re-run with --yes to delete"
        )
        return
    seen: set[Path] = set()
    for path, _, _ in victims:
        if path in seen:
            continue
        seen.add(path)
        path.unlink(missing_ok=True)
    click.echo(f"pruned {len(seen)} file(s), {total / (1024 * 1024):.0f} MB reclaimed")

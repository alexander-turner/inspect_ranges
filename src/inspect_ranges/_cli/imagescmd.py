"""`inspect-ranges images`: golden derivation and cache listing."""

from pathlib import Path

import click

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
    for listing in realized:
        click.echo(
            f"  {listing.file}  realized {listing.range_name}/{listing.guest}  key {listing.build_key[:12]}  ({listing.created})"
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

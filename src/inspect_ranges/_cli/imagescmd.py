"""`inspect-ranges images`: golden derivation and cache listing."""

from pathlib import Path

import click

from .._runtime import DeriveError, derive_golden, list_images
from .._runtime.images import RECIPE_VERSION

_DEFAULT_CACHE = Path.home() / ".cache" / "inspect-ranges" / "images"


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
    default=_DEFAULT_CACHE,
    show_default="~/.cache/inspect-ranges/images",
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
    image_cache: Path,
    daemon_bundle: Path | None,
    daemon_sha256: str | None,
) -> None:
    """Derive a daemon-baked golden from a digest-pinned vendor cloud image.

    Offline derivation (Ubuntu noble vendor images in v1): verifies the vendor digest, bakes the pinned control daemon, disables ssh and the resolved stub listener, and records provenance beside the golden. Idempotent: re-running with the same inputs is a cache hit.
    """
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
    default=_DEFAULT_CACHE,
    show_default="~/.cache/inspect-ranges/images",
    help="Image cache to list.",
)
def list_cmd(image_cache: Path) -> None:
    """List the cache: managed goldens with provenance, then unmanaged files."""
    try:
        managed, unmanaged = list_images(image_cache)
    except OSError as error:
        raise click.ClickException(f"cannot read image cache: {error}") from error
    if not managed and not unmanaged:
        click.echo(f"image cache {image_cache} is empty")
        return
    for metadata in managed:
        flags = ""
        if not (image_cache / metadata.file).is_file():
            flags += "  MISSING GOLDEN (interrupted derive; re-run derive)"
        if metadata.recipe_version != RECIPE_VERSION:
            flags += f"  STALE RECIPE (v{metadata.recipe_version} < v{RECIPE_VERSION}; re-derive)"
        click.echo(
            f"{metadata.file}  sha256:{metadata.golden_sha256[:12]}  "
            f"vendor={metadata.vendor_file}  daemon={metadata.daemon.name} v{metadata.daemon.version}  "
            f"recipe=v{metadata.recipe_version}  created={metadata.created}{flags}"
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

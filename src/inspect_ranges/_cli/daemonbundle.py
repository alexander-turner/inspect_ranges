"""`inspect-ranges daemon-bundle`: build the versioned daemon artifact."""

from pathlib import Path

import click

from .._channel.bundle import BundleError, build_daemon_bundle


@click.command(name="daemon-bundle")
@click.option(
    "--output",
    "-o",
    type=click.Path(file_okay=False, path_type=Path),
    default=Path("dist/daemon"),
    show_default=True,
    help="Directory receiving the bundle tar and its daemon.json sidecar.",
)
def daemon_bundle(output: Path) -> None:
    """Build the byte-deterministic daemon bundle the realizer bakes into goldens."""
    try:
        info = build_daemon_bundle(output)
    except BundleError as error:
        raise click.ClickException(str(error)) from error
    click.echo(f"bundle: vsockd-bundle-{info.version}.tar")
    click.echo(f"protocol: {info.protocol}")
    for name, digest in sorted(info.files.items()):
        click.echo(f"  {name}  sha256:{digest[:16]}…")
    click.echo(f"bundle sha256:{info.bundle_sha256}")

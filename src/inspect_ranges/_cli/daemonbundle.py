"""`inspect-ranges daemon-bundle`: build (or fetch) the versioned daemon artifact."""

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
@click.option(
    "--pull",
    is_flag=True,
    help="Fetch the published daemon bundle instead of building (no Go toolchain needed).",
)
@click.option(
    "--from",
    "from_location",
    default=None,
    help="Location override for `--pull`; default is the configured search path (INSPECT_RANGES_REGISTRY).",
)
@click.option(
    "--sha256",
    "expected_sha256",
    default=None,
    help="Out-of-band pin for `--pull`: the bundle digest publish day recorded; a served bundle that differs refuses.",
)
def daemon_bundle(
    output: Path, pull: bool, from_location: str | None, expected_sha256: str | None
) -> None:
    """Build the byte-deterministic daemon bundle the realizer bakes into goldens, or fetch the published one with `--pull`."""
    if (from_location is not None or expected_sha256 is not None) and not pull:
        raise click.UsageError("--from/--sha256 only apply to --pull")
    if pull:
        from .._dist.catalog import fetch_daemon_bundle
        from .._dist.errors import DistError
        from .._dist.location import registry_locations

        try:
            info = fetch_daemon_bundle(
                registry_locations(from_location),
                output,
                expected_sha256=expected_sha256,
            )
        except DistError as error:
            raise click.ClickException(str(error)) from error
    else:
        try:
            info = build_daemon_bundle(output)
        except BundleError as error:
            raise click.ClickException(str(error)) from error
    click.echo(f"bundle: vsockd-bundle-{info.version}.tar")
    click.echo(f"protocol: {info.protocol}")
    for name, digest in sorted(info.files.items()):
        click.echo(f"  {name}  sha256:{digest[:16]}…")
    click.echo(f"bundle sha256:{info.bundle_sha256}")

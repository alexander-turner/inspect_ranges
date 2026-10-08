"""`inspect-ranges up` / `down`: realize a rendered bundle; tear a project down."""

import tempfile
from pathlib import Path

import click

from .._compiler import PlanOptions, render_bundle
from .._runtime.down import DownError, down_all
from .._runtime.down import down as run_down
from .._runtime.up import UpError, UpOptions
from .._runtime.up import up as run_up
from ..schema import load_range
from ..types import IssueError

_DEFAULT_CACHE = Path.home() / ".cache" / "inspect-ranges" / "images"


@click.command()
@click.argument("bundle", required=False, type=click.Path(path_type=Path))
@click.option(
    "--from-spec",
    type=click.Path(exists=True, path_type=Path),
    default=None,
    help="Render SPEC into a temporary bundle first, then apply it (composition sugar; the applier still consumes only the verified bundle).",
)
@click.option(
    "--project",
    default=None,
    help="Compose project name (default: ir-<range>-<spec digest>).",
)
@click.option(
    "--image-cache",
    type=click.Path(path_type=Path),
    default=_DEFAULT_CACHE,
    show_default="~/.cache/inspect-ranges/images",
)
@click.option(
    "--cid-base",
    type=int,
    default=3,
    show_default=True,
    help="First vsock CID when rendering --from-spec (plan-time input).",
)
@click.option("--readiness-timeout", type=float, default=300.0, show_default=True)
@click.option(
    "--keep",
    is_flag=True,
    help="Keep a failed range running for inspection instead of tearing it down.",
)
@click.option(
    "--uplink-network",
    default=None,
    help="Deployment-supplied uplink network, for ranges that request egress.",
)
def up(
    bundle: Path | None,
    from_spec: Path | None,
    project: str | None,
    image_cache: Path,
    cid_base: int,
    readiness_timeout: float,
    keep: bool,
    uplink_network: str | None,
) -> None:
    """Realize a rendered BUNDLE into a running, ready range.

    Verifies every manifest digest before acting (tampered or incomplete bundles refuse), brings up the hardened range container on the bundle's own compose project, boots every guest per `boot.json`, and waits on every readiness probe. The hardened range image is required; there is no bypass.
    """
    if (bundle is None) == (from_spec is None):
        raise click.UsageError("pass a BUNDLE directory or --from-spec, not both")
    options = UpOptions(
        project=project,
        image_cache=image_cache,
        readiness_timeout=readiness_timeout,
        keep_on_failure=keep,
        uplink_network=uplink_network,
    )
    try:
        if from_spec is not None:
            with tempfile.TemporaryDirectory(prefix="ir-bundle-") as temp:
                spec = load_range(from_spec)
                render_bundle(
                    spec,
                    Path(temp) / "bundle",
                    PlanOptions(image_cache=image_cache, cid_base=cid_base),
                )
                result = run_up(Path(temp) / "bundle", options)
        else:
            assert bundle is not None
            result = run_up(bundle, options)
    except UpError as error:
        raise click.ClickException(str(error)) from error
    except IssueError as error:
        raise click.ClickException(str(error)) from error
    click.echo(
        f"ready: project {result.project} ({result.range_name}) in {result.seconds}s"
    )
    for guest in result.guests:
        click.echo(f"  {guest.name}  cid={guest.cid}  ready={str(guest.ready).lower()}")
    click.echo(f"tear down with: inspect-ranges down {result.project}")


@click.command()
@click.argument("project", required=False)
@click.option(
    "--all",
    "sweep_all",
    is_flag=True,
    help="Tear down every ir- project on this host (never touches other prefixes).",
)
def down(project: str | None, sweep_all: bool) -> None:
    """Tear down PROJECT (idempotent, works from any process, after any crash)."""
    if (project is None) == (not sweep_all):
        raise click.UsageError("pass a PROJECT name or --all")
    try:
        _run_down_command(project, sweep_all)
    except DownError as error:
        raise click.ClickException(str(error)) from error


def _run_down_command(project: str | None, sweep_all: bool) -> None:
    if sweep_all:
        results = down_all()
        if not results:
            click.echo("no ir- projects found")
        for result in results:
            click.echo(
                f"down: {result.project}  containers={result.containers} volumes={result.volumes} networks={result.networks}"
            )
        return
    assert project is not None
    result = run_down(project)
    click.echo(
        f"down: {result.project}  containers={result.containers} volumes={result.volumes} networks={result.networks}"
    )

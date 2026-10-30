"""`inspect-ranges up` / `down`: realize a rendered bundle; tear a project down."""

import tempfile
from pathlib import Path

import click

from .._attackbox.backend import attack_box_is_default, attack_box_origin
from .._build.manifest import (
    apply_build_manifest,
    default_build_cache,
    realized_backings,
)
from .._compiler import PlanOptions, render_bundle
from .._runtime.down import DownError, down_all
from .._runtime.down import down as run_down
from .._runtime.images import default_image_cache
from .._runtime.ownership import default_state_dir
from .._runtime.up import UpError, UpOptions
from .._runtime.up import up as run_up
from ..schema import load_range
from ..types import IssueError
from .specpath import resolve_spec_path


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
    help="Compose project name (default: `ir-<range>-<spec digest>`).",
)
@click.option(
    "--image-cache",
    type=click.Path(path_type=Path),
    default=None,
    show_default="~/.cache/inspect-ranges/images (or INSPECT_RANGES_IMAGE_CACHE)",
    help="Image cache the bundle's image digests re-verify against.",
)
@click.option(
    "--cid-base",
    type=click.IntRange(min=3),
    default=3,
    show_default=True,
    help="First vsock CID when rendering `--from-spec` (plan-time input).",
)
@click.option(
    "--readiness-timeout",
    type=float,
    default=300.0,
    show_default=True,
    help="Per-guest readiness deadline in seconds (daemon answer, then cloud-init).",
)
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
    image_cache: Path | None,
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
    if image_cache is None:
        image_cache = default_image_cache()
    try:
        attack_box = attack_box_origin()
    except ValueError as error:
        raise click.ClickException(str(error)) from error
    options = UpOptions(
        project=project,
        image_cache=image_cache,
        readiness_timeout=readiness_timeout,
        keep_on_failure=keep,
        uplink_network=uplink_network,
        attack_box=attack_box,
        attack_box_is_default=attack_box_is_default(),
    )
    try:
        if from_spec is not None:
            # staged under the state root, not /tmp: a SIGKILL mid-up leaves
            # the staging dir where `down --all` sweeps it, not as a leak
            staging_root = default_state_dir().parent / "staging"
            staging_root.mkdir(parents=True, exist_ok=True)
            with tempfile.TemporaryDirectory(
                prefix="ir-bundle-", dir=staging_root
            ) as temp:
                spec = load_range(resolve_spec_path(from_spec))
                spec, realized_sections, consumed = apply_build_manifest(
                    spec,
                    image_cache=image_cache,
                    build_cache=default_build_cache(),
                )
                render_bundle(
                    spec,
                    Path(temp) / "bundle",
                    PlanOptions(
                        image_cache=image_cache,
                        cid_base=cid_base,
                        realized_sections=realized_sections,
                        realized_backings=(
                            realized_backings(consumed) if consumed else {}
                        ),
                    ),
                )
                result = run_up(Path(temp) / "bundle", options)
        else:
            assert bundle is not None
            result = run_up(bundle, options)
    except UpError as error:
        raise click.ClickException(str(error)) from error
    except IssueError as error:
        # the refusal's remedy travels with it (round-2: plan/render print the
        # hint through the planning report; this arm dropped it)
        detail = "; ".join(
            f"{issue.message}" + (f" ({issue.hint})" if issue.hint else "")
            for issue in error.issues
        )
        raise click.ClickException(detail) from error
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

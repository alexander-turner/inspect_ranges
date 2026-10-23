"""The `build` verb: the full author loop (recipes, verification, capture, manifest, behavioral checks)."""

from pathlib import Path
from typing import Any

import click

from .._build.errors import BuildError
from .._build.orchestrate import (
    DEFAULT_UPLINK_NETWORK,
    BuildOptions,
    build_range,
)
from .._build.recipes import DEFAULT_RECIPE_BUDGET_S
from .._diagnostics import IssueError
from .._runtime.up import UpError
from .plancmd import load_or_exit, planning_report
from .specpath import resolve_spec_path


def _echo_stage(stage: str, status: str, fields: dict[str, Any]) -> None:
    if status == "start":
        return
    if stage == "verify":
        # per-declaration lines in the Journey A shape
        if status == "fail":
            click.echo(
                f"verify    [{fields.get('code', '')}] guest '{fields.get('guest', '')}': "
                f"declared {fields.get('declared', '')}; observed {fields.get('observed', '')}"
            )
            click.echo(f"          log: {fields.get('log', '')}")
        else:
            click.echo(
                f"verify    ok  {fields.get('kind', '')} {fields.get('guest', '')}/{fields.get('name', '')}"
            )
        return
    if status == "fail":
        click.echo(f"{stage:<9} FAILED  {fields.get('error', '')}")
        return
    if status == "warn":
        click.echo(f"{stage:<9} WARNING {fields.get('warning', '')}")
        return
    detail = "  ".join(f"{key}={value}" for key, value in sorted(fields.items()))
    click.echo(f"{stage:<9} {detail}")


@click.command()
@click.argument("path", required=False, type=click.Path(exists=True, path_type=Path))
@click.option(
    "--image-cache",
    type=click.Path(path_type=Path),
    default=None,
    show_default="~/.cache/inspect-ranges/images (or INSPECT_RANGES_IMAGE_CACHE)",
    help="Image cache used for golden resolution.",
)
@click.option(
    "--recipe-cache",
    type=click.Path(path_type=Path),
    default=None,
    show_default="~/.cache/inspect-ranges/recipes (or INSPECT_RANGES_RECIPE_CACHE)",
    help="Recipe cache for the resolution fallback after ./recipes/.",
)
@click.option(
    "--cid-base",
    type=click.IntRange(min=3),
    default=3,
    show_default=True,
    help="First vsock CID (plan-time input; realizer batteries use 3000+).",
)
@click.option(
    "--keep",
    is_flag=True,
    help="Keep the built range running for inspection (success or failure); tear down with `inspect-ranges down`.",
)
@click.option(
    "--uplink-network",
    default=DEFAULT_UPLINK_NETWORK,
    show_default=True,
    help="Docker network build-time egress masquerades onto (created when absent).",
)
@click.option(
    "--build-nameserver",
    default=None,
    show_default="derived from the host's resolv.conf",
    help="Resolver handed to build guests (fleets forcing DNS through a VPC resolver are the norm, not the exception).",
)
@click.option(
    "--build-cache",
    type=click.Path(path_type=Path),
    default=None,
    show_default="~/.cache/inspect-ranges/builds (or INSPECT_RANGES_BUILD_CACHE)",
    help="Builds cache where the range's manifest lives.",
)
@click.option(
    "--reverify",
    is_flag=True,
    help="Boot and verify in full even when every build key matches the recorded manifest.",
)
@click.option(
    "--readiness-timeout",
    type=float,
    default=300.0,
    show_default=True,
    help="Per-guest readiness deadline in seconds (daemon answer, then cloud-init).",
)
@click.option(
    "--settle-probe",
    default=None,
    show_default="archive.ubuntu.com",
    help="Hostname each guest must resolve before its first recipe runs; pass 'off' to skip the gate (fleets whose resolver answers only internal names).",
)
@click.option(
    "--settle-timeout",
    "settle_timeout_s",
    type=float,
    default=None,
    show_default="90",
    help="Seconds to wait for the settle probe per guest.",
)
@click.option(
    "--recipe-budget",
    "recipe_budget_s",
    type=float,
    default=DEFAULT_RECIPE_BUDGET_S,
    show_default=True,
    help="Whole-entrypoint budget per provisioning step, in seconds.",
)
@click.pass_context
def build(
    ctx: click.Context,
    path: Path | None,
    image_cache: Path | None,
    recipe_cache: Path | None,
    cid_base: int,
    keep: bool,
    uplink_network: str,
    build_nameserver: str | None,
    build_cache: Path | None,
    reverify: bool,
    readiness_timeout: float,
    settle_probe: str | None,
    settle_timeout_s: float | None,
    recipe_budget_s: float,
) -> None:
    """Build PATH (default `.`): realize, verify, capture, and prove the range's declared guest content.

    The build boots an egress-enabled variant of the range (runtime isolation is untouched), runs each host's `provisioning` steps in declaration order, verifies every declared service and vulnerability against the live guests, captures each provisioned guest as a realized image, runs any declared behavioral checks against the captured artifacts, and records the build manifest that `plan`/`render`/`up`/the provider consume. Rebuilds are incremental per guest; an unchanged range is a cached no-op. `--keep` preserves the running range for diagnosis (and captures nothing). Full reference: the Building Ranges docs page.
    """
    spec_path = resolve_spec_path(path)
    spec = load_or_exit(ctx, spec_path)
    options = BuildOptions(
        image_cache=image_cache,
        recipe_cache=recipe_cache,
        cid_base=cid_base,
        keep=keep,
        uplink_network=uplink_network,
        build_nameserver=build_nameserver,
        build_cache=build_cache,
        reverify=reverify,
        readiness_timeout=readiness_timeout,
        recipe_budget_s=recipe_budget_s,
    )
    if settle_probe is not None:
        options = options.model_copy(
            update={"settle_probe": None if settle_probe == "off" else settle_probe}
        )
    if settle_timeout_s is not None:
        options = options.model_copy(update={"settle_timeout_s": settle_timeout_s})
    try:
        result = build_range(spec, spec_path.parent, options, on_stage=_echo_stage)
    except IssueError as error:
        click.echo(planning_report(spec_path, error).render())
        ctx.exit(1)
    except UpError as error:
        _echo_stage(error.stage, "fail", {"error": str(error)})
        click.echo(f"build FAILED: {error}")
        ctx.exit(1)
    except BuildError as error:
        click.echo(f"build FAILED: {error}")
        ctx.exit(1)
    if result.cached:
        click.echo(
            f"build OK (cached, verified {result.verified_at}; pass --reverify to re-run)"
        )
        ctx.exit(0)
    if result.manifest_path is not None:
        click.echo(f"manifest  {result.manifest_path}")
    click.echo(
        f"build OK ({result.seconds:.1f} s, {len(result.recipes)} recipes) project {result.project}"
    )
    if result.kept:
        click.echo(
            f"range kept running; tear down with: inspect-ranges down {result.project}"
            " (it holds this --cid-base's vsock CIDs: tear down before rebuilding,"
            " or rebuild with a different --cid-base)"
        )
    ctx.exit(0)

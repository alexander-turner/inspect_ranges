import hashlib
import json as json_module
from pathlib import Path

import click

from .._build.manifest import (
    apply_build_manifest,
    default_build_cache,
    realized_backings,
    stamp_bundle_sha256,
)
from .._compiler import PlanOptions, plan_json, render_bundle, resolve_plan
from .._diagnostics import IssueError, ValidationReport, locate, parse_marked
from .._runtime.images import default_image_cache
from ..schema import validate_range
from ..types import Issue, RangeSpec
from .specpath import resolve_spec_path


def load_or_exit(ctx: click.Context, path: Path) -> RangeSpec:
    report = validate_range(path)
    if not report.valid or report.spec is None:
        click.echo(report.render())
        ctx.exit(1)
    assert report.spec is not None
    return report.spec


def planning_report(path: Path, error: IssueError) -> ValidationReport:
    """Position planning issues against the source, through the same report machinery as validation."""
    try:
        _, node = parse_marked(path.read_text())
    except Exception:
        node = None
    issues: list[Issue] = []
    for issue in error.issues:
        position = locate(node, issue.path)
        issues.append(
            issue.model_copy(
                update={
                    "line": position[0] if position else None,
                    "col": position[1] if position else None,
                }
            )
        )
    return ValidationReport(file=str(path), issues=issues)


@click.command()
@click.argument("path", required=False, type=click.Path(exists=True, path_type=Path))
@click.option("--json", "as_json", is_flag=True, help="Emit the plan as JSON.")
@click.option(
    "--image-cache",
    type=click.Path(path_type=Path),
    default=None,
    show_default="~/.cache/inspect-ranges/images (or INSPECT_RANGES_IMAGE_CACHE)",
    help="Image cache used for digest resolution.",
)
@click.option("--cpu-model", default="host-passthrough", show_default=True)
@click.option(
    "--cid-base",
    type=click.IntRange(min=3),
    default=3,
    show_default=True,
    help="First vsock CID (plan-time input; realizer batteries use 3000+).",
)
@click.pass_context
def plan(
    ctx: click.Context,
    path: Path | None,
    as_json: bool,
    image_cache: Path | None,
    cpu_model: str,
    cid_base: int,
) -> None:
    """Resolve PATH (default `.`, a range directory or spec file) into its immutable plan.

    Unsupported constructs fail here, at planning, with the same diagnostics as `validate`.
    """
    path = resolve_spec_path(path)
    spec = load_or_exit(ctx, path)
    if image_cache is None:
        image_cache = default_image_cache()
    try:
        spec, realized_sections, _ = apply_build_manifest(
            spec, image_cache=image_cache, build_cache=default_build_cache()
        )
        options = PlanOptions(
            image_cache=image_cache,
            cpu_model=cpu_model,
            cid_base=cid_base,
            realized_sections=realized_sections,
        )
        resolved = resolve_plan(spec, options)
    except IssueError as error:
        click.echo(planning_report(path, error).render())
        ctx.exit(1)
    if as_json:
        click.echo(plan_json(resolved), nl=False)
        ctx.exit(0)
    click.echo(f"{resolved.range.name}  (spec {resolved.range.spec_sha256[:12]})")
    click.echo("networks:")
    for network in resolved.networks:
        gateway = f" gw {network.gateway}" if network.gateway else ""
        click.echo(
            f"  {network.name:<16} {network.cidr}  {network.mode}{gateway}  [{network.bridge}]"
        )
    click.echo("guests:")
    for guest in resolved.guests:
        addresses = ", ".join(str(i.ip) for i in guest.interfaces)
        digest = guest.image.digest[7:19] if guest.image.digest else "not-in-cache"
        click.echo(
            f"  {guest.name:<16} {guest.kind:<8} cid {guest.cid:<3} {addresses:<32} {guest.image.reference} ({digest})"
        )
    requirements = resolved.requirements
    click.echo(
        f"requires: cpu={requirements.cpu_model} egress_uplink={str(requirements.egress_uplink).lower()}"
    )
    click.echo(
        f"totals: {resolved.totals.guests} guests, {resolved.totals.cpus} vcpus, {resolved.totals.memory_mb} MiB"
    )
    ctx.exit(0)


@click.command()
@click.argument("path", required=False, type=click.Path(exists=True, path_type=Path))
@click.option(
    "--output",
    "-o",
    "out",
    required=True,
    type=click.Path(path_type=Path),
    help="Bundle directory to write (must be empty or absent).",
)
@click.option(
    "--image-cache",
    type=click.Path(path_type=Path),
    default=None,
    show_default="~/.cache/inspect-ranges/images (or INSPECT_RANGES_IMAGE_CACHE)",
    help="Image cache used for digest resolution.",
)
@click.option("--cpu-model", default="host-passthrough", show_default=True)
@click.option(
    "--cid-base",
    type=click.IntRange(min=3),
    default=3,
    show_default=True,
    help="First vsock CID (plan-time input; realizer batteries use 3000+).",
)
@click.option(
    "--evidence-capture",
    is_flag=True,
    default=False,
    help="Render the evidence-capture sidecar (per-segment pcap; evidence-v1).",
)
@click.pass_context
def render(
    ctx: click.Context,
    path: Path | None,
    out: Path,
    image_cache: Path | None,
    cpu_model: str,
    cid_base: int,
    evidence_capture: bool,
) -> None:
    """Render PATH (default `.`, a range directory or spec file) into its realization bundle."""
    path = resolve_spec_path(path)
    spec = load_or_exit(ctx, path)
    if image_cache is None:
        image_cache = default_image_cache()
    try:
        spec, realized_sections, consumed = apply_build_manifest(
            spec, image_cache=image_cache, build_cache=default_build_cache()
        )
        options = PlanOptions(
            image_cache=image_cache,
            cpu_model=cpu_model,
            cid_base=cid_base,
            evidence_capture=evidence_capture,
            realized_sections=realized_sections,
            realized_backings=realized_backings(consumed) if consumed else {},
        )
        render_bundle(spec, out, options)
    except IssueError as error:
        click.echo(planning_report(path, error).render())
        ctx.exit(1)
    manifest_bytes = (out / "manifest.json").read_bytes()
    manifest = json_module.loads(manifest_bytes)
    digest = hashlib.sha256(manifest_bytes).hexdigest()
    if consumed is not None:
        # wraps-by-reference: the build manifest records the runtime bundle
        # rendered from it (the spine's two-manifest decision); the stamp is a
        # locked read-modify-write that lands only while the on-disk manifest
        # is still the revision this render consumed, so a concurrent rebuild
        # is never clobbered (round-1 review)
        stamp_bundle_sha256(
            default_build_cache(), consumed.range_name, consumed.spec_sha256, digest
        )
    click.echo(
        f"{click.style('✓', fg='green')} {out}  bundle sha256:{digest[:16]}  ({len(manifest['files']) + 1} files)"
    )
    ctx.exit(0)

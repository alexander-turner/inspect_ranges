import json as json_module
from pathlib import Path

import click

from .._diagnostics import ValidationReport
from ..schema import validate_range
from .specpath import resolve_spec_path


def _challenges_report(
    path: Path, range_path: Path, range_report: ValidationReport
) -> ValidationReport:
    """Validate a sibling `challenges.yaml`, cross-referenced against the validated range.

    Goal-type registrations load first (the same `inspect_ai` entry points inspect loads at startup), so a custom-typed file validates here exactly as it parses at build and eval time; a custom type whose registration did not load refuses `unknown-goal-type` with the known-name listing. An invalid range reads as the designed `range-invalid` finding (cross-reference checks skipped), never a crash.
    """
    from .._challenges.registration import ensure_goal_type_registrations
    from .._challenges.schema import validate_challenges

    ensure_goal_type_registrations()
    spec = (
        range_report.spec
        if range_report.valid and range_report.spec is not None
        else range_path
    )
    return validate_challenges(path, spec)


@click.command()
@click.argument(
    "paths", nargs=-1, required=False, type=click.Path(exists=True, path_type=Path)
)
@click.option(
    "--json",
    "as_json",
    is_flag=True,
    help="Emit one JSON report per file instead of text.",
)
@click.pass_context
def validate(ctx: click.Context, paths: tuple[Path, ...], as_json: bool) -> None:
    """Validate `range.yaml` files against schema v0.1 (default: the current directory's).

    Reports every detectable issue in each file at once, with source positions and hints. Each PATH may be a spec file or a range directory. A `challenges.yaml` beside the spec is validated too, cross-referenced against the range; custom goal types load through the `inspect_ai` entry points, and an unregistered type refuses with the known-name listing. Exits with status 1 if any file is invalid.
    """
    resolved = (
        [resolve_spec_path(path) for path in paths]
        if paths
        else [resolve_spec_path(None)]
    )
    reports: list[ValidationReport] = []
    for path in resolved:
        report = validate_range(path)
        reports.append(report)
        challenges_path = path.parent / "challenges.yaml"
        if challenges_path.is_file():
            reports.append(_challenges_report(challenges_path, path, report))
    if as_json:
        click.echo(
            json_module.dumps([report.to_json() for report in reports], indent=2)
        )
    else:
        for report in reports:
            if report.valid and not report.issues:
                meta = getattr(report.spec, "meta", None)
                name = f"  ({meta.name})" if meta is not None else ""
                click.echo(f"{click.style('✓', fg='green')} {report.file}{name}")
            else:
                marker = "✓" if report.valid else "✗"
                color = "green" if report.valid else "red"
                styled = report.render().replace(
                    marker, click.style(marker, fg=color), 1
                )
                click.echo(styled)
    ctx.exit(0 if all(report.valid for report in reports) else 1)

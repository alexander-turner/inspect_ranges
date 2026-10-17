import json as json_module
from pathlib import Path

import click

from ..schema import validate_range
from .specpath import resolve_spec_path


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

    Reports every detectable issue in each file at once, with source positions and hints. Each PATH may be a spec file or a range directory. Exits with status 1 if any file is invalid.
    """
    resolved = (
        [resolve_spec_path(path) for path in paths]
        if paths
        else [resolve_spec_path(None)]
    )
    reports = [validate_range(path) for path in resolved]
    if as_json:
        click.echo(
            json_module.dumps([report.to_json() for report in reports], indent=2)
        )
    else:
        for report in reports:
            if report.valid and not report.issues:
                name = f"  ({report.spec.meta.name})" if report.spec is not None else ""
                click.echo(f"{click.style('✓', fg='green')} {report.file}{name}")
            else:
                marker = "✓" if report.valid else "✗"
                color = "green" if report.valid else "red"
                styled = report.render().replace(
                    marker, click.style(marker, fg=color), 1
                )
                click.echo(styled)
    ctx.exit(0 if all(report.valid for report in reports) else 1)

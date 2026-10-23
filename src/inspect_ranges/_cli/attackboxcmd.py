"""`inspect-ranges attackbox`: operations on the external attack-box seam (attack-box-v1)."""

import json as json_module
from pathlib import Path

import click

from .._attackbox.conformance import BatteryError, run_attack_box_battery
from .._runtime.images import default_image_cache
from .specpath import resolve_spec_path


@click.group()
def attackbox() -> None:
    """External attack-box provider operations (INSPECT_RANGES_ATTACK_BOX)."""


@attackbox.command()
@click.option(
    "--spec",
    "spec",
    required=True,
    type=click.Path(path_type=Path, exists=True),
    metavar="RANGE_YAML",
    help="A range with a dedicated attack box and a shared-segment Linux defender (the canonical battery spec).",
)
@click.option(
    "--keep",
    is_flag=True,
    help="Leave the range (and the provider's box) running for inspection; teardown obligations are skipped.",
)
@click.option("--json", "as_json", is_flag=True, help="Emit the report as JSON.")
@click.option(
    "--image-cache",
    type=click.Path(path_type=Path, file_okay=False),
    default=None,
    show_default="~/.cache/inspect-ranges/images (or INSPECT_RANGES_IMAGE_CACHE)",
)
@click.option(
    "--readiness-timeout",
    type=float,
    default=300.0,
    show_default=True,
    help="Seconds the realize obligation allows for boot and readiness.",
)
def verify(
    spec: Path,
    keep: bool,
    as_json: bool,
    image_cache: Path | None,
    readiness_timeout: float,
) -> None:
    """Run the attack-box conformance battery against the registered provider.

    A provider boots when it passes: the foothold wall holds against the foreign box, the attacker-surface sweep is clean, the exec surface passes the full sandbox self_check suite with no pins, readiness and teardown behave, and evidence drops are declared.
    """
    try:
        report = run_attack_box_battery(
            resolve_spec_path(spec),
            image_cache=image_cache
            if image_cache is not None
            else default_image_cache(),
            keep=keep,
            readiness_timeout=readiness_timeout,
        )
    except BatteryError as error:
        raise click.ClickException(str(error)) from error
    if as_json:
        click.echo(json_module.dumps(report.to_json(), indent=2))
    else:
        for row in report.rows:
            status = " ok " if row.ok else "FAIL"
            click.echo(f"[{status}] {row.name}: {row.detail}")
        verdict = "PASS" if report.passed else "FAIL"
        click.echo(f"a provider boots when it passes: {verdict}")
    if not report.passed:
        raise SystemExit(1)

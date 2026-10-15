"""`inspect-ranges evidence`: offline verification of an evidence location."""

import asyncio
from pathlib import Path

import click

from .._evidence.reader import (
    LocalDirStore,
    VerifyReport,
    WriterReport,
    verify_location,
)


def _echo_writer(report: WriterReport) -> None:
    seal = (
        f"sealed ({report.seal_status}), digest {report.seal_digest}"
        if report.sealed
        else "UNSEALED (tail truncation of an unsealed record is undetectable)"
    )
    click.echo(f"writer {report.writer}: {report.parts} part(s), {seal}")
    for name in sorted(report.streams):
        coverage = report.streams[name]
        span = (
            f"wall {coverage.wall_start:.3f}..{coverage.wall_end:.3f}"
            if coverage.wall_start is not None and coverage.wall_end is not None
            else "no records"
        )
        click.echo(
            f"  {name}: {coverage.chunks} chunk(s), {coverage.gaps} gap(s), "
            f"{coverage.size} byte(s), {span}"
        )
    for gap in report.gaps:
        click.echo(
            f"  GAP {gap.stream}#{gap.seq}: {gap.cause}, {gap.dropped} byte(s) dropped, "
            f"wall {gap.wall_start:.3f}..{gap.wall_end:.3f}"
        )
    if report.first_break is not None:
        broke = report.first_break
        click.echo(f"  BREAK [{broke.kind}] at {broke.key}: {broke.detail}")
        if broke.neighborhood is not None:
            click.echo(f"    last good record: {broke.neighborhood}")


def _echo(report: VerifyReport) -> None:
    for writer in sorted(report.writers):
        _echo_writer(report.writers[writer])
    for key in report.unreferenced:
        click.echo(f"unreferenced object (residue, not covered by any chain): {key}")
    if not report.writers:
        click.echo("no manifests found at this location")
    click.echo("verify: OK" if report.ok else "verify: FAILED")


@click.group()
def evidence() -> None:
    """Work with evidence locations (see design/inspect-ranges/evidence-v1.md)."""


@evidence.command()
@click.argument("location")
@click.option(
    "--shallow",
    is_flag=True,
    help="Replay manifests, chains, and seals only (skip fetching chunk bytes).",
)
@click.option("--json", "as_json", is_flag=True, help="Emit the full report as JSON.")
def verify(location: str, shallow: bool, as_json: bool) -> None:
    """Replay the hash chains at LOCATION and name the first break.

    Exits 0 when every writer replays cleanly, 1 on any break or when no manifests exist. An unsealed writer is reported loudly but is not itself a break (the lifecycle seals on finalize and on reap; unsealed-at-rest means neither happened).
    """
    if "://" in location:
        raise click.ClickException(
            "only local directories are supported in this build (the S3 store arrives with evidence-v1 slice 3)"
        )
    store = LocalDirStore(Path(location))
    report = asyncio.run(verify_location(store, location=location, deep=not shallow))
    if as_json:
        click.echo(report.model_dump_json(indent=2))
    else:
        _echo(report)
    if not report.ok:
        raise SystemExit(1)

"""`inspect-ranges evidence`: offline verification of an evidence location."""

import asyncio

import click

from .._evidence.reader import (
    VerifyReport,
    WriterReport,
    verify_location,
)
from .._evidence.s3 import store_for_location


def _echo_writer(report: WriterReport) -> None:
    seal = (
        f"sealed ({report.seal_status}), digest {report.seal_digest}"
        if report.sealed
        else "UNSEALED (an unsealed record is extendable as well as truncatable)"
    )
    binding = (
        "binding CHECKED against an external seal digest"
        if report.binding_checked
        else "internal consistency only (no --expect-seal binding supplied)"
    )
    click.echo(f"writer {report.writer}: {report.parts} part(s), {seal}")
    click.echo(f"  {binding}")
    if report.lease_id is not None or report.sample_id is not None:
        click.echo(
            f"  seal claims lease={report.lease_id or '-'} sample={report.sample_id or '-'}"
        )
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
@click.option(
    "--expect-seal",
    "expect_seal",
    multiple=True,
    metavar="WRITER=DIGEST",
    help="Externally-held seal digest to bind against (repeatable, one per writer). Without it, verification attests internal consistency only: the chain anchors everything at or below the seal, but a forged or absent seal, or a record transplanted from another location, is not detectable from the location alone.",
)
def verify(
    location: str, shallow: bool, as_json: bool, expect_seal: tuple[str, ...]
) -> None:
    """Replay the hash chains at LOCATION and name the first break.

    LOCATION is a local directory or an `s3://bucket/prefix` evidence location (S3 credentials follow standard AWS resolution). Exits 0 when every writer replays cleanly, 1 on any break or when no manifests exist. An unsealed writer is reported loudly but is not itself a break unless a binding was supplied for it (the lifecycle seals on finalize and on reap; unsealed-at-rest means neither happened). With `--expect-seal` the writer's result carries the full detection claim; without it, internal consistency only.
    """
    expected: dict[str, str] = {}
    for item in expect_seal:
        writer_name, separator, digest = item.partition("=")
        if not separator or not writer_name or not digest:
            raise click.ClickException(
                f"--expect-seal takes WRITER=DIGEST, got {item!r}"
            )
        expected[writer_name] = digest
    try:
        store = store_for_location(location)
    except ValueError as error:
        raise click.ClickException(str(error)) from error
    report = asyncio.run(
        verify_location(
            store, location=location, deep=not shallow, expected_seals=expected or None
        )
    )
    if as_json:
        click.echo(report.model_dump_json(indent=2))
    else:
        _echo(report)
    if not report.ok:
        raise SystemExit(1)

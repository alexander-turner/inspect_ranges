"""`inspect-ranges reaper`: reclaim expired host leases from on-disk state."""

import time
from pathlib import Path

import click

from .._host.reaper import ReapOutcome, sweep
from .._runtime.ownership import default_state_dir


def _report(outcomes: list[ReapOutcome]) -> None:
    for outcome in outcomes:
        line = f"{outcome.action}: {outcome.project} (lease {outcome.lease_id})"
        if outcome.error is not None:
            line += f": {outcome.error}"
        click.echo(line)


@click.command()
@click.option(
    "--state-dir",
    type=click.Path(path_type=Path),
    default=None,
    help="Project state directory (default: the shared inspect-ranges state dir).",
)
@click.option(
    "--interval",
    type=click.FloatRange(min_open=True, min=0),
    default=None,
    help="Seconds between sweeps; omitted means one sweep and exit.",
)
def reaper(state_dir: Path | None, interval: float | None) -> None:
    """Reclaim expired host leases: teardown first, then CID and lease release.

    Reclaims on expiry alone, never probing liveness: a healthy sample never expires because its driver renews independently. A failed teardown frees nothing and the lease stays findable for the next sweep. One-shot mode exits 1 if any teardown failed.
    """
    target = state_dir if state_dir is not None else default_state_dir()
    while True:
        try:
            outcomes = sweep(target)
        except Exception as error:
            # the long-lived daemon must survive one bad pass; one-shot
            # surfaces the failure to its caller
            if interval is None:
                raise
            click.echo(f"sweep failed (retrying in {interval}s): {error}", err=True)
            outcomes = []
        _report(outcomes)
        if interval is None:
            if any(outcome.action != "reaped" for outcome in outcomes):
                raise SystemExit(1)
            return
        time.sleep(interval)

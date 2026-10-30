"""`inspect-ranges shell`: an interactive operator tmux session on a guest of a range booted with `up`."""

import asyncio
from pathlib import Path

import click

from .._challenges.attach import attach_oracle, recorded_boot
from .._challenges.oracle import OracleSetupError
from .._runtime.ownership import default_state_dir, read_owner
from .._terminal.operator import (
    OperatorShellError,
    require_operator_origin,
    resolve_guest,
    run_shell,
)


@click.command()
@click.argument("project")
@click.argument("guest", required=False, default=None)
@click.option(
    "--session",
    default="operator",
    show_default=True,
    help="tmux session name on the guest; the same name reattaches.",
)
@click.option(
    "--user",
    "user",
    default=None,
    show_default="the daemon identity (root on Linux)",
    help="Guest user the session runs as.",
)
@click.option(
    "--cast",
    "cast_path",
    type=click.Path(path_type=Path, dir_okay=False, writable=True),
    default=None,
    help="Record the attach as an asciicast v2 file (filtered output, local only).",
)
def shell(
    project: str,
    guest: str | None,
    session: str,
    user: str | None,
    cast_path: Path | None,
) -> None:
    """Open an interactive shell on GUEST of the running range PROJECT.

    Attaches a tmux session in the guest over the range's control channel: no SSH, no guest listener, works on fully isolated networks. Only ranges booted with `inspect-ranges up` attach; a project booted by the Inspect sandbox provider (an eval sample) refuses, so scored runs are structurally out of reach. GUEST defaults to the range's attacker when it has exactly one. Detach with Ctrl-]; the session keeps running for reattach.
    """
    state = default_state_dir()
    try:
        require_operator_origin(project, read_owner(state, project))
        resolved = resolve_guest(recorded_boot(state, project), guest)
        with attach_oracle(project) as oracle:
            asyncio.run(
                run_shell(
                    oracle,
                    resolved,
                    session=session,
                    user=user,
                    cast_path=cast_path,
                )
            )
    except (OperatorShellError, OracleSetupError) as error:
        raise click.ClickException(str(error)) from error

"""`inspect-ranges applier`: serve the host plane and guest relay on a unix socket."""

import asyncio
from pathlib import Path

import click

from .._host.applier import Applier
from .._provider.state import default_image_cache
from .._runtime.ownership import default_state_dir


@click.command()
@click.option(
    "--socket",
    "socket_path",
    required=True,
    type=click.Path(path_type=Path),
    help="Unix socket to serve on (created 0600 in a 0700 directory).",
)
@click.option(
    "--state-dir",
    type=click.Path(path_type=Path),
    default=None,
    help="Project state directory (default: the shared inspect-ranges state dir).",
)
@click.option(
    "--image-cache",
    type=click.Path(path_type=Path),
    default=None,
    show_default="~/.cache/inspect-ranges/images (or INSPECT_RANGES_IMAGE_CACHE)",
)
def applier(
    socket_path: Path, state_dir: Path | None, image_cache: Path | None
) -> None:
    """Serve realize/teardown/heartbeat and the guest relay for driver processes on this host.

    Runs the doctor-readiness subset at startup and refuses to serve unhealthy. A restart loses the replay log, relay map, and admission charges (recorded v1 limitation); disk-driven teardown (the reaper, `inspect-ranges down`) is the recovery.
    """

    async def serve() -> None:
        endpoint = Applier(
            socket_path,
            state_dir if state_dir is not None else default_state_dir(),
            image_cache=image_cache
            if image_cache is not None
            else default_image_cache(),
        )
        await endpoint.start()
        click.echo(f"applier serving on {socket_path}")
        try:
            await asyncio.Event().wait()
        finally:
            await endpoint.aclose()

    try:
        asyncio.run(serve())
    except KeyboardInterrupt:
        click.echo("applier stopped")

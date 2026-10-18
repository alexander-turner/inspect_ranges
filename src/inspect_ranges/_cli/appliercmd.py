"""`inspect-ranges applier`: serve the host plane and guest relay on a unix socket."""

import asyncio
import signal
from pathlib import Path

import click

from .._host.applier import Applier
from .._host.glovebox import GloveboxHost
from .._host.local import HostNotReadyError
from .._runtime.images import default_image_cache
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
@click.option(
    "--glovebox-cell",
    "glovebox_cells",
    multiple=True,
    metavar="GUEST=CONTAINER_ID",
    help="Bind a `provider: glovebox` guest to the CRI container id of its cell; "
    "the applier routes that guest's exec/read/write into the cell and stitches "
    "its segment bridge to the node netns at realize. Repeatable.",
)
def applier(
    socket_path: Path,
    state_dir: Path | None,
    image_cache: Path | None,
    glovebox_cells: tuple[str, ...],
) -> None:
    """Serve realize/teardown/heartbeat and the guest relay for driver processes on this host.

    Runs the doctor-readiness subset at startup and refuses to serve unhealthy. A restart loses the replay log, relay map, and admission charges (recorded v1 limitation); disk-driven teardown (the reaper, `inspect-ranges down`) is the recovery.
    """
    containers: dict[str, str] = {}
    for pair in glovebox_cells:
        guest, _, container_id = pair.partition("=")
        if not guest or not container_id:
            raise click.BadParameter(
                f"--glovebox-cell expects GUEST=CONTAINER_ID, got {pair!r}"
            )
        containers[guest] = container_id
    glovebox = GloveboxHost(containers=containers) if containers else None

    async def serve() -> None:
        endpoint = Applier(
            socket_path,
            state_dir if state_dir is not None else default_state_dir(),
            image_cache=image_cache
            if image_cache is not None
            else default_image_cache(),
            glovebox=glovebox,
        )
        # SIGTERM must reach the finally, and from BEFORE start(): the
        # readiness gate plus bind is a multi-second window, and a killed
        # applier that leaves a stale socket file behind makes the next
        # applier's startup racy for anything watching the path
        stop = asyncio.Event()
        loop = asyncio.get_running_loop()

        def request_stop() -> None:
            # one graceful stop; further signals regain the default
            # disposition, so a hung shutdown stays killable without the
            # SIGKILL that would recreate the stale-socket hazard
            stop.set()
            for signum in (signal.SIGTERM, signal.SIGINT):
                loop.remove_signal_handler(signum)

        for signum in (signal.SIGTERM, signal.SIGINT):
            loop.add_signal_handler(signum, request_stop)
        try:
            # expected startup refusals convert here, scoped to start():
            # an OSError hours into serving is an unexpected bug and must
            # keep its traceback, not a bind-failure message
            try:
                await endpoint.start()
            except HostNotReadyError as error:
                raise click.ClickException(str(error)) from error
            except OSError as error:
                raise click.ClickException(
                    f"cannot serve on {socket_path}: {error}"
                ) from error
            click.echo(f"applier serving on {socket_path}")
            await stop.wait()
        finally:
            await endpoint.aclose()
        click.echo("applier stopped")

    try:
        asyncio.run(serve())
    except KeyboardInterrupt:
        # only reachable in the sliver before the loop installs handlers
        click.echo("applier stopped (interrupted during startup)")

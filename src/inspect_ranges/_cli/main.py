import click

from .. import __version__
from .._devbox import devbox_group
from .daemonbundle import daemon_bundle
from .doctor import doctor
from .imagescmd import images
from .plancmd import plan, render
from .reapercmd import reaper
from .schema import schema
from .upcmd import down, up
from .validate import validate


@click.group()
@click.version_option(version=__version__, prog_name="inspect-ranges")
def ranges() -> None:
    """Inspect Ranges CLI."""


ranges.add_command(daemon_bundle)
ranges.add_command(devbox_group)
ranges.add_command(doctor)
ranges.add_command(images)
ranges.add_command(plan)
ranges.add_command(reaper)
ranges.add_command(render)
ranges.add_command(schema)
ranges.add_command(up)
ranges.add_command(down)
ranges.add_command(validate)


def main() -> None:
    ranges()

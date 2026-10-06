import click

from .. import __version__
from .._devbox import devbox_group
from .doctor import doctor
from .plancmd import plan, render
from .schema import schema
from .validate import validate


@click.group()
@click.version_option(version=__version__, prog_name="inspect-ranges")
def ranges() -> None:
    """Inspect Ranges CLI."""


ranges.add_command(devbox_group)
ranges.add_command(doctor)
ranges.add_command(plan)
ranges.add_command(render)
ranges.add_command(schema)
ranges.add_command(validate)


def main() -> None:
    ranges()

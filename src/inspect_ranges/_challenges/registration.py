"""Goal-type registration loading for plain (non-inspect) processes.

Eval-time parsing runs under inspect, whose startup loads the `inspect_ai` entry-point group before any parse, so custom goal types registered by third-party packages are always known there. The build and the CLI's `validate` are plain processes: they call `ensure_goal_type_registrations` before parsing `challenges.yaml`, or a custom-typed file dies with `unknown-goal-type` while the identical eval passes.
"""

import importlib.metadata as metadata
import logging

logger = logging.getLogger(__name__)

__all__ = ["ensure_goal_type_registrations"]


def ensure_goal_type_registrations() -> None:
    """Load every `inspect_ai` entry point so custom goal types are registered before `challenges.yaml` parses.

    The error posture mirrors inspect's own loader: each entry point loads independently, and one package's failure is a warning naming the entry point and its cause, never a failure of the caller; the honest refusal stays downstream, where the parse still refuses an unregistered type with the known-name listing.
    """
    for entry_point in metadata.entry_points(group="inspect_ai"):
        try:
            entry_point.load()
        except Exception as error:
            logger.warning(
                "inspect_ai entry point %r (%s) failed to load; goal types it "
                "registers stay unknown to this process: %s: %s",
                entry_point.name,
                entry_point.value,
                type(error).__name__,
                error,
            )

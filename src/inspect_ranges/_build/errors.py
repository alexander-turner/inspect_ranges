"""The build phase's stage-named failure type, shared across its modules."""

from pathlib import Path


class BuildError(Exception):
    """Stage-named build failure; recipe failures carry guest, recipe, and log path."""

    def __init__(
        self,
        stage: str,
        message: str,
        *,
        guest: str | None = None,
        recipe: str | None = None,
        log_path: Path | None = None,
    ) -> None:
        self.stage = stage
        self.guest = guest
        self.recipe = recipe
        self.log_path = log_path
        detail = f" guest {guest!r}" if guest else ""
        detail += f" recipe {recipe!r}" if recipe else ""
        super().__init__(
            f"[{stage}]{detail}: {message}" if detail else f"[{stage}] {message}"
        )

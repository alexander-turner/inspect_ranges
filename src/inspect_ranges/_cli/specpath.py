"""The `.` default for spec-taking verbs (Journey A, decided 2026-10-17): bare invocations work from inside a range directory."""

from pathlib import Path

import click


def resolve_spec_path(path: Path | None) -> Path:
    """The `range.yaml` a spec-taking verb operates on.

    An explicit file is used as given; a directory means its `range.yaml`; no argument means the current directory's `range.yaml`.
    """
    base = path if path is not None else Path(".")
    candidate = base / "range.yaml" if base.is_dir() else base
    if not candidate.is_file():
        raise click.UsageError(
            f"no range.yaml at {candidate} (run from a range directory, or pass a range directory or spec file)"
        )
    return candidate

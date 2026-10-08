"""Project ownership records and the structured stage log.

Teardown is keyed off recorded ownership, never live process state: `up` registers the project here before creating any resource (the cleanup-registry pattern from `docker-provider-reuse`), so a `down` run by any process, after any crash, can find and remove everything the project ever owned. The stage log is the debuggability contract from `realizer-v1`: one JSONL line per stage transition, each failure naming its stage and guest.
"""

import json
import os
import shutil
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from pydantic import BaseModel

PROJECT_PREFIX = "ir-"
"""Compose projects owned by the realizer; `down --all` sweeps exactly this prefix (the channel track's `chan-` projects are never touched)."""


class OwnerRecord(BaseModel):
    """What `up` registers before touching docker: enough for any process to tear the project down."""

    project: str
    range_name: str
    spec_sha256: str
    bundle: str
    created: str
    pid: int


def default_state_dir() -> Path:
    """`$XDG_STATE_HOME/inspect-ranges/projects` (or the `~/.local/state` default)."""
    base = os.environ.get("XDG_STATE_HOME")
    root = Path(base) if base else Path.home() / ".local" / "state"
    return root / "inspect-ranges" / "projects"


def project_dir(state_dir: Path, project: str) -> Path:
    """The per-project state directory (owner record, stage log, pulled console logs)."""
    return state_dir / project


def write_owner(state_dir: Path, record: OwnerRecord) -> None:
    """Register ownership; called before the first docker resource exists."""
    directory = project_dir(state_dir, record.project)
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "owner.json").write_text(record.model_dump_json(indent=2) + "\n")


def read_owner(state_dir: Path, project: str) -> OwnerRecord | None:
    """The project's owner record, or None when unregistered or unreadable."""
    path = project_dir(state_dir, project) / "owner.json"
    try:
        return OwnerRecord.model_validate_json(path.read_text())
    except (OSError, ValueError):
        return None


def list_projects(state_dir: Path) -> list[str]:
    """Registered project names (including entries whose resources are already gone)."""
    if not state_dir.is_dir():
        return []
    return sorted(
        entry.name
        for entry in state_dir.iterdir()
        if entry.is_dir() and entry.name.startswith(PROJECT_PREFIX)
    )


def remove_project(state_dir: Path, project: str) -> None:
    """Drop the project's state after teardown; idempotent."""
    shutil.rmtree(project_dir(state_dir, project), ignore_errors=True)


def owner_record(
    project: str, range_name: str, spec_sha256: str, bundle: Path
) -> OwnerRecord:
    """A fresh owner record for this process."""
    return OwnerRecord(
        project=project,
        range_name=range_name,
        spec_sha256=spec_sha256,
        bundle=str(bundle),
        created=datetime.now(timezone.utc).isoformat(timespec="seconds"),
        pid=os.getpid(),
    )


class StageLog:
    """Append-only JSONL stage log under the project state directory."""

    def __init__(self, state_dir: Path, project: str) -> None:
        directory = project_dir(state_dir, project)
        directory.mkdir(parents=True, exist_ok=True)
        self.path = directory / "stages.jsonl"

    def log(self, stage: str, status: str, **fields: Any) -> None:
        """One stage transition; `status` is `start`, `ok`, or `fail` (failures carry `guest` and `error` where they apply)."""
        entry: dict[str, Any] = {"ts": time.time(), "stage": stage, "status": status}
        entry.update(fields)
        with self.path.open("a") as handle:
            handle.write(json.dumps(entry) + "\n")

    def events(self) -> list[dict[str, Any]]:
        """Every logged entry (for tests and diagnostics)."""
        if not self.path.is_file():
            return []
        return [json.loads(line) for line in self.path.read_text().splitlines()]

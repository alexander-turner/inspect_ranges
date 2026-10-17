"""Project ownership records and the structured stage log.

Teardown is keyed off recorded ownership, never live process state: `up` registers the project here before creating any resource (the cleanup-registry pattern from `docker-provider-reuse`), so a `down` run by any process, after any crash, can find and remove everything the project ever owned. The stage log is the debuggability contract from `realizer-v1`: one JSONL line per stage transition, each failure naming its stage and guest.
"""

import hashlib
import json
import os
import shutil
import stat
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from pydantic import BaseModel

PROJECT_PREFIX = "ir-"
"""Compose projects owned by the realizer; `down --all` sweeps exactly this prefix (the channel track's `chan-` projects are never touched)."""


class OwnerRecord(BaseModel):
    """What `up` registers before touching docker: enough for any process to tear the project down.

    The optional provider-origin fields are written by the Inspect sandbox provider after a successful boot (the CID lease registry covers the crash window before that), so a fresh-process `cli_cleanup` can tell provider samples from operator-run projects.
    """

    project: str
    range_name: str
    spec_sha256: str
    bundle: str
    created: str
    pid: int
    origin: str | None = None
    sample_id: str | None = None
    cid_base: int | None = None


def default_state_dir() -> Path:
    """`$XDG_STATE_HOME/inspect-ranges/projects` (or the `~/.local/state` default)."""
    base = os.environ.get("XDG_STATE_HOME")
    root = Path(base) if base else Path.home() / ".local" / "state"
    return root / "inspect-ranges" / "projects"


def project_dir(state_dir: Path, project: str) -> Path:
    """The per-project state directory (owner record, stage log, pulled console logs)."""
    return state_dir / project


def ch_vsock_dir(project: str) -> Path:
    """The host directory holding a project's Cloud Hypervisor vsock sockets.

    Not under the state dir: `AF_UNIX` paths cap at 108 bytes and provider project names are long, so the directory is a short per-user root plus a digest of the project name.
    """
    root = Path(tempfile.gettempdir()) / f"inspect-ranges-{os.getuid()}"
    return root / hashlib.sha256(project.encode()).hexdigest()[:16]


def prepare_ch_vsock_dir(project: str) -> Path:
    """Create `ch_vsock_dir(project)` for the range container to bind-mount.

    The per-user root is private (0700, owned by this user; anything else refuses, since it sits in a shared temp dir). The project directory is sticky and writable by all (1733) because the unprivileged VMM inside the container runs as a uid this host does not know; the private root is what keeps other host users out, and the sticky bit keeps this user able to remove the VMM's sockets.

    Raises:
        PermissionError: The per-user root exists but is not a private directory owned by this user.
    """
    directory = ch_vsock_dir(project)
    root = directory.parent
    root.mkdir(mode=0o700, exist_ok=True)
    info = root.lstat()
    if (
        not stat.S_ISDIR(info.st_mode)
        or info.st_uid != os.getuid()
        or info.st_mode & 0o077
    ):
        raise PermissionError(
            f"{root} must be a directory owned by uid {os.getuid()} with mode 0700"
        )
    directory.mkdir(exist_ok=True)
    directory.chmod(0o1733)
    return directory


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

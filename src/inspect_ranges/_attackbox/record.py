"""The attack-box origin record: teardown-by-origin for a guest an external provider owns.

Mirrors the owner-record pattern (`_runtime/ownership.py`): `up` writes `attackbox.json` into the project state dir BEFORE the provider boots anything, so a `down` run by any process, after any crash, finds the origin and reclaims the foreign box through its own backend. The record carries the origin verbatim (the `INSPECT_RANGES_ATTACK_BOX` value, re-resolved by import in whatever process tears down) plus the provider's opaque reclaim token and, after a successful boot, the exec socket facts the out-of-band oracle needs (`boot.json` has no socket for a guest the realizer never booted).
"""

from pathlib import Path

from pydantic import BaseModel, ConfigDict

from .._runtime.ownership import project_dir

RECORD_FILENAME = "attackbox.json"


class AttackBoxRecord(BaseModel):
    """What `up` registers before the external provider boots: enough for any process to reclaim the foreign box."""

    model_config = ConfigDict(extra="forbid")

    origin: str
    """The full `INSPECT_RANGES_ATTACK_BOX` value, verbatim: re-resolved by import at teardown."""
    project: str
    guest_name: str
    cid: int
    reclaim_token: str = ""
    """The provider's opaque teardown token (`AttackBoxHandle.reclaim_token`); empty until boot returns."""
    exec_socket: str | None = None
    """The exec surface's unix socket path, once booted (for out-of-band attach)."""
    exec_uid: int | None = None
    """The uid the exec socket's peer must have (`SO_PEERCRED`), once booted."""
    created: str


def attack_box_record_path(state_dir: Path, project: str) -> Path:
    """Where the project's attack-box record lives (inside the project state dir, so `remove_project` drops it)."""
    return project_dir(state_dir, project) / RECORD_FILENAME


def write_attack_box_record(state_dir: Path, record: AttackBoxRecord) -> None:
    """Register the external attack box; called before the provider boots anything."""
    path = attack_box_record_path(state_dir, record.project)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(record.model_dump_json(indent=2) + "\n")


def read_attack_box_record(state_dir: Path, project: str) -> AttackBoxRecord | None:
    """The project's attack-box record, or None when the project has no external attack box or the record is unreadable."""
    path = attack_box_record_path(state_dir, project)
    try:
        return AttackBoxRecord.model_validate_json(path.read_text())
    except (OSError, ValueError):
        return None

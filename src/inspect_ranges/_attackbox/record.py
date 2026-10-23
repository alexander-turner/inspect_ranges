"""The attack-box origin record: teardown-by-origin for a guest an external provider owns.

Mirrors the owner-record pattern (`_runtime/ownership.py`): `up` writes `attackbox.json` into the project state dir BEFORE the provider boots anything, so a `down` run by any process, after any crash, finds the origin and reclaims the foreign box through its own backend. The record carries the origin verbatim (the `INSPECT_RANGES_ATTACK_BOX` value, re-resolved by import in whatever process tears down) plus the provider's opaque reclaim token and, after a successful boot, the exec socket facts the out-of-band oracle needs (`boot.json` has no socket for a guest the realizer never booted).

The write is atomic (temp file + rename: the record is rewritten in place after boot, and a torn write must never read as "no external box") and the parse is lenient about unknown fields (an older process must still reclaim a record a newer one wrote). Absent and unreadable are different answers: absent means no external box; unreadable raises, because proceeding as if absent is exactly the silent deny-first bypass the record exists to prevent.
"""

import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from pydantic import BaseModel

from .._runtime.ownership import project_dir

RECORD_FILENAME = "attackbox.json"


def record_timestamp() -> str:
    """The record `created` convention, matching the owner record's exactly (`ownership.py`: UTC, second precision)."""
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class AttackBoxRecordError(ValueError):
    """The record file exists but cannot be parsed; teardown must refuse rather than strand the provider's box."""


class AttackBoxRecord(BaseModel):
    """What `up` registers before the external provider boots: enough for any process to reclaim the foreign box."""

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
    """Register the external attack box (atomically; called before the provider boots, and again after with the handle facts)."""
    path = attack_box_record_path(state_dir, record.project)
    path.parent.mkdir(parents=True, exist_ok=True)
    handle, temp = tempfile.mkstemp(dir=path.parent, prefix=".attackbox-")
    try:
        with os.fdopen(handle, "w") as sink:
            sink.write(record.model_dump_json(indent=2) + "\n")
        os.replace(temp, path)
    except BaseException:
        try:
            os.unlink(temp)
        except OSError:
            pass
        raise


def read_attack_box_record(state_dir: Path, project: str) -> AttackBoxRecord | None:
    """The project's attack-box record: `None` when the project has no external attack box.

    Raises:
        AttackBoxRecordError: The file exists but does not parse; reading it as absent would skip the deny-first reclaim and strand a live foreign VMM, so the caller must refuse and name the path.
    """
    path = attack_box_record_path(state_dir, project)
    try:
        text = path.read_text()
    except FileNotFoundError:
        return None
    except OSError as error:
        raise AttackBoxRecordError(
            f"attack-box record {path} is unreadable ({error}); repair it "
            "before tearing the project down"
        ) from error
    try:
        return AttackBoxRecord.model_validate_json(text)
    except ValueError as error:
        raise AttackBoxRecordError(
            f"attack-box record {path} does not parse ({error}); repair it "
            "before tearing the project down"
        ) from error

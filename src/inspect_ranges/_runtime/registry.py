"""Flock-guarded JSON registries: one read-modify-write discipline for `cids.json` and `leases.json`.

Extracted from the CID allocator (`range-host-v1.md`) so the host lease store shares the exact same guarantees: every mutation is a read-modify-write under an exclusive `flock`; writes are atomic (temp file plus rename), sorted, and newline-terminated; entries another version wrote that this version cannot parse are preserved verbatim and never silently dropped, and read-only operations never rewrite the file at all.
"""

import fcntl
import json
from collections.abc import Generator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import cast

from pydantic import BaseModel


@dataclass
class RegistryView[EntryT: BaseModel]:
    """The registry contents under the lock: parseable entries, plus everything else verbatim."""

    entries: dict[str, EntryT]
    extras: dict[str, object]


class JsonRegistry[EntryT: BaseModel]:
    """A cross-process string-keyed registry of one pydantic entry type over a flock-guarded JSON file."""

    def __init__(self, path: Path, lock_path: Path, entry_type: type[EntryT]) -> None:
        self._path = path
        self._lock_path = lock_path
        self._entry_type = entry_type
        path.parent.mkdir(parents=True, exist_ok=True)

    @property
    def path(self) -> Path:
        return self._path

    @contextmanager
    def locked(self, *, write: bool) -> Generator[RegistryView[EntryT]]:
        """The registry under the flock. Read-only operations never rewrite the file, so an entry this version cannot parse is never silently destroyed by a mere listing; writes preserve unparseable entries verbatim (another version's entry stays findable). An exception out of the body skips the write."""
        with open(self._lock_path, "a+") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            try:
                view = self._read()
                yield view
                if write:
                    self._write(view)
            finally:
                fcntl.flock(lock, fcntl.LOCK_UN)

    def _read(self) -> RegistryView[EntryT]:
        # an unreadable, non-JSON, or non-object file reads as empty
        # (inherited from the CID allocator for byte-compatibility), which
        # means a corrupted registry is silently discarded by the next
        # write; doctor's strict registry health checks are the mitigation
        try:
            raw = json.loads(self._path.read_text())
        except (OSError, ValueError):
            return RegistryView(entries={}, extras={})
        if not isinstance(raw, dict):
            return RegistryView(entries={}, extras={})
        parsed = cast("dict[str, object]", raw)
        entries: dict[str, EntryT] = {}
        extras: dict[str, object] = {}
        for key, entry in parsed.items():
            try:
                entries[key] = self._entry_type.model_validate(entry)
            except ValueError:
                extras[key] = entry  # preserved verbatim, never silently dropped
        return RegistryView(entries=entries, extras=extras)

    def _write(self, view: RegistryView[EntryT]) -> None:
        payload: dict[str, object] = {
            key: entry.model_dump() for key, entry in view.entries.items()
        }
        for key, entry in view.extras.items():
            payload.setdefault(key, entry)
        temporary = self._path.with_suffix(".json.tmp")
        temporary.write_text(json.dumps(dict(sorted(payload.items())), indent=2) + "\n")
        temporary.replace(self._path)

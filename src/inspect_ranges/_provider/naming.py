"""Per-sample identity: project names and the cross-process CID lease registry.

Project names are collision-free by construction: `up`'s default project keys on the spec digest, so two samples of the same spec would collide; the provider always passes an explicit project of the form `ir-<range>-<sanitized sample id>-<6 hex random>`. The random suffix (never epoch arithmetic) makes epochs, same-sample retries, and layer-3 respins distinct, and the `ir-` prefix keeps `down --all` and `cli_cleanup` sweeps intact.

CIDs are host-kernel-global, so parallel samples need disjoint blocks and the allocator must be safe across processes, not just tasks: every mutation is a read-modify-write of `cids.json` under an `flock`. The provider's partition starts at 10000, beside the compiler default (3+), the channel harness (2048-2999), and the realizer batteries (3000+).
"""

import fcntl
import json
import re
import secrets
from collections.abc import Generator
from contextlib import contextmanager
from pathlib import Path
from typing import cast

from pydantic import BaseModel

from .._runtime.ownership import PROJECT_PREFIX

PROVIDER_CID_BASE = 10_000
"""First CID of the provider partition (documented beside the other bands in provider-v1.md)."""

_SANITIZE = re.compile(r"[^a-z0-9_-]+")
_MAX_COMPONENT = 24


def _sanitize(value: str) -> str:
    cleaned = _SANITIZE.sub("-", value.lower()).strip("-") or "x"
    return cleaned[:_MAX_COMPONENT]


def sample_project(range_name: str, sample_id: str) -> str:
    """A fresh, compose-legal project name for one sample attempt.

    Every call mints a new name (the Daytona rule: never retry a create with unchanged identity), so layer-3 respins and sample retries can never collide with a prior attempt's leftovers.
    """
    return (
        f"{PROJECT_PREFIX}{_sanitize(range_name)}-{_sanitize(sample_id)}"
        f"-{secrets.token_hex(3)}"
    )


class CidLease(BaseModel):
    """One project's leased CID block."""

    project: str
    base: int
    count: int


class CidAllocator:
    """Cross-process CID block leasing over a flock-guarded `cids.json`.

    Leases are keyed by project name so ANY process can release them (`down`, `cli_cleanup`); `prune` drops leases whose project no longer exists anywhere.
    """

    def __init__(self, state_dir: Path, *, base: int = PROVIDER_CID_BASE) -> None:
        self._path = state_dir / "cids.json"
        self._lock_path = state_dir / ".cids.lock"
        self._base = base
        state_dir.mkdir(parents=True, exist_ok=True)

    @contextmanager
    def _locked(self) -> Generator[dict[str, CidLease]]:
        with open(self._lock_path, "a+") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            try:
                leases = self._read()
                yield leases
                self._write(leases)
            finally:
                fcntl.flock(lock, fcntl.LOCK_UN)

    def _read(self) -> dict[str, CidLease]:
        try:
            raw = json.loads(self._path.read_text())
        except (OSError, ValueError):
            return {}
        if not isinstance(raw, dict):
            return {}
        entries = cast("dict[str, object]", raw)
        leases: dict[str, CidLease] = {}
        for project, entry in entries.items():
            try:
                leases[project] = CidLease.model_validate(entry)
            except ValueError:
                continue  # a corrupt entry never blocks allocation; prune clears it
        return leases

    def _write(self, leases: dict[str, CidLease]) -> None:
        payload = {
            project: lease.model_dump() for project, lease in sorted(leases.items())
        }
        temporary = self._path.with_suffix(".json.tmp")
        temporary.write_text(json.dumps(payload, indent=2) + "\n")
        temporary.replace(self._path)

    def lease(self, project: str, count: int) -> CidLease:
        """Lease a contiguous block of `count` CIDs for `project` (first fit in the partition)."""
        if count < 1:
            raise ValueError(f"cannot lease {count} CIDs")
        with self._locked() as leases:
            if project in leases:
                raise ValueError(f"project {project!r} already holds a lease")
            taken = sorted((lease.base, lease.count) for lease in leases.values())
            base = self._base
            for existing_base, existing_count in taken:
                if base + count <= existing_base:
                    break
                base = max(base, existing_base + existing_count)
            lease = CidLease(project=project, base=base, count=count)
            leases[project] = lease
            return lease

    def release(self, project: str) -> None:
        """Release `project`'s lease; idempotent, callable from any process."""
        with self._locked() as leases:
            leases.pop(project, None)

    def leased_projects(self) -> list[str]:
        """Projects currently holding leases (the provider-origin marker for fresh-process cleanup)."""
        with self._locked() as leases:
            return sorted(leases)

    def prune(self, live_projects: set[str]) -> list[str]:
        """Drop leases for projects not in `live_projects`; returns what was pruned."""
        with self._locked() as leases:
            stale = sorted(set(leases) - live_projects)
            for project in stale:
                leases.pop(project, None)
            return stale

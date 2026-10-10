"""The host lease store: `leases.json` beside `cids.json`, over the shared `JsonRegistry` discipline.

A lease is identity plus expiry, nothing else (`host-provider.md`): a sample that outlives its lease is reclaimed, and release is destruction. Renewal is a compare-and-swap under the flock at a third of the TTL (`INSPECT_RANGES_LEASE_TTL_S`, default 600); a lost CAS raises `LeaseLostError` and the sample fails loudly as lease loss. The reaper reclaims on expiry alone and never probes liveness: a healthy sample never expires because renewal is independent of sample activity, so the only way to expire mid-sample is a dead or wedged driver, which is exactly the reaper's job (`range-host-v1.md`).
"""

import os
import uuid
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, field_validator

from .._channel.protocol import Sha256Hex
from .._runtime.registry import JsonRegistry
from .host import HostFacts, IsolationLevel

DEFAULT_LEASE_TTL_S = 600.0

LeaseState = Literal["active", "reaping"]

NowFn = Callable[[], datetime]
"""Injectable clock returning a timezone-aware UTC `datetime` (tests freeze and advance it)."""


def _utcnow() -> datetime:
    return datetime.now(UTC)


def lease_ttl_s() -> float:
    """`INSPECT_RANGES_LEASE_TTL_S` as a positive float, default 600; renewal runs at a third of it.

    Raises:
        ValueError: The variable is set but not a positive number.
    """
    raw = os.environ.get("INSPECT_RANGES_LEASE_TTL_S")
    if raw is None:
        return DEFAULT_LEASE_TTL_S
    try:
        value = float(raw)
    except ValueError as error:
        raise ValueError(
            f"INSPECT_RANGES_LEASE_TTL_S must be a number of seconds, got {raw!r}"
        ) from error
    if value <= 0:
        raise ValueError(f"INSPECT_RANGES_LEASE_TTL_S must be positive, got {raw!r}")
    return value


class LeaseLostError(RuntimeError):
    """The sample's host lease is gone or being reaped; the sample fails loudly as lease loss, never limps on."""


class HostLease(BaseModel):
    """One sample's claim on a host: identity plus absolute expiry, the exact record shape from `range-host-v1.md`."""

    model_config = ConfigDict(extra="forbid")

    lease_id: str
    """Opaque lease identity (uuid4 hex)."""
    project: str
    task_name: str
    sample_id: str
    isolation: IsolationLevel
    origin: str
    """The backend that minted the lease: `local`, or `uds:<socket>` for the applier path."""
    bundle_path: str
    bundle_digest: Sha256Hex
    staging: str
    created: str
    expires_at: str
    """Absolute ISO-8601 UTC expiry; the reaper compares against it, never against liveness."""
    state: LeaseState
    host_facts: HostFacts

    @field_validator("created", "expires_at")
    @classmethod
    def _aware_iso(cls, value: str) -> str:
        if datetime.fromisoformat(value).tzinfo is None:
            raise ValueError(f"timestamp {value!r} must be timezone-aware")
        return value

    def expires(self) -> datetime:
        return datetime.fromisoformat(self.expires_at)


class LeaseStore:
    """Cross-process host leases over a flock-guarded `leases.json`, keyed by lease id.

    Shares the `JsonRegistry` discipline with the CID allocator: atomic sorted writes, and entries another version wrote are preserved verbatim, never silently dropped.
    """

    def __init__(self, state_dir: Path, *, now_fn: NowFn = _utcnow) -> None:
        self._registry = JsonRegistry(
            state_dir / "leases.json", state_dir / ".leases.lock", HostLease
        )
        self._now = now_fn

    def acquire(
        self,
        *,
        project: str,
        task_name: str,
        sample_id: str,
        isolation: IsolationLevel,
        origin: str,
        bundle_path: str,
        bundle_digest: str,
        staging: str,
        host_facts: HostFacts,
        ttl_s: float | None = None,
    ) -> HostLease:
        """Mint a fresh active lease expiring `ttl_s` (default `lease_ttl_s()`) from now."""
        now = self._now()
        ttl = lease_ttl_s() if ttl_s is None else ttl_s
        lease = HostLease(
            lease_id=uuid.uuid4().hex,
            project=project,
            task_name=task_name,
            sample_id=sample_id,
            isolation=isolation,
            origin=origin,
            bundle_path=bundle_path,
            bundle_digest=bundle_digest,
            staging=staging,
            created=now.isoformat(),
            expires_at=(now + timedelta(seconds=ttl)).isoformat(),
            state="active",
            host_facts=host_facts,
        )
        with self._registry.locked(write=True) as view:
            view.entries[lease.lease_id] = lease
        return lease

    def renew(self, lease_id: str, ttl_s: float | None = None) -> HostLease:
        """The renewal CAS: extend expiry if and only if the lease still exists and is `active`.

        Raises:
            LeaseLostError: The lease is gone or marked `reaping`; the reaper won (or already reclaimed), and the sample must fail as lease loss rather than keep running on a reclaimed host.
        """
        ttl = lease_ttl_s() if ttl_s is None else ttl_s
        with self._registry.locked(write=True) as view:
            current = view.entries.get(lease_id)
            if current is None or current.state != "active":
                verdict = "gone" if current is None else current.state
                raise LeaseLostError(
                    f"host lease {lease_id} is {verdict}; the host was (or is being) reclaimed"
                )
            renewed = current.model_copy(
                update={
                    "expires_at": (self._now() + timedelta(seconds=ttl)).isoformat()
                }
            )
            view.entries[lease_id] = renewed
            return renewed

    def release(self, lease_id: str) -> None:
        """Remove the lease; idempotent, callable from any process. Release is destruction: call only after a successful teardown."""
        with self._registry.locked(write=True) as view:
            view.entries.pop(lease_id, None)

    def get(self, lease_id: str) -> HostLease | None:
        with self._registry.locked(write=False) as view:
            return view.entries.get(lease_id)

    def leases(self) -> list[HostLease]:
        """Every parseable lease, sorted by lease id (read-only; never rewrites the file)."""
        with self._registry.locked(write=False) as view:
            return [view.entries[key] for key in sorted(view.entries)]

    def expired(self) -> list[HostLease]:
        """Leases past expiry or already `reaping`, without mutating anything (the doctor-hint view of what a sweep would select)."""
        now = self._now()
        return [
            lease
            for lease in self.leases()
            if lease.state == "reaping" or lease.expires() <= now
        ]

    def mark_reaping(self) -> list[HostLease]:
        """One sweep selection under the flock: every lease already `reaping` (crash resume) plus every `active` lease whose expiry, re-checked against now, has passed (a renewal may have landed since the sweep was scheduled), marked `reaping`. Teardown happens outside the lock; a marked lease refuses renewal, so the race is settled here, atomically, in one direction or the other."""
        now = self._now()
        with self._registry.locked(write=True) as view:
            selected: list[HostLease] = []
            for lease_id in sorted(view.entries):
                lease = view.entries[lease_id]
                if lease.state == "reaping":
                    selected.append(lease)
                elif lease.expires() <= now:
                    marked = lease.model_copy(update={"state": "reaping"})
                    view.entries[lease_id] = marked
                    selected.append(marked)
            return selected

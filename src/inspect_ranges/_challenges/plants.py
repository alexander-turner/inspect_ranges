"""The plant record: per-sample proof material, values in memory, digests at T1.

The split (`challenges-v1.md`, deliberate deviation from the sample-store sketch): plant VALUES live only in this in-memory store, scoped to the sample's `SampleHandle` and gone with the process. What persists is the T1 record on the `plants` evidence stream: key, goal, placement, sha256 digest, clock stamps. Rationale: the Inspect sample store lands in the eval log, a durable, shared artifact, and plant values there would outlive the sample; the digest supports post-hoc equality audits (hash a claimed submission, compare) without ever persisting the secret. Live scoring that needs the raw value (canary containment searches) reads it from memory in the same process that planted it.

Nothing in this module logs, serializes, or reprs a plant value.
"""

import hashlib
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .._provider.evidence import EvidenceSession

__all__ = ["Plant", "PlantStore"]


@dataclass
class Plant:
    """One planted value's record; `value` is excluded from repr by design."""

    key: str
    goal_id: str
    guest: str
    path: str
    digest: str
    size: int
    value: bytes = field(repr=False)


class PlantStore:
    """Per-sample plant record: `record` at setup, `get`/`digest` at compare, `discard` on unwind.

    Values are held in memory only; every mutation emits a value-free record to the `plants` evidence stream when evidence is enabled (best-effort, like every driver stream).
    """

    def __init__(self, session: "EvidenceSession | None") -> None:
        self._session = session
        self._plants: dict[str, Plant] = {}

    async def record(
        self, key: str, value: bytes, *, goal_id: str, guest: str, path: str
    ) -> None:
        """Record a plant before it lands on the guest (the T1 record precedes guest state).

        Raises:
            ValueError: `key` is already recorded (a plant key is written once per sample).
        """
        if key in self._plants:
            raise ValueError(f"plant key {key!r} already recorded")
        digest = hashlib.sha256(value).hexdigest()
        plant = Plant(
            key=key,
            goal_id=goal_id,
            guest=guest,
            path=path,
            digest=digest,
            size=len(value),
            value=value,
        )
        self._plants[key] = plant
        await self._emit("planted", plant)

    def get(self, key: str) -> bytes:
        """The planted value, for host-side comparison in this process.

        Raises:
            KeyError: No plant under `key`.
        """
        return self._plants[key].value

    def plant(self, key: str) -> Plant:
        """The full plant record (placement metadata; `value` rides along for in-process use).

        Raises:
            KeyError: No plant under `key`.
        """
        return self._plants[key]

    def digest(self, key: str) -> str:
        """The plant's sha256 hex digest (what the T1 record carries).

        Raises:
            KeyError: No plant under `key`.
        """
        return self._plants[key].digest

    def keys(self) -> list[str]:
        """Recorded plant keys, in insertion order."""
        return list(self._plants)

    async def discard(self, key: str, *, reason: str) -> None:
        """Drop a plant from the record (setup unwind), emitting a value-free `unwound` event.

        Raises:
            KeyError: No plant under `key`.
        """
        plant = self._plants.pop(key)
        await self._emit("unwound", plant, reason=reason)

    async def _emit(
        self, event: str, plant: Plant, *, reason: str | None = None
    ) -> None:
        if self._session is None:
            return
        record: dict[str, object] = {
            "event": event,
            "key": plant.key,
            "goal": plant.goal_id,
            "guest": plant.guest,
            "path": plant.path,
            "sha256": plant.digest,
            "size": plant.size,
        }
        if reason is not None:
            record["reason"] = reason
        await self._session.record_plant(record)

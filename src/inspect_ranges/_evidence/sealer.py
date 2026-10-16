"""Reap-sealing: close an abandoned evidence record from the store, honestly.

A driver that dies mid-sample leaves its writers unsealed, and an unsealed record is extendable as well as truncatable. The reaper calls `seal_abandoned` after a successful teardown: every writer with manifest parts but no seal has its parts replayed (the same models the verifier reads), per-stream chain heads and counts recomputed, and a `reaped` seal delivered through the write-once sink, so a dead driver still leaves a verifiable record.

Two honest limitations, by design. Sealing needs a read-capable credential (the parts must be replayed), so a host whose evidence credential is put-only cannot reap-seal and the record stays unsealed, reported as such by verify. And a record whose parts are unparseable or non-contiguous is left alone with a warning: fabricating a seal over state the sealer cannot replay would anchor a lie. Sealing failures never block reclamation; the reaper logs and moves on.
"""

import asyncio
import logging

from pydantic import ValidationError

from .manifest import (
    ChunkRecord,
    ManifestPart,
    Seal,
    StreamSummary,
    canonical_bytes,
    clock_now,
    seal_digest,
    seal_key,
)
from .reader import EvidenceStore
from .s3 import sink_for_location, store_for_location
from .sink import EvidenceSink

logger = logging.getLogger(__name__)

SEAL_PUT_ATTEMPTS = 3
SEAL_RETRY_WAIT_S = 0.1
"""The writer's bounded-put discipline, applied to the one-shot-ever reap-seal put (B14: a single transient 5xx previously left the record permanently unsealed, since the reaper never revisits a reaped lease)."""


async def _put_seal_with_retry(sink: EvidenceSink, key: str, data: bytes) -> None:
    """Deliver the seal with bounded retries; every `FileExistsError` propagates.

    The ambiguity mapping differs from the writer's: a `FileExistsError` after a transient failure means EITHER our earlier put landed or another sealer (a racing reaper, or finalize) won. Both read as the race lost: the caller skips, and the record is sealed either way (quality-review B14).
    """
    last: Exception | None = None
    for attempt in range(SEAL_PUT_ATTEMPTS):
        try:
            await sink.put(key, data)
            return
        except FileExistsError:
            raise
        except Exception as error:
            last = error
            if attempt + 1 < SEAL_PUT_ATTEMPTS:
                await asyncio.sleep(SEAL_RETRY_WAIT_S * (attempt + 1))
    assert last is not None
    raise last


async def seal_abandoned(
    location: str, *, lease_id: str | None, sample_id: str | None
) -> dict[str, str]:
    """Seal every unsealed writer at `location` with status `reaped`.

    Returns writer name to seal digest for the writers actually sealed. Writers already sealed are skipped; writers whose parts cannot be replayed (unparseable, non-contiguous) are skipped with a warning and stay honestly unsealed. A `FileExistsError` on the seal put means another sealer won the race, also skipped.
    """
    store = store_for_location(location)
    sink = sink_for_location(location)
    sealed: dict[str, str] = {}
    manifest_keys = await store.list("manifests")
    writers = sorted(
        {key.split("/")[1] for key in manifest_keys if len(key.split("/")) >= 3}
    )
    for writer in writers:
        try:
            await store.get(seal_key(writer))
            continue  # already sealed (finalize ran, or another reaper won)
        except FileNotFoundError:
            pass
        seal = await _replay_for_seal(
            store, writer, lease_id=lease_id, sample_id=sample_id
        )
        if seal is None:
            continue
        try:
            await _put_seal_with_retry(sink, seal_key(writer), canonical_bytes(seal))
        except FileExistsError:
            # first-attempt: another sealer won outright; post-transient: our
            # earlier put may itself have landed. Either way the record is
            # sealed and this sealer skips (race lost).
            logger.info("reap-seal race lost for writer %r at %s", writer, location)
            continue
        except Exception as error:
            logger.warning(
                "reap-seal delivery failed for writer %r at %s (record stays "
                "unsealed): %s",
                writer,
                location,
                error,
            )
            continue
        digest = seal_digest(seal)
        sealed[writer] = digest
        logger.info(
            "reap-sealed evidence: location=%s writer=%s parts=%d digest=%s",
            location,
            writer,
            seal.parts,
            digest,
        )
    return sealed


async def _replay_for_seal(
    store: EvidenceStore,
    writer: str,
    *,
    lease_id: str | None,
    sample_id: str | None,
) -> Seal | None:
    """Replay a writer's delivered parts into the seal that honestly closes them, or `None` when replay is impossible."""
    keys = await store.list(f"manifests/{writer}")
    part_keys = sorted(key for key in keys if key.split("/")[-1].startswith("part-"))
    chains: dict[str, str] = {}
    counts: dict[str, StreamSummary] = {}
    for index, key in enumerate(part_keys):
        try:
            part = ManifestPart.model_validate_json(await store.get(key))
        except (ValidationError, ValueError, FileNotFoundError) as error:
            logger.warning(
                "reap-seal skipped for writer %r: part %s unreadable (%s)",
                writer,
                key,
                error,
            )
            return None
        if part.part != index or part.writer != writer:
            logger.warning(
                "reap-seal skipped for writer %r: part %s out of sequence "
                "(claims writer=%r part=%d, expected %d)",
                writer,
                key,
                part.writer,
                part.part,
                index,
            )
            return None
        for record in part.records:
            summary = counts.get(record.stream)
            if summary is None:
                summary = StreamSummary(
                    chain=record.chain, records=0, chunks=0, gaps=0, size=0
                )
                counts[record.stream] = summary
            chains[record.stream] = record.chain
            summary.records += 1
            if isinstance(record, ChunkRecord):
                summary.chunks += 1
                summary.size += record.size
            else:
                summary.gaps += 1
    for stream, summary in counts.items():
        summary.chain = chains[stream]
    return Seal(
        writer=writer,
        status="reaped",
        lease_id=lease_id,
        sample_id=sample_id,
        parts=len(part_keys),
        streams=dict(counts),
        unflushed=0,
        sealed_at=clock_now(),
    )

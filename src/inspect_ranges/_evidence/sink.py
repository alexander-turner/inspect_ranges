"""The evidence sink: write-once backends and the buffered chaining writer.

`EvidenceSink` is deliberately write-only: one `put` that must refuse an existing key. The writer keeps all chain state in memory and never reads back, so a host's credential can be scoped to put-only (evidence-v1.md); reading and verification live in `reader.py` behind a separate protocol.

`EvidenceWriter` is the delivery discipline around the manifest format: chunks are delivered before the manifest part that references them (a crash leaves unreferenced chunks, which read as residue, never as a referenced-but-missing break); backend errors buffer and retry and are never raised into the caller's path mid-stream; the local buffer cap drops the oldest undelivered chunk and commits an in-chain gap record in its sequence slot, so loss is always explicit. `seal` is the one call that can fail loudly: a seal must never claim parts that were not delivered, so undeliverable parts leave the record honestly unsealed.
"""

import asyncio
import hashlib
import logging
import os
import time
import uuid
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Protocol

from .manifest import (
    STREAM_NAME_PATTERN,
    WRITER_NAME_PATTERN,
    ChunkRecord,
    ClockSpan,
    ClockStamp,
    GapRecord,
    ManifestPart,
    ManifestRecord,
    Seal,
    SealStatus,
    StreamSummary,
    canonical_bytes,
    chain_genesis,
    chain_next,
    check_name,
    chunk_key,
    clock_now,
    part_key,
    seal_digest,
    seal_key,
)

logger = logging.getLogger(__name__)

_CHAIN_PLACEHOLDER = "0" * 64
"""Pattern-valid filler for a record's `chain` while computing the real value (the field is excluded from its own hash, so the content never matters)."""

DEFAULT_BUFFER_CAP_BYTES = 64 * 1024 * 1024
"""Default local backpressure cap; the runtime wires `INSPECT_RANGES_EVIDENCE_BUFFER_MB` to this at construction (slice 5)."""

DEFAULT_PART_INTERVAL_S = 15.0
"""Default manifest-part batching interval (chunk-2 verification finding 3): chunks still deliver on every flush (data durability is never delayed), but a manifest part is cut only when the oldest uncommitted record reaches this age, when `part_max_records` accumulate, or at seal. The trade is explicit: per-poll part objects (2 S3 objects per telemetry poll, ~29k per collector over 8h) collapse to a bounded cadence, while a crash can leave up to one interval of records committed to the in-memory chain but not yet in a delivered part, whose chunks then verify as unreferenced residue rather than referenced records. Set to 0 for cut-on-every-flush (the pre-batching behavior; unit tests pin exact part layouts with it)."""

DEFAULT_PART_MAX_RECORDS = 256
"""Records that force a part cut regardless of age (bounds part object size and the crash window under bursts)."""


class EvidenceSink(Protocol):
    """A write-once key/value backend.

    `put` stores `data` at `key` exactly once and MUST raise `FileExistsError` if the key already exists: re-putting is the rewrite the format forbids. Any other exception is a transient delivery failure the writer buffers and retries.
    """

    async def put(self, key: str, data: bytes) -> None: ...


class LocalDirSink:
    """Write-once objects under a local directory (the dev and CI backend).

    Writes are atomic and exclusive: data lands in a temporary file and is hard-linked to its final key, so a key either does not exist or holds complete bytes, and an existing key raises `FileExistsError`.
    """

    def __init__(self, root: Path) -> None:
        self.root = root

    async def put(self, key: str, data: bytes) -> None:
        target = self.root / key
        target.parent.mkdir(parents=True, exist_ok=True)
        tmp = target.parent / f".tmp-{uuid.uuid4().hex}"
        try:
            with open(tmp, "wb") as handle:
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
            os.link(tmp, target)
        finally:
            tmp.unlink(missing_ok=True)


class SealDeliveryError(Exception):
    """Sealing failed: undelivered manifest parts or an undeliverable seal.

    The evidence record stays honestly unsealed (readable as `incomplete`); a seal must never claim parts that are not in the store.
    """


@dataclass
class _PendingChunk:
    stream: str
    data: bytes
    span: ClockSpan


@dataclass
class _StreamState:
    chain: str
    next_seq: int = 0
    chunks: int = 0
    gaps: int = 0
    size: int = 0


@dataclass
class FlushResult:
    """What one flush pass accomplished; informational, never an error signal."""

    delivered_chunks: int = 0
    delivered_parts: int = 0
    pending_chunks: int = 0
    pending_parts: int = 0
    errors: list[str] = field(default_factory=list[str])


class EvidenceWriter:
    """Buffered, chaining writer for one writer identity at one evidence location.

    Two writers at one location (host and driver) are isolated by construction: manifests AND chunks are namespaced by writer, so even a shared stream name cannot collide.

    `append` and `gap` never raise backend errors (invalid names raise `ValueError` immediately: a programming error, caught at the boundary before it can poison the queue); `flush` reports; `seal` raises `SealDeliveryError` only when the record cannot be closed honestly. The public methods serialize on an internal lock, so `append` may briefly wait for an in-flight flush; the lock is what keeps chunk object keys and committed sequence numbers in step under concurrent use (a capture loop appending while a flusher task delivers).
    """

    def __init__(
        self,
        sink: EvidenceSink,
        *,
        writer: str,
        lease_id: str | None = None,
        sample_id: str | None = None,
        buffer_cap_bytes: int = DEFAULT_BUFFER_CAP_BYTES,
        max_total_bytes: int | None = None,
        part_interval_s: float = DEFAULT_PART_INTERVAL_S,
        part_max_records: int = DEFAULT_PART_MAX_RECORDS,
        put_attempts: int = 3,
        retry_wait_s: float = 0.1,
        clock: Callable[[], ClockStamp] = clock_now,
    ) -> None:
        if put_attempts < 1:
            raise ValueError("put_attempts must be >= 1")
        if part_max_records < 1:
            raise ValueError("part_max_records must be >= 1")
        if part_interval_s < 0 or max_total_bytes is not None and max_total_bytes < 1:
            raise ValueError("part_interval_s must be >= 0 and max_total_bytes >= 1")
        check_name(writer, WRITER_NAME_PATTERN, "writer")
        self._sink = sink
        self._writer = writer
        self._lock = asyncio.Lock()
        self._lease_id = lease_id
        self._sample_id = sample_id
        self._buffer_cap = buffer_cap_bytes
        self._max_total = max_total_bytes
        self._part_interval_s = part_interval_s
        self._part_max_records = part_max_records
        self._put_attempts = put_attempts
        self._retry_wait_s = retry_wait_s
        self._clock = clock
        self._pending_chunks: deque[_PendingChunk] = deque()
        self._pending_bytes = 0
        self._total_bytes = 0
        self._cap_breached = False
        self._records: list[ManifestRecord] = []
        self._records_since: float | None = None
        self._pending_parts: deque[ManifestPart] = deque()
        self._next_part = 0
        self._streams: dict[str, _StreamState] = {}
        self._sealed = False

    @property
    def writer(self) -> str:
        """This writer's identity (`host`, `driver`)."""
        return self._writer

    async def append(
        self, stream: str, data: bytes, *, span: ClockSpan | None = None
    ) -> None:
        """Buffer one chunk for delivery; never raises backend errors.

        If the buffer cap is exceeded, the oldest undelivered chunks are dropped with in-chain gap records (cause `buffer-cap`); a chunk larger than the cap is gapped immediately. An invalid stream name raises `ValueError` here, at the boundary, before it can poison the delivery queue.
        """
        check_name(stream, STREAM_NAME_PATTERN, "stream")
        async with self._lock:
            self._check_open()
            resolved = span if span is not None else self._point_span()
            if (
                self._max_total is not None
                and self._total_bytes + len(data) > self._max_total
            ):
                # the per-sample volume cap (INSPECT_RANGES_EVIDENCE_MAX_MB):
                # breach yields explicit gaps and flags the seal (a cap-hit
                # record can never claim `complete`)
                self._cap_breached = True
                self._commit_gap(
                    stream, resolved, cause="evidence-cap", dropped=len(data)
                )
                logger.warning(
                    "evidence gap (evidence-cap): writer=%s stream=%s dropped=%d total=%d",
                    self._writer,
                    stream,
                    len(data),
                    self._total_bytes,
                )
                return
            if len(data) > self._buffer_cap:
                self._commit_gap(
                    stream, resolved, cause="buffer-cap", dropped=len(data)
                )
                logger.warning(
                    "evidence gap (buffer-cap, oversized chunk): writer=%s stream=%s dropped=%d",
                    self._writer,
                    stream,
                    len(data),
                )
                return
            self._total_bytes += len(data)
            self._pending_chunks.append(
                _PendingChunk(stream=stream, data=data, span=resolved)
            )
            self._pending_bytes += len(data)
            self._enforce_cap()

    async def gap(
        self,
        stream: str,
        *,
        span: ClockSpan | None = None,
        cause: str,
        dropped: int = 0,
    ) -> None:
        """Record an explicit hole in a stream (data lost before it reached the writer)."""
        check_name(stream, STREAM_NAME_PATTERN, "stream")
        async with self._lock:
            self._check_open()
            self._commit_gap(
                stream,
                span if span is not None else self._point_span(),
                cause=cause,
                dropped=dropped,
            )

    async def flush(self) -> FlushResult:
        """Deliver buffered chunks and manifest parts; backend errors are retried, logged, and reported, never raised."""
        async with self._lock:
            self._check_open()
            return await self._flush_locked()

    async def _flush_locked(self) -> FlushResult:
        result = FlushResult()
        await self._deliver_chunks(result)
        self._cut_part(force=False)
        await self._deliver_parts(result)
        result.pending_chunks = len(self._pending_chunks)
        result.pending_parts = len(self._pending_parts)
        for error in result.errors:
            logger.warning("evidence delivery failure (buffered for retry): %s", error)
        return result

    async def seal(
        self,
        status: SealStatus = "complete",
        *,
        worst_watermark_lag_s: float | None = None,
    ) -> tuple[Seal, str]:
        """Close the record: final flush, unflushed chunks become gaps, seal delivered.

        Returns the seal and its canonical digest (the sample-store binding value). Raises `SealDeliveryError` if manifest parts or the seal itself cannot be delivered: a seal must never claim parts that are not in the store, so the record stays honestly unsealed.
        """
        async with self._lock:
            self._check_open()
            return await self._seal_locked(
                status, worst_watermark_lag_s=worst_watermark_lag_s
            )

    async def _seal_locked(
        self, status: SealStatus, *, worst_watermark_lag_s: float | None
    ) -> tuple[Seal, str]:
        result = await self._flush_locked()
        unflushed = 0
        while self._pending_chunks:
            pending = self._pending_chunks.popleft()
            self._pending_bytes -= len(pending.data)
            unflushed += len(pending.data)
            self._commit_gap(
                pending.stream,
                pending.span,
                cause="unflushed",
                dropped=len(pending.data),
            )
        self._cut_part(force=True)
        await self._deliver_parts(result)
        if self._pending_parts:
            raise SealDeliveryError(
                f"{len(self._pending_parts)} manifest part(s) undeliverable; record left unsealed"
            )
        if (unflushed > 0 or self._cap_breached) and status == "complete":
            # a cap breach left evidence-cap gaps: the seal must not claim
            # everything appended was delivered
            status = "incomplete"
        seal = Seal(
            writer=self._writer,
            status=status,
            lease_id=self._lease_id,
            sample_id=self._sample_id,
            parts=self._next_part,
            streams={
                name: StreamSummary(
                    chain=state.chain,
                    records=state.next_seq,
                    chunks=state.chunks,
                    gaps=state.gaps,
                    size=state.size,
                )
                for name, state in self._streams.items()
            },
            unflushed=unflushed,
            worst_watermark_lag_s=worst_watermark_lag_s,
            sealed_at=self._clock(),
        )
        try:
            await self._put_with_retry(seal_key(self._writer), canonical_bytes(seal))
        except FileExistsError:
            raise SealDeliveryError(
                f"seal already exists for writer {self._writer!r}"
            ) from None
        except Exception as error:
            raise SealDeliveryError(f"seal undeliverable: {error}") from error
        self._sealed = True
        digest = seal_digest(seal)
        logger.info(
            "evidence sealed: writer=%s status=%s streams=%d parts=%d unflushed=%d digest=%s",
            self._writer,
            seal.status,
            len(seal.streams),
            seal.parts,
            unflushed,
            digest,
        )
        return seal, digest

    # internal ---------------------------------------------------------------

    def _check_open(self) -> None:
        if self._sealed:
            raise RuntimeError("evidence writer is sealed")

    def _point_span(self) -> ClockSpan:
        stamp = self._clock()
        return ClockSpan(start=stamp, end=stamp)

    def _stream_state(self, stream: str) -> _StreamState:
        state = self._streams.get(stream)
        if state is None:
            state = _StreamState(chain=chain_genesis(self._writer, stream))
            self._streams[stream] = state
        return state

    def _commit_chunk(self, pending: _PendingChunk) -> ChunkRecord:
        state = self._stream_state(pending.stream)
        record = ChunkRecord(
            stream=pending.stream,
            seq=state.next_seq,
            sha256=hashlib.sha256(pending.data).hexdigest(),
            size=len(pending.data),
            span=pending.span,
            chain=_CHAIN_PLACEHOLDER,
        )
        record.chain = chain_next(state.chain, record)
        state.chain = record.chain
        state.next_seq += 1
        state.chunks += 1
        state.size += len(pending.data)
        if not self._records:
            self._records_since = time.monotonic()
        self._records.append(record)
        return record

    def _commit_gap(
        self, stream: str, span: ClockSpan, *, cause: str, dropped: int
    ) -> None:
        state = self._stream_state(stream)
        record = GapRecord(
            stream=stream,
            seq=state.next_seq,
            span=span,
            cause=cause,
            dropped=dropped,
            chain=_CHAIN_PLACEHOLDER,
        )
        record.chain = chain_next(state.chain, record)
        state.chain = record.chain
        state.next_seq += 1
        state.gaps += 1
        if not self._records:
            self._records_since = time.monotonic()
        self._records.append(record)

    def _enforce_cap(self) -> None:
        while self._pending_bytes > self._buffer_cap and self._pending_chunks:
            oldest = self._pending_chunks.popleft()
            self._pending_bytes -= len(oldest.data)
            self._commit_gap(
                oldest.stream, oldest.span, cause="buffer-cap", dropped=len(oldest.data)
            )
            logger.warning(
                "evidence gap (buffer-cap): writer=%s stream=%s dropped=%d",
                self._writer,
                oldest.stream,
                len(oldest.data),
            )

    def _cut_part(self, *, force: bool) -> None:
        """Batch committed records into a manifest part when due.

        Chunks are already delivered by the time their records sit here; batching delays only the manifest commitment (`DEFAULT_PART_INTERVAL_S`). `force` (the seal path) always cuts.
        """
        if not self._records:
            return
        if not force:
            due_by_count = len(self._records) >= self._part_max_records
            age = (
                0.0
                if self._records_since is None
                else time.monotonic() - self._records_since
            )
            due_by_age = self._part_interval_s == 0 or age >= self._part_interval_s
            if not due_by_count and not due_by_age:
                return
        part = ManifestPart(
            writer=self._writer, part=self._next_part, records=self._records
        )
        self._next_part += 1
        self._records = []
        self._records_since = None
        self._pending_parts.append(part)

    async def _deliver_chunks(self, result: FlushResult) -> None:
        # strict FIFO: stopping at the first failure preserves per-stream
        # sequence order between delivery and commitment
        while self._pending_chunks:
            pending = self._pending_chunks[0]
            # the lock guarantees nothing else commits to this stream between
            # the key computation here and _commit_chunk below
            next_seq = self._stream_state(pending.stream).next_seq
            key = chunk_key(self._writer, pending.stream, next_seq)
            try:
                await self._put_with_retry(key, pending.data)
            except FileExistsError:
                # a foreign object at our key: write-once forbids replacing it,
                # so the chunk is lost explicitly rather than retried forever
                self._pending_chunks.popleft()
                self._pending_bytes -= len(pending.data)
                self._commit_gap(
                    pending.stream,
                    pending.span,
                    cause="write-once-conflict",
                    dropped=len(pending.data),
                )
                logger.warning(
                    "evidence gap (write-once-conflict): writer=%s key=%s",
                    self._writer,
                    key,
                )
                continue
            except Exception as error:
                result.errors.append(f"chunk {key}: {error}")
                return
            self._pending_chunks.popleft()
            self._pending_bytes -= len(pending.data)
            self._commit_chunk(pending)
            result.delivered_chunks += 1
            logger.debug(
                "evidence chunk delivered: writer=%s key=%s bytes=%d",
                self._writer,
                key,
                len(pending.data),
            )

    async def _deliver_parts(self, result: FlushResult) -> None:
        while self._pending_parts:
            part = self._pending_parts[0]
            key = part_key(self._writer, part.part)
            try:
                await self._put_with_retry(key, canonical_bytes(part))
            except Exception as error:
                result.errors.append(f"manifest part {key}: {error}")
                return
            self._pending_parts.popleft()
            result.delivered_parts += 1
            logger.debug(
                "evidence manifest part delivered: writer=%s key=%s records=%d",
                self._writer,
                key,
                len(part.records),
            )

    async def _put_with_retry(self, key: str, data: bytes) -> None:
        last: Exception | None = None
        for attempt in range(self._put_attempts):
            try:
                await self._sink.put(key, data)
                return
            except FileExistsError:
                if last is None:
                    # first attempt: a foreign object genuinely sits at our
                    # key; write-once forbids replacing it, surface it
                    raise
                # a prior attempt failed transiently but may have landed
                # (routine for S3: bytes accepted, response lost). Assume the
                # object is ours: if it is in fact foreign, verify reports a
                # loud digest break instead of us silently gapping delivered
                # data. Read-back disambiguation is unavailable by design
                # (put-only credentials).
                logger.warning(
                    "evidence put ambiguous after transient failure, assuming delivered: key=%s",
                    key,
                )
                return
            except Exception as error:
                last = error
                if attempt + 1 < self._put_attempts:
                    await asyncio.sleep(self._retry_wait_s * (attempt + 1))
        assert last is not None
        raise last

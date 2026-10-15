"""The S3 evidence backend: write-once objects via conditional puts.

`S3Sink` implements the put-only `EvidenceSink` protocol over one object per chunk and per manifest part under the per-sample prefix (the location derivation already yields `s3://` locations when the eval log lives in S3). Write-once is enforced at the store, not merely promised by the client: every put carries `IfNoneMatch="*"`, so an existing key answers 412 and surfaces as the protocol's `FileExistsError`. The writer's ambiguous-put posture composes unchanged: a put whose response was lost retries, meets 412, and is treated as our own landed write, with a genuinely foreign object surfacing at verify as a loud digest break.

Retry layering, recorded deliberately: the SDK runs botocore's `standard` retry mode (bounded attempts, exponential backoff with jitter, throttling-aware), and `EvidenceWriter` above buffers failed puts and retries across flushes. A third tenacity layer inside `put` would hold the writer's lock through its sleeps and starve capture appends, so the house posture (bounded attempts, jittered backoff, loud telemetry) is met by the two layers that already exist, not duplicated here. Timeouts are bounded (connect and read) for the same reason: the writer's buffer, not a hung socket, is where backpressure belongs.

Driving model: the sink protocol is async; boto3 is sync and its clients are thread-safe, so calls hop through `asyncio.to_thread`. boto3 is already a project dependency (the devbox CLI); aiobotocore would add a second SDK surface and version coupling for no measurable win at evidence volumes (chunks are rotation-bounded megabytes, where a thread hop is noise). Multipart upload is deliberately absent: a single `PutObject` carries up to 5 GB, chunk sizes are bounded by capture rotation and the writer's buffer cap (an oversized append is gapped, never delivered), and conditional multipart completion has weaker write-once semantics.

Credentials follow standard AWS resolution (env, profile, instance role); nothing here reads, logs, or stores them. The deny-overwrite deployment guidance (a bucket policy requiring `s3:if-none-match` on every put) lives with the slice battery's README until the slice-6 docs page.
"""

# boto3 is untyped-by-nature (same rationale as the _devbox pyright
# relaxation in pyproject.toml, applied per-file here to keep the rest of
# _evidence under full strict checking)
# pyright: reportMissingTypeStubs=false, reportUnknownMemberType=false
# pyright: reportUnknownVariableType=false, reportUnknownArgumentType=false

from __future__ import annotations

import asyncio
import logging
import threading
from pathlib import Path
from typing import Any

from .reader import EvidenceStore, LocalDirStore
from .sink import EvidenceSink, LocalDirSink

logger = logging.getLogger(__name__)

_CONNECT_TIMEOUT_S = 5.0
_READ_TIMEOUT_S = 20.0
_SDK_MAX_ATTEMPTS = 3


def parse_s3_location(location: str) -> tuple[str, str]:
    """Split `s3://bucket/prefix` into `(bucket, prefix)`.

    The prefix comes back without leading or trailing slashes (possibly empty); object keys append as `<prefix>/<key>`. Raises `ValueError` for anything that is not an `s3://` URL with a bucket.
    """
    if not location.startswith("s3://"):
        raise ValueError(f"not an s3:// location: {location!r}")
    rest = location[len("s3://") :]
    bucket, _, prefix = rest.partition("/")
    if not bucket:
        raise ValueError(f"s3 location has no bucket: {location!r}")
    return bucket, prefix.strip("/")


def _new_client() -> Any:
    import boto3
    from botocore.config import Config

    return boto3.client(
        "s3",
        config=Config(
            connect_timeout=_CONNECT_TIMEOUT_S,
            read_timeout=_READ_TIMEOUT_S,
            retries={"mode": "standard", "max_attempts": _SDK_MAX_ATTEMPTS},
        ),
    )


def _error_code(error: Exception) -> str:
    """The S3 error code of a botocore `ClientError`, else an empty string."""
    from botocore.exceptions import ClientError

    if not isinstance(error, ClientError):
        return ""
    code = error.response.get("Error", {}).get("Code", "")
    return str(code)


class _S3Base:
    """Shared bucket/prefix/client plumbing for the sink and the store."""

    def __init__(self, location: str, *, client: Any | None = None) -> None:
        self.bucket, self.prefix = parse_s3_location(location)
        self._client_instance: Any | None = client
        self._client_lock = threading.Lock()

    def _s3(self) -> Any:
        # lazy so constructing a sink or store never touches credential
        # resolution; shared because boto3 clients are thread-safe (sessions
        # are not, so none is kept)
        with self._client_lock:
            if self._client_instance is None:
                self._client_instance = _new_client()
            return self._client_instance

    def _object_key(self, key: str) -> str:
        return f"{self.prefix}/{key}" if self.prefix else key


class S3Sink(_S3Base):
    """Write-once puts under an `s3://` prefix (put-only; implements `EvidenceSink`)."""

    async def put(self, key: str, data: bytes) -> None:
        """Store `data` at `key` exactly once; `FileExistsError` when the key exists.

        412 (`PreconditionFailed`) from the conditional put is the store refusing a rewrite and maps to `FileExistsError` per the sink protocol. 409 (`ConditionalRequestConflict`: a concurrent conditional put on the same key in flight) raises as-is: the writer buffers and retries, and the retry resolves to success or 412. Every other failure also raises as-is into the writer's buffered-retry path; nothing is retried here beyond the SDK's own standard mode.
        """
        await asyncio.to_thread(self._put_sync, key, data)

    def _put_sync(self, key: str, data: bytes) -> None:
        object_key = self._object_key(key)
        try:
            self._s3().put_object(
                Bucket=self.bucket,
                Key=object_key,
                Body=data,
                IfNoneMatch="*",
            )
        except Exception as error:
            if _error_code(error) == "PreconditionFailed":
                raise FileExistsError(object_key) from error
            raise


class S3Store(_S3Base):
    """Read-side counterpart of `S3Sink` (implements `EvidenceStore`); used by verify, never by any writer."""

    async def get(self, key: str) -> bytes:
        """Return the object at `key`; `FileNotFoundError` when absent."""
        return await asyncio.to_thread(self._get_sync, key)

    def _get_sync(self, key: str) -> bytes:
        try:
            response = self._s3().get_object(
                Bucket=self.bucket, Key=self._object_key(key)
            )
        except Exception as error:
            if _error_code(error) in ("NoSuchKey", "404", "NotFound"):
                raise FileNotFoundError(key) from error
            raise
        body: bytes = response["Body"].read()
        return body

    async def list(self, prefix: str) -> list[str]:
        """All keys under `prefix`, relative to the location, sorted by key."""
        return await asyncio.to_thread(self._list_sync, prefix)

    def _list_sync(self, prefix: str) -> list[str]:
        strip = len(self.prefix) + 1 if self.prefix else 0
        keys: list[str] = []
        paginator = self._s3().get_paginator("list_objects_v2")
        for page in paginator.paginate(
            Bucket=self.bucket, Prefix=self._object_key(prefix)
        ):
            for item in page.get("Contents", []):
                keys.append(str(item["Key"])[strip:])
        # sorted by key, never by backend page order (the EvidenceStore contract)
        return sorted(keys)


def sink_for_location(location: str) -> EvidenceSink:
    """The write-side backend for an evidence location: `S3Sink` for `s3://`, `LocalDirSink` otherwise."""
    if location.startswith("s3://"):
        return S3Sink(location)
    if "://" in location:
        raise ValueError(f"unsupported evidence location scheme: {location!r}")
    return LocalDirSink(Path(location))


def store_for_location(location: str) -> EvidenceStore:
    """The read-side backend for an evidence location: `S3Store` for `s3://`, `LocalDirStore` otherwise."""
    if location.startswith("s3://"):
        return S3Store(location)
    if "://" in location:
        raise ValueError(f"unsupported evidence location scheme: {location!r}")
    return LocalDirStore(Path(location))

"""The S3 evidence backend: write-once objects via conditional puts.

`S3Sink` implements the put-only `EvidenceSink` protocol over one object per chunk and per manifest part under the per-sample prefix (the location derivation already yields `s3://` locations when the eval log lives in S3). Write-once is enforced at the store, not merely promised by the client: every put carries `IfNoneMatch="*"`, so an existing key answers 412 and surfaces as the protocol's `FileExistsError`. The writer's ambiguous-put posture composes unchanged: a put whose response was lost retries, meets 412, and is treated as our own landed write, with a genuinely foreign object surfacing at verify as a loud digest break.

Retry layering, recorded deliberately: `EvidenceWriter` is the ONLY retry layer. SDK-internal retries are disabled (`max_attempts: 1`), because a retry inside one client call collapses the distinction the writer's ambiguous-put posture depends on: a put that landed but lost its response, auto-retried by botocore, would surface as a FIRST-attempt 412 and be misread as a foreign object (falsely gapping delivered data, or refusing a seal that landed). With the SDK transparent, a transient failure reaches the writer as a transient, the writer's own same-key retry meets 412, and the assume-landed branch fires exactly when it should. A tenacity layer inside `put` is rejected for the same reason it would be redundant: it would hold the writer's lock through its sleeps and starve capture appends. Timeouts are bounded (connect and read) because the writer's buffer, not a hung socket, is where backpressure belongs; throttling (503) likewise buffers to the next flush pass.

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


def new_s3_client() -> Any:
    """A fresh S3 client under this module's config: bounded timeouts, retry-transparent (one total attempt). The doctor's sink probe shares it so probe behavior matches the writer's."""
    import boto3
    from botocore.config import Config

    return boto3.client(
        "s3",
        config=Config(
            connect_timeout=_CONNECT_TIMEOUT_S,
            read_timeout=_READ_TIMEOUT_S,
            # one TOTAL attempt: the SDK must be transparent so the writer's
            # same-key retry (the only retry layer) can tell a first-attempt
            # 412 (foreign object) from 412-after-OUR-transient (we landed).
            # total_max_attempts is the unambiguous key: botocore normalizes
            # max_attempts=1 to total_max_attempts=2, i.e. one hidden retry
            retries={"mode": "standard", "total_max_attempts": 1},
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
                self._client_instance = new_s3_client()
            return self._client_instance

    def _object_key(self, key: str) -> str:
        return f"{self.prefix}/{key}" if self.prefix else key


class S3Sink(_S3Base):
    """Write-once puts under an `s3://` prefix (put-only; implements `EvidenceSink`)."""

    async def put(self, key: str, data: bytes) -> None:
        """Store `data` at `key` exactly once; `FileExistsError` when the key is foreign.

        412 (`PreconditionFailed`) is the store refusing a rewrite and maps to `FileExistsError` per the sink protocol. 409 (`ConditionalRequestConflict`: another conditional put on the same key is in flight) maps to `FileExistsError` TOO: the writer is single-flight per key, so a concurrent put on our key is by definition foreign activity, and the honest outcome is the writer's explicit `write-once-conflict` gap. Letting a 409 raise as a transient instead would feed the writer's assume-landed branch on its next attempt (409 then 412 reads as "ours landed"), committing OUR digest over the FOREIGN winner's bytes and turning an honest conflict into a false tamper break at verify. The conservative cost: if the foreign put later fails and the key ends up absent, we gapped a deliverable chunk, explicitly and loudly. Every other failure raises as-is into the writer's buffered-retry path; the SDK performs no retries of its own.
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
            if _error_code(error) in (
                "PreconditionFailed",
                "ConditionalRequestConflict",
            ):
                raise FileExistsError(object_key) from error
            raise


class S3Store(_S3Base):
    """Read-side counterpart of `S3Sink` (implements `EvidenceStore`); used by verify, never by any writer."""

    _denied_warned: bool = False

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
            if _error_code(error) == "AccessDenied":
                # without s3:ListBucket, S3 reports a MISSING key as 403, so
                # a restricted verifier credential must read this as absent
                # (the alternative is a traceback instead of the first-break
                # report). The ambiguity is logged loudly: if GetObject
                # itself is denied, every chunk will read as missing and
                # verify will fail on the first referenced chunk.
                if not self._denied_warned:
                    self._denied_warned = True
                    logger.warning(
                        "s3 answered AccessDenied for a GET under %s: treated "
                        "as a missing key (how S3 reports absence without "
                        "s3:ListBucket); if GetObject is denied outright, "
                        "every chunk will read as missing",
                        self.bucket,
                    )
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
        # terminated with "/" so the raw S3 Prefix keeps LocalDirStore's
        # directory semantics: list("manifests/host") must not also match a
        # writer named "host2"
        full = self._object_key(prefix).rstrip("/") + "/"
        paginator = self._s3().get_paginator("list_objects_v2")
        for page in paginator.paginate(Bucket=self.bucket, Prefix=full):
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


def valid_sink_location(location: str) -> bool:
    """Whether `sink_for_location` would accept `location`, without constructing a backend.

    Doctor's lockstep predicate: the sink and off-instance rows must classify a location exactly as the runtime will, or doctor blesses configurations the runtime disables (or fails healthy ones).
    """
    if location.startswith("s3://"):
        try:
            parse_s3_location(location)
        except ValueError:
            return False
        return True
    return "://" not in location


def store_for_location(location: str) -> EvidenceStore:
    """The read-side backend for an evidence location: `S3Store` for `s3://`, `LocalDirStore` otherwise."""
    if location.startswith("s3://"):
        return S3Store(location)
    if "://" in location:
        raise ValueError(f"unsupported evidence location scheme: {location!r}")
    return LocalDirStore(Path(location))

"""Where a sample's evidence lives: beside the eval log, derived, never configured per sample.

The per-sample location is `<evallogstem>.evidence/<sample_id>_<epoch>_<attempt>/` (evidence-v1.md): local beside a local log in development, in the log's S3 bucket in production, so durability inherits from the log location and anything that finds the log finds the evidence. Each attempt gets a fresh prefix (write-once discipline across retries). `INSPECT_RANGES_EVIDENCE_SINK` exists only as an override for deployments whose evidence needs a different bucket or retention than their logs.

The identity (log location, sample id, epoch, attempt) comes from `inspect_ai`'s active-sample context. That is a private API (`inspect_ai.log._samples.sample_active`), adopted on user direction and isolated in `active_evidence_identity` with a documented fallback: when the context is unavailable the caller derives the location from the log directory and run id instead (`fallback_evidence_location`). A pin test asserts the private surface's shape so an `inspect_ai` upgrade fails loudly in CI rather than silently degrading every sample to the fallback.
"""

import hashlib
import logging
import os
import re

from pydantic import BaseModel, ConfigDict

logger = logging.getLogger(__name__)

EVIDENCE_SINK_OVERRIDE_VAR = "INSPECT_RANGES_EVIDENCE_SINK"
"""Override base for evidence locations; unset means derive from the log location."""


class EvidenceIdentity(BaseModel):
    """The identifiers that name a sample's evidence prefix."""

    model_config = ConfigDict(extra="forbid")

    log_location: str
    sample_id: str
    epoch: int
    attempt: int
    """1-based across every re-run of the sample: task-level reruns seed prior errors into the active sample's retry list, so `len(error_retries) + 1` counts both."""


def active_evidence_identity() -> EvidenceIdentity | None:
    """The running sample's evidence identity, or `None` outside a sample context.

    This is the single place the private `inspect_ai` surface is touched: `sample_active()` returns the `ActiveSample` carrying `log_location`, the `sample` (its id), `epoch`, and `error_retries`. The sandbox context is entered inside the active-sample context (verified against the installed `inspect_ai`), so this is available from `sample_init`. Any import or shape failure returns `None` and the caller falls back to `fallback_evidence_location`.
    """
    try:
        from inspect_ai.log._samples import sample_active
    except ImportError:
        return None
    try:
        active = sample_active()
        if active is None:
            return None
        sample_id = active.sample.id
        if sample_id is None:
            return None
        retries = active.error_retries or []
        return EvidenceIdentity(
            log_location=active.log_location,
            sample_id=str(sample_id),
            epoch=int(active.epoch),
            attempt=len(retries) + 1,
        )
    except (AttributeError, TypeError, ValueError) as error:
        # any shape drift in the private surface degrades to the fallback
        # (pydantic's ValidationError is a ValueError); the pin test is what
        # makes such drift loud in CI
        logger.debug("active-sample identity unavailable, using fallback: %s", error)
        return None


def derive_evidence_location(
    log_location: str, *, sample_id: str, epoch: int, attempt: int
) -> str:
    """The per-sample evidence prefix beside the eval log.

    Strips the log file's final suffix (`.eval`, `.json`) and appends `.evidence/<sample_id>_<epoch>_<attempt>`. Works on paths and URLs alike (string surgery on the final `/` segment, never `Path`, so `s3://` locations survive). When `INSPECT_RANGES_EVIDENCE_SINK` is set, the same `<stem>.evidence/<triple>` layout is rooted under the override instead. Filesystem results are absolutized: inspect may report a relative log location (relative to its own working directory), and a relative path in the binding would only resolve from that directory, which a later verifier does not have.
    """
    base, _, name = log_location.rstrip("/").rpartition("/")
    stem = name.rsplit(".", 1)[0] if "." in name else name
    triple = f"{_sanitize(sample_id)}_{epoch}_{attempt}"
    override = os.environ.get(EVIDENCE_SINK_OVERRIDE_VAR)
    if override:
        return _absolutize(f"{override.rstrip('/')}/{stem}.evidence/{triple}")
    prefix = f"{base}/" if base else ""
    return _absolutize(f"{prefix}{stem}.evidence/{triple}")


def _absolutize(location: str) -> str:
    """Anchor a filesystem location to the current working directory; URL schemes pass through."""
    if "://" in location or location.startswith("/"):
        return location
    return os.path.abspath(location)


def evidence_location_for(identity: EvidenceIdentity) -> str:
    """`derive_evidence_location` over an `EvidenceIdentity`."""
    return derive_evidence_location(
        identity.log_location,
        sample_id=identity.sample_id,
        epoch=identity.epoch,
        attempt=identity.attempt,
    )


def fallback_evidence_location(
    log_dir: str, run_id: str, *, sample_id: str, epoch: int, attempt: int
) -> str:
    """The documented fallback when no active-sample context exists.

    Roots the same layout at `<log_dir>/<run_id>.evidence/<triple>`: discoverable from the log directory even though the exact log stem was not available.
    """
    return derive_evidence_location(
        f"{log_dir.rstrip('/')}/{run_id}.eval",
        sample_id=sample_id,
        epoch=epoch,
        attempt=attempt,
    )


def _sanitize(value: str) -> str:
    """Key-safe form of a sample id (filesystem and S3 alike).

    When sanitization alters the id, a short digest of the raw value is appended so distinct ids (`a/b` vs `a?b`) cannot collapse onto one evidence prefix: a collision would turn the second sample's whole record into write-once conflicts.
    """
    cleaned = re.sub(r"[^A-Za-z0-9._-]", "-", value)
    if cleaned == value and cleaned:
        return cleaned
    tag = hashlib.sha256(value.encode()).hexdigest()[:8]
    return f"{cleaned or 'sample'}-{tag}"

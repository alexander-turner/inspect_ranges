"""The terminal tool's capture leg: per-session recording, evidence mirroring, cast assembly, and the store cast.

Each open session gets one streaming `exec_remote` tailing its pipe-pane sink; every output event is timestamped host-side on arrival, appended to the session's chunk list (for playback assembly), and mirrored to the `terminal/<session>` evidence stream when the sample has an evidence session. At session close, and for still-open sessions at sample finalize (the provider's `finalize_terminal_captures`, plus the evidence producer where one exists), the chunks and per-call markers assemble into an asciicast v2 document, written into the sample store under `asciinema:<name>` (clipped to `INSPECT_RANGES_CAST_STORE_CAP_MB`; the viewer-side binding) and, when a local evidence location exists, as a file beside the sample's evidence.

Capture is observability, never load-bearing: it requires a range sandbox (evidence optional), degrades to off everywhere else, and no failure in this module ever reaches the agent. The sample handle is used inside this module only and never surfaces to the agent (`terminal-tool-v1.md`, recorded exceptions).
"""

import logging
import time
import weakref
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

import anyio
from inspect_ai.util import background, sandbox
from inspect_ai.util._sandbox.exec_remote import ExecRemoteProcess, ExecStdout

from .cast import SessionOpener, assemble_cast, cast_store_cap_bytes, clip_cast
from .session import SessionState, sink_path, wait_channel_prefix

if TYPE_CHECKING:
    from .._provider.evidence import EvidenceSession

logger = logging.getLogger("inspect_ranges.terminal")

__all__ = [
    "discard_sample_captures",
    "finalize_terminal_captures",
    "start_capture",
    "stop_all_captures",
    "stop_capture",
]


@dataclass
class _Capture:
    """One session's live recorder; `evidence` is `None` when the sample runs without an evidence session (recording and the store cast still happen)."""

    session: str
    state: SessionState
    evidence: "EvidenceSession | None"
    opener: SessionOpener | None = None
    process: ExecRemoteProcess | None = None
    stopped: bool = False
    drained: anyio.Event = field(default_factory=anyio.Event)


@dataclass
class _SampleCaptures:
    """All of one sample's recorders, with the finalize producer registered once (evidence path) and the sample store held weakly for cast writes."""

    evidence: "EvidenceSession | None"
    on_finalize: "Callable[[], None]"
    store_ref: "weakref.ref[Any] | None" = None
    captures: dict[str, _Capture] = field(default_factory=dict[str, _Capture])


_SAMPLES: dict[int, _SampleCaptures] = {}

_PROJECTS: dict[str, int] = {}
"""Project name to the sample's capture registry id, so the provider's teardown can finalize by project (the deferred-teardown path runs outside the sample's store context)."""


def _capture_target() -> "tuple[bool, EvidenceSession | None, str | None]":
    """Whether this sample records at all (any range sandbox does), plus its evidence session (optional: mirroring and cast files need it, recording does not) and project name."""
    try:
        from .._provider.provider import sample_handle_for

        handle = sample_handle_for(sandbox())
    except Exception:  # noqa: BLE001  (not a range sandbox: capture off)
        return False, None, None
    evidence: EvidenceSession | None = getattr(handle, "evidence", None)
    project: str | None = getattr(handle, "project", None)
    return True, evidence, project


def _current_store() -> object | None:
    """The sample's store object, held by weakref for the cast's store write (an interrupted sample's deferred teardown finds it dead and skips the write, by decision)."""
    try:
        from inspect_ai.util import store as inspect_store

        return inspect_store()
    except Exception:  # noqa: BLE001
        return None


async def start_capture(
    store_id: int,
    session: str,
    state: SessionState,
    on_finalize: "Callable[[], None]",
    opener: SessionOpener | None = None,
) -> None:
    """Start recording an open session; quietly a no-op outside a range sandbox.

    `on_finalize` runs once at sample finalize after every recorder stops (the tool passes its state cleanup). `opener` is the agent context that opened the session, captured by the tool at open time; it rides the cast header so playback can group sessions by agent.
    """
    recording, evidence, project = _capture_target()
    if not recording:
        return
    try:
        sample = _SAMPLES.get(store_id)
        if sample is None:
            sample_store = _current_store()
            sample = _SampleCaptures(
                evidence=evidence,
                on_finalize=on_finalize,
                store_ref=weakref.ref(sample_store)
                if sample_store is not None
                else None,
            )
            _SAMPLES[store_id] = sample
            if project is not None:
                _PROJECTS[project] = store_id

            async def finalize() -> None:
                await stop_all_captures(store_id)

            if evidence is not None:
                evidence.register_producer(finalize)
        capture = _Capture(
            session=session, state=state, evidence=sample.evidence, opener=opener
        )
        sample.captures[session] = capture
        process = await sandbox().exec_remote(
            [
                "sh",
                "-c",
                f"touch {sink_path(session)} && tail -c +1 -F {sink_path(session)}",
            ],
            stream=True,
        )
        capture.process = process
        background(_consume, capture, process)
    except Exception as error:  # noqa: BLE001  (observability, never load-bearing)
        logger.info("terminal capture for %r is off: %s", session, error)


async def _consume(capture: _Capture, process: ExecRemoteProcess) -> None:
    """Drain the recorder's output events: timestamp, retain for the cast, mirror to evidence."""
    stream = f"terminal/{capture.session}"
    try:
        async for event in process:
            if isinstance(event, ExecStdout) and event.data:
                data = event.data.encode(errors="replace")
                capture.state.chunks.append((time.monotonic(), data))
                if capture.evidence is not None:
                    await capture.evidence.append_driver(stream, data)
    except Exception as error:  # noqa: BLE001
        logger.info("terminal capture stream for %r ended: %s", capture.session, error)
    finally:
        capture.drained.set()


async def stop_capture(store_id: int, session: str) -> None:
    """Stop one session's recorder and write its cast; idempotent.

    `kill` enqueues output buffered since the recorder's last poll, so the cast waits (bounded) for the consume task to drain those final events before assembly.
    """
    sample = _SAMPLES.get(store_id)
    if sample is None:
        return
    capture = sample.captures.pop(session, None)
    if capture is None or capture.stopped:
        return
    capture.stopped = True
    if capture.process is not None:
        try:
            await capture.process.kill()
        except Exception:  # noqa: BLE001
            pass
        with anyio.move_on_after(10):
            await capture.drained.wait()
    _write_cast(sample, capture)


def discard_sample_captures(store_id: int) -> None:
    """Drop a sample's capture registry entry without stopping anything (GC-time cleanup when the sample's store was collected before finalize ran, so the id can be reused safely)."""
    _SAMPLES.pop(store_id, None)
    for project in [p for p, sid in _PROJECTS.items() if sid == store_id]:
        _PROJECTS.pop(project, None)


async def finalize_terminal_captures(project: str) -> None:
    """Stop the project's recorders and write their casts; the provider's teardown hook, idempotent, never raises.

    Keyed by project rather than the ambient store because an interrupted sample's deferred teardown runs at task cleanup, outside the sample's store context; there the casts still reach evidence (when present) while the store write is skipped (the weakref resolves dead), by decision.
    """
    store_id = _PROJECTS.get(project)
    if store_id is not None:
        await stop_all_captures(store_id)


async def stop_all_captures(store_id: int) -> None:
    """The finalize path: stop every live recorder, write their casts, run the tool cleanup; never raises."""
    sample = _SAMPLES.get(store_id)
    if sample is None:
        return
    for session in list(sample.captures):
        try:
            await stop_capture(store_id, session)
        except Exception as error:  # noqa: BLE001
            logger.info("terminal capture finalize for %r: %s", session, error)
    _SAMPLES.pop(store_id, None)
    for project in [p for p, sid in _PROJECTS.items() if sid == store_id]:
        _PROJECTS.pop(project, None)
    try:
        sample.on_finalize()
    except Exception:  # noqa: BLE001
        pass


def _write_cast(sample: _SampleCaptures, capture: _Capture) -> None:
    """Assemble the asciicast (with the blocking signal's echo scrubbed, as tool results are) and deliver it: into the sample store always (capped), and beside the sample's evidence when a local evidence location exists. The evidence mirror (`terminal/<session>`) stays raw.

    A session name can record more than one life (close then reopen, or reopen after dying), each with its own cast: later lives get a numbered suffix rather than overwriting the earlier record, in the store and on disk alike.
    """
    try:
        cast = assemble_cast(
            chunks=capture.state.chunks,
            markers=capture.state.markers,
            start_monotonic=capture.state.opened_monotonic,
            start_wall=capture.state.opened_wall,
            title=f"terminal session {capture.session}",
            session=capture.session,
            opener=capture.opener,
            channel_prefix=wait_channel_prefix(capture.session, capture.state.token),
        )
    except Exception as error:  # noqa: BLE001
        logger.info("terminal cast for %r not assembled: %s", capture.session, error)
        return
    _store_cast(sample, capture.session, cast)
    if capture.evidence is None:
        return
    location = capture.evidence.location
    if "://" in location:
        logger.info(
            "terminal cast for %r not written: remote evidence location",
            capture.session,
        )
        return
    try:
        directory = Path(location)
        directory.mkdir(parents=True, exist_ok=True)
        path = directory / f"terminal-{capture.session}.cast"
        serial = 2
        while path.exists():
            path = directory / f"terminal-{capture.session}-{serial}.cast"
            serial += 1
        path.write_text(cast)
    except Exception as error:  # noqa: BLE001
        logger.info("terminal cast for %r not written: %s", capture.session, error)


def _store_cast(sample: _SampleCaptures, session: str, cast: str) -> None:
    """Write the cast into the sample store under the `asciinema:<name>` convention, clipped to the store cap; never raises.

    The key convention is what the viewer-side asciicast rendering binds to; until that lands the keys are inert store entries. The store write targets the sample's own store object (weakly held), so an interrupted sample's deferred teardown skips it rather than writing into another context's store.
    """
    try:
        sample_store = sample.store_ref() if sample.store_ref is not None else None
        if sample_store is None:
            return
        clipped = clip_cast(cast, cast_store_cap_bytes())
        base = f"asciinema:terminal-{session}"
        key = base
        serial = 2
        while sample_store.get(key) is not None:
            key = f"{base}-{serial}"
            serial += 1
        sample_store.set(key, clipped)
    except Exception as error:  # noqa: BLE001
        logger.info("terminal cast for %r not stored: %s", session, error)


def captures_for_tests(store_id: int) -> dict[str, Any]:
    """Test visibility into the live registry (sessions currently recording)."""
    sample = _SAMPLES.get(store_id)
    return dict(sample.captures) if sample is not None else {}

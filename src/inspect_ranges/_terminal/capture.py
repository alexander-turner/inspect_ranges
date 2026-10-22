"""The terminal tool's capture leg: per-session recording, evidence mirroring, and cast assembly.

Each open session gets one streaming `exec_remote` tailing its pipe-pane sink; every output event is timestamped host-side on arrival, appended to the session's chunk list (for playback assembly), and mirrored to the `terminal/<session>` evidence stream. At session close, and for still-open sessions at sample finalize (a producer registered on the evidence session), the chunks and per-call markers assemble into an asciicast v2 file beside the sample's evidence.

Capture is observability, never load-bearing: it requires a range sandbox with an evidence session, degrades to off everywhere else, and no failure in this module ever reaches the agent. The sample handle is used inside this module only and never surfaces to the agent (`terminal-tool-v1.md`, recorded exceptions).
"""

import logging
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

import anyio
from inspect_ai.util import background, sandbox
from inspect_ai.util._sandbox.exec_remote import ExecRemoteProcess, ExecStdout

from .cast import assemble_cast
from .session import SessionState, sink_path

if TYPE_CHECKING:
    from .._provider.evidence import EvidenceSession

logger = logging.getLogger("inspect_ranges.terminal")

__all__ = [
    "discard_sample_captures",
    "start_capture",
    "stop_all_captures",
    "stop_capture",
]


@dataclass
class _Capture:
    """One session's live recorder."""

    session: str
    state: SessionState
    evidence: "EvidenceSession"
    process: ExecRemoteProcess | None = None
    stopped: bool = False
    drained: anyio.Event = field(default_factory=anyio.Event)


@dataclass
class _SampleCaptures:
    """All of one sample's recorders, with the finalize producer registered once."""

    evidence: "EvidenceSession"
    on_finalize: "Callable[[], None]"
    captures: dict[str, _Capture] = field(default_factory=dict[str, _Capture])


_SAMPLES: dict[int, _SampleCaptures] = {}


def _evidence_session() -> "EvidenceSession | None":
    """The sample's evidence session, or `None` outside a range sandbox."""
    try:
        from .._provider.provider import sample_handle_for

        handle = sample_handle_for(sandbox())
    except Exception:  # noqa: BLE001  (not a range sandbox: capture off)
        return None
    evidence: EvidenceSession | None = getattr(handle, "evidence", None)
    return evidence


async def start_capture(
    store_id: int,
    session: str,
    state: SessionState,
    on_finalize: "Callable[[], None]",
) -> None:
    """Start recording an open session; quietly a no-op outside a range sandbox.

    `on_finalize` runs once at sample finalize after every recorder stops (the tool passes its state cleanup).
    """
    evidence = _evidence_session()
    if evidence is None:
        return
    try:
        sample = _SAMPLES.get(store_id)
        if sample is None:
            sample = _SampleCaptures(evidence=evidence, on_finalize=on_finalize)
            _SAMPLES[store_id] = sample

            async def finalize() -> None:
                await stop_all_captures(store_id)

            evidence.register_producer(finalize)
        capture = _Capture(session=session, state=state, evidence=evidence)
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
    _write_cast(capture)


def discard_sample_captures(store_id: int) -> None:
    """Drop a sample's capture registry entry without stopping anything (GC-time cleanup when the sample's store was collected before finalize ran, so the id can be reused safely)."""
    _SAMPLES.pop(store_id, None)


async def stop_all_captures(store_id: int) -> None:
    """The finalize producer: stop every live recorder, write their casts, run the tool cleanup; never raises."""
    sample = _SAMPLES.get(store_id)
    if sample is None:
        return
    for session in list(sample.captures):
        try:
            await stop_capture(store_id, session)
        except Exception as error:  # noqa: BLE001
            logger.info("terminal capture finalize for %r: %s", session, error)
    _SAMPLES.pop(store_id, None)
    try:
        sample.on_finalize()
    except Exception:  # noqa: BLE001
        pass


def _write_cast(capture: _Capture) -> None:
    """Assemble the asciicast beside the sample's evidence; local locations only.

    A session name can record more than one life (close then reopen, or reopen after dying), each with its own cast: later lives get a numbered suffix rather than overwriting the earlier record.
    """
    location = capture.evidence.location
    if "://" in location:
        logger.info(
            "terminal cast for %r not written: remote evidence location",
            capture.session,
        )
        return
    try:
        cast = assemble_cast(
            chunks=capture.state.chunks,
            markers=capture.state.markers,
            start_monotonic=capture.state.opened_monotonic,
            start_wall=capture.state.opened_wall,
            title=f"terminal session {capture.session}",
        )
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


def captures_for_tests(store_id: int) -> dict[str, Any]:
    """Test visibility into the live registry (sessions currently recording)."""
    sample = _SAMPLES.get(store_id)
    return dict(sample.captures) if sample is not None else {}

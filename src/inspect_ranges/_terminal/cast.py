"""Asciicast v2 assembly for terminal session playback.

A session's capture is a list of host-timestamped output chunks plus per-tool-call markers. `assemble_cast` turns them into an asciicast v2 document (JSON header line, then one JSON event per line: `[t, "o", data]` for output, `[t, "m", label]` for markers), playable by any asciinema player. Pure: no I/O.
"""

from __future__ import annotations

import json
from dataclasses import dataclass

from .session import PANE_HEIGHT, PANE_WIDTH


@dataclass(frozen=True)
class SessionOpener:
    """The agent context that opened a session, captured at open time.

    Captured inside the tool call because retroactive attribution is impossible: sample finalize runs outside every span (agent-spans investigation, 2026-10-25). `agent_span_id` is the grouping key (it joins to the transcript's `SpanBeginEvent.id`, the same join the viewer already does for `ToolEvent.agent_span_id`); `agent_name` is denormalized display text that survives logs written without events; `tool_span_id` pins the exact opening call.
    """

    agent_span_id: str | None = None
    agent_name: str | None = None
    tool_span_id: str | None = None


def assemble_cast(
    chunks: list[tuple[float, bytes]],
    markers: list[tuple[float, str]],
    start_monotonic: float,
    start_wall: float,
    title: str,
    session: str | None = None,
    opener: SessionOpener | None = None,
) -> str:
    """The asciicast v2 document for one session's capture.

    `chunks` and `markers` carry monotonic timestamps; event times are seconds since `start_monotonic`, clamped at zero. Events merge in time order, markers before output at equal times (the marker names the tool call that caused what follows).

    `session` and `opener` land as additive `ir_*` header fields (asciicast parsers ignore unknown keys), so a viewer can group sessions by the agent that opened them while older casts without the fields simply present flat.
    """
    header: dict[str, object] = {
        "version": 2,
        "width": PANE_WIDTH,
        "height": PANE_HEIGHT,
        "timestamp": int(start_wall),
        "title": title,
    }
    if session is not None:
        header["ir_session"] = session
    if opener is not None:
        if opener.agent_span_id is not None:
            header["ir_agent_span_id"] = opener.agent_span_id
        if opener.agent_name is not None:
            header["ir_agent"] = opener.agent_name
        if opener.tool_span_id is not None:
            header["ir_tool_span_id"] = opener.tool_span_id
    events: list[tuple[float, int, str, str]] = []
    for at, label in markers:
        events.append((max(at - start_monotonic, 0.0), 0, "m", label))
    for at, data in chunks:
        events.append(
            (max(at - start_monotonic, 0.0), 1, "o", data.decode(errors="replace"))
        )
    events.sort(key=lambda event: (event[0], event[1]))
    lines = [json.dumps(header)]
    lines.extend(json.dumps([round(at, 6), kind, data]) for at, _, kind, data in events)
    return "\n".join(lines) + "\n"


CAST_STORE_CAP_ENV = "INSPECT_RANGES_CAST_STORE_CAP_MB"
DEFAULT_CAST_STORE_CAP_MB = 50
"""Generous by design: range evals run few samples and their logs are large anyway, so the cap exists for the pathological session (a runaway scan spewing output for the whole wall clock), not the normal one."""


def cast_store_cap_bytes() -> int:
    """The store-cast size cap in bytes (`INSPECT_RANGES_CAST_STORE_CAP_MB`, default 50); a malformed value falls back to the default."""
    import os

    raw = os.environ.get(CAST_STORE_CAP_ENV, "")
    try:
        cap_mb = int(raw) if raw else DEFAULT_CAST_STORE_CAP_MB
    except ValueError:
        cap_mb = DEFAULT_CAST_STORE_CAP_MB
    return max(1, cap_mb) * 1024 * 1024


def clip_cast(cast: str, cap_bytes: int) -> str:
    """Clip an asciicast document to roughly `cap_bytes`, keeping the header and the tail of the event stream (the end of a session is what gets replayed), with a marker event recording the cut.

    The result stays a valid cast: whole event lines only, the marker inserted at time zero so ordering holds. Pure.
    """
    encoded = cast.encode(errors="replace")
    if len(encoded) <= cap_bytes:
        return cast
    header, _, events = cast.partition("\n")
    marker = json.dumps(
        [
            0.0,
            "m",
            "clipped to the tail under the store cap; when evidence is enabled, "
            "the evidence record carries the session's full raw stream",
        ]
    )
    budget = cap_bytes - len(header.encode()) - len(marker.encode()) - 2
    tail = events.encode(errors="replace")[-max(budget, 0) :].decode(errors="replace")
    newline = tail.find("\n")
    tail = tail[newline + 1 :] if newline >= 0 else ""
    return f"{header}\n{marker}\n{tail}"

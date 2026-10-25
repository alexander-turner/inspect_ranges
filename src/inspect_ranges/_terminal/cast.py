"""Asciicast v2 assembly for terminal session playback.

A session's capture is a list of host-timestamped output chunks plus per-tool-call markers. `assemble_cast` turns them into an asciicast v2 document (JSON header line, then one JSON event per line: `[t, "o", data]` for output, `[t, "m", label]` for markers), playable by any asciinema player. Pure: no I/O.
"""

from __future__ import annotations

import json

from .session import PANE_HEIGHT, PANE_WIDTH


def assemble_cast(
    chunks: list[tuple[float, bytes]],
    markers: list[tuple[float, str]],
    start_monotonic: float,
    start_wall: float,
    title: str,
) -> str:
    """The asciicast v2 document for one session's capture.

    `chunks` and `markers` carry monotonic timestamps; event times are seconds since `start_monotonic`, clamped at zero. Events merge in time order, markers before output at equal times (the marker names the tool call that caused what follows).
    """
    header = {
        "version": 2,
        "width": PANE_WIDTH,
        "height": PANE_HEIGHT,
        "timestamp": int(start_wall),
        "title": title,
    }
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

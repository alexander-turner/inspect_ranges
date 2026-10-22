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

"""Generate `splunk-detection.excalidraw`, the topology diagram for the splunk-detection example.

See `splunk-detection-brief.md` for the design brief. Regenerate with `python3 docs/diagrams/splunk_detection.py` (or via `preview.py`, which also renders the SVG).
"""

from __future__ import annotations

from pathlib import Path

from _elements import (
    ATTACKER_BG,
    ATTACKER_STROKE,
    CONTAINER_BG,
    CONTAINER_STROKE,
    EVIDENCE,
    FONT_MONO,
    HOST_BG,
    HOST_STROKE,
    MUTED,
    Elements,
    make_arrow,
    make_rect,
    make_text,
    reset,
    save,
)


def build() -> Elements:
    """Build the splunk-detection topology elements."""
    reset()
    els: Elements = []

    # One flat subnet: the point of this range is the telemetry flow on it.
    seg_y, seg_h = 40, 185
    _, e = make_rect(
        0,
        seg_y,
        620,
        seg_h,
        bg=CONTAINER_BG,
        stroke=CONTAINER_STROKE,
        stroke_style="dashed",
    )
    els += e
    _, e = make_text(
        16, seg_y + 14, "lab · 10.0.2.0/24", 12, MUTED, font_family=FONT_MONO
    )
    els += e

    # The attack box, the instrumented endpoint, and the Splunk server.
    box_y, box_h = 105, 60
    _, e = make_rect(
        25,
        box_y,
        110,
        box_h,
        "attacker",
        bg=ATTACKER_BG,
        stroke=ATTACKER_STROKE,
        stroke_width=2,
        font_size=14,
    )
    els += e
    _, e = make_text(
        80,
        box_y + box_h + 10,
        "attack box\noperator foothold",
        11,
        MUTED,
        align="center",
        font_family=FONT_MONO,
    )
    els += e

    win_id, e = make_rect(
        215,
        box_y,
        130,
        box_h,
        "win",
        bg=HOST_BG,
        stroke=HOST_STROKE,
        stroke_width=2,
        font_size=14,
    )
    els += e
    _, e = make_text(
        280,
        box_y + box_h + 10,
        "10.0.2.11\nServer 2022 · sysmon",
        11,
        MUTED,
        align="center",
        font_family=FONT_MONO,
    )
    els += e

    splunk_id, e = make_rect(
        460,
        box_y,
        130,
        box_h,
        "splunk",
        bg=HOST_BG,
        stroke=HOST_STROKE,
        stroke_width=2,
        font_size=14,
    )
    els += e
    _, e = make_text(
        525,
        box_y + box_h + 10,
        "10.0.2.10\nSplunk Enterprise :8000",
        11,
        MUTED,
        align="center",
        font_family=FONT_MONO,
    )
    els += e

    # The telemetry flow, the range's reason to exist, in the evidence amber.
    mid_y = box_y + box_h / 2 - 10
    _, e = make_arrow(
        345,
        mid_y,
        460,
        mid_y,
        color=EVIDENCE,
        stroke_width=2,
        start_id=win_id,
        end_id=splunk_id,
    )
    els += e
    _, e = make_text(
        402,
        mid_y + 8,
        "forwarder → :9997",
        11,
        EVIDENCE,
        align="center",
        font_family=FONT_MONO,
    )
    els += e

    # The payload: the defense tier, stated plainly.
    _, e = make_text(
        310,
        seg_y + seg_h + 22,
        "defense tier D2: detections recorded and searchable, not acted on",
        13,
        align="center",
        font_family=FONT_MONO,
    )
    els += e

    return els


def main() -> None:
    """Write `splunk-detection.excalidraw` next to this script."""
    save(Path(__file__).parent / "splunk-detection.excalidraw", build())


if __name__ == "__main__":
    main()

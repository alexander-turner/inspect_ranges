"""Generate `cyris-basic.excalidraw`, the topology diagram for the cyris-basic example.

See `cyris-basic-brief.md` for the design brief. Regenerate with `python3 docs/diagrams/cyris_basic.py` (or via `preview.py`, which also renders the SVG).
"""

from __future__ import annotations

from pathlib import Path

from _elements import (
    ATTACKER_BG,
    ATTACKER_STROKE,
    CONTAINER_BG,
    CONTAINER_STROKE,
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
    """Build the cyris-basic topology elements."""
    reset()
    els: Elements = []

    # Two segments joined only by the firewall VM.
    seg_y, seg_h = 40, 185
    _, e = make_rect(
        0,
        seg_y,
        280,
        seg_h,
        bg=CONTAINER_BG,
        stroke=CONTAINER_STROKE,
        stroke_style="dashed",
    )
    els += e
    _, e = make_rect(
        420,
        seg_y,
        200,
        seg_h,
        bg=CONTAINER_BG,
        stroke=CONTAINER_STROKE,
        stroke_style="dashed",
    )
    els += e
    _, e = make_text(
        16, seg_y + 14, "office · 10.1.10.0/24", 12, MUTED, font_family=FONT_MONO
    )
    els += e
    _, e = make_text(
        433, seg_y + 14, "servers · 10.1.20.0/24", 12, MUTED, font_family=FONT_MONO
    )
    els += e

    # Hosts: the desktop IS the attacker foothold (assumed breach).
    box_y, box_h = 105, 60
    _, e = make_rect(
        85,
        box_y,
        110,
        box_h,
        "desktop",
        bg=ATTACKER_BG,
        stroke=ATTACKER_STROKE,
        stroke_width=2,
        font_size=14,
    )
    els += e
    _, e = make_text(
        140,
        box_y + box_h + 10,
        "10.1.10.5\nattacker foothold",
        12,
        MUTED,
        align="center",
        font_family=FONT_MONO,
    )
    els += e

    _, e = make_rect(
        465,
        box_y,
        110,
        box_h,
        "webserver",
        bg=HOST_BG,
        stroke=HOST_STROKE,
        stroke_width=2,
        font_size=14,
    )
    els += e
    _, e = make_text(
        520,
        box_y + box_h + 10,
        "10.1.20.5\n:80 · :22",
        12,
        MUTED,
        align="center",
        font_family=FONT_MONO,
    )
    els += e

    # The firewall between the segments: a gateway that is itself a target.
    router_id, e = make_rect(
        302, box_y, 96, box_h, "firewall", stroke_width=2, font_size=14
    )
    els += e
    mid_y = box_y + box_h / 2
    _, e = make_arrow(280, mid_y, 302, mid_y, end_arrowhead=None, end_id=router_id)
    els += e
    _, e = make_arrow(398, mid_y, 420, mid_y, end_arrowhead=None, start_id=router_id)
    els += e
    _, e = make_text(
        350,
        box_y + box_h + 10,
        "gateway + target\n(weak ssh account)",
        12,
        MUTED,
        align="center",
        font_family=FONT_MONO,
    )
    els += e

    # The payload: the forwarding rule, on its own line below the segments.
    _, e = make_text(
        310,
        seg_y + seg_h + 22,
        "acl: office → servers · tcp/25, tcp/53 only",
        13,
        align="center",
        font_family=FONT_MONO,
    )
    els += e

    return els


def main() -> None:
    """Write `cyris-basic.excalidraw` next to this script."""
    save(Path(__file__).parent / "cyris-basic.excalidraw", build())


if __name__ == "__main__":
    main()

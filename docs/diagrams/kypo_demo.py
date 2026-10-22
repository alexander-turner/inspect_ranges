"""Generate `kypo-demo.excalidraw`, the topology diagram for the kypo-demo example.

See `kypo-demo-brief.md` for the design brief. Regenerate with `python3 docs/diagrams/kypo_demo.py` (or via `preview.py`, which also renders the SVG).
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
    """Build the kypo-demo topology elements."""
    reset()
    els: Elements = []

    # Two routed /24 segments: the foothold's switch left, the server's right.
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
        250,
        seg_h,
        bg=CONTAINER_BG,
        stroke=CONTAINER_STROKE,
        stroke_style="dashed",
    )
    els += e
    _, e = make_text(
        16,
        seg_y + 14,
        "client-switch · 192.168.30.0/24",
        12,
        MUTED,
        font_family=FONT_MONO,
    )
    els += e
    _, e = make_text(
        433,
        seg_y + 14,
        "server-switch · 192.168.20.0/24",
        12,
        MUTED,
        font_family=FONT_MONO,
    )
    els += e

    # Hosts: the client IS the attacker foothold (assumed breach).
    box_y, box_h = 105, 60
    _, e = make_rect(
        85,
        box_y,
        110,
        box_h,
        "client",
        bg=ATTACKER_BG,
        stroke=ATTACKER_STROKE,
        stroke_width=2,
        font_size=14,
    )
    els += e
    _, e = make_text(
        140,
        box_y + box_h + 10,
        "192.168.30.5\nattacker foothold",
        12,
        MUTED,
        align="center",
        font_family=FONT_MONO,
    )
    els += e

    _, e = make_rect(
        490,
        box_y,
        110,
        box_h,
        "server",
        bg=HOST_BG,
        stroke=HOST_STROKE,
        stroke_width=2,
        font_size=14,
    )
    els += e
    _, e = make_text(
        545,
        box_y + box_h + 10,
        "192.168.20.5\ntelnetd :<telnet_port>",
        12,
        MUTED,
        align="center",
        font_family=FONT_MONO,
    )
    els += e

    # Router between the segments, joined to each by a plain connector.
    router_id, e = make_rect(
        302, box_y, 96, box_h, "router", stroke_width=2, font_size=14
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
        "192.168.30.1\n192.168.20.1",
        12,
        MUTED,
        align="center",
        font_family=FONT_MONO,
    )
    els += e

    # The payload: no ACL (pure routing) and the randomized service port.
    _, e = make_text(
        335,
        seg_y + seg_h + 22,
        "no acl declared: the router forwards all traffic\ntelnet_port drawn per instance via variables (default 2323)",
        13,
        align="center",
        font_family=FONT_MONO,
    )
    els += e

    return els


def main() -> None:
    """Write `kypo-demo.excalidraw` next to this script."""
    save(Path(__file__).parent / "kypo-demo.excalidraw", build())


if __name__ == "__main__":
    main()

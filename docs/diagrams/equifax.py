"""Generate `equifax.excalidraw`, the topology diagram for the equifax example.

See `equifax-brief.md` for the design brief. Regenerate with `python3 docs/diagrams/equifax.py` (or via `preview.py`, which also renders the SVG).
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


def _host(
    els: Elements, x: float, y: float, w: float, h: float, name: str, ip: str
) -> None:
    """Add a blue host box with its address underneath."""
    _, e = make_rect(
        x, y, w, h, name, bg=HOST_BG, stroke=HOST_STROKE, stroke_width=2, font_size=13
    )
    els += e
    _, e = make_text(
        x + w / 2, y + h + 6, ip, 11, MUTED, align="center", font_family=FONT_MONO
    )
    els += e


def build() -> Elements:
    """Build the equifax topology elements."""
    reset()
    els: Elements = []

    # Three segments in breach order: attacker, DMZ-like webservers, critical.
    seg_y, seg_h = 40, 200
    for x, w, label in (
        (0, 170, "attacker_network\n192.168.202.0/24"),
        (210, 200, "webserver_network\n192.168.200.0/24"),
        (450, 240, "critical_company_network\n192.168.201.0/24"),
    ):
        _, e = make_rect(
            x,
            seg_y,
            w,
            seg_h,
            bg=CONTAINER_BG,
            stroke=CONTAINER_STROKE,
            stroke_style="dashed",
        )
        els += e
        _, e = make_text(x + 14, seg_y + 12, label, 11, MUTED, font_family=FONT_MONO)
        els += e

    # The attacker, alone on its own segment.
    _, e = make_rect(
        35,
        155,
        100,
        50,
        "attacker",
        bg=ATTACKER_BG,
        stroke=ATTACKER_STROKE,
        stroke_width=2,
        font_size=13,
    )
    els += e
    _, e = make_text(
        85,
        211,
        "192.168.202.100\nentry: external",
        11,
        MUTED,
        align="center",
        font_family=FONT_MONO,
    )
    els += e

    # Two Struts webservers (the pivot key lives on webserver_0 only).
    _host(els, 240, 92, 140, 46, "webserver_0", "192.168.200.10")
    _host(els, 240, 165, 140, 46, "webserver_1", "192.168.200.11")

    # Four database hosts, each with a planted sensitive dataset.
    _host(els, 470, 92, 100, 46, "database_0", "192.168.201.50")
    _host(els, 585, 92, 100, 46, "database_1", "192.168.201.51")
    _host(els, 470, 165, 100, 46, "database_2", "192.168.201.52")
    _host(els, 585, 165, 100, 46, "database_3", "192.168.201.53")

    # The router below, an interface on every subnet.
    router_y, router_h = 282, 50
    router_id, e = make_rect(
        285, router_y, 130, router_h, "router_external", stroke_width=2, font_size=13
    )
    els += e
    for cx in (85, 310, 570):
        _, e = make_arrow(
            cx, seg_y + seg_h, 350, router_y, end_arrowhead=None, end_id=router_id
        )
        els += e

    # The payload: the asymmetric ACL, attacker never reaches critical.
    _, e = make_text(
        345,
        router_y + router_h + 20,
        "acl: attacker ↔ webserver · tcp any port\nwebserver ↔ critical · tcp any port\nattacker → critical · denied (default deny)",
        13,
        align="center",
        font_family=FONT_MONO,
    )
    els += e

    return els


def main() -> None:
    """Write `equifax.excalidraw` next to this script."""
    save(Path(__file__).parent / "equifax.excalidraw", build())


if __name__ == "__main__":
    main()

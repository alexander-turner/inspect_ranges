"""Generate `defender-ops.excalidraw`, the topology diagram for the defender-ops example.

See `defender-ops-brief.md` for the design brief. Regenerate with `python3 docs/diagrams/defender_ops.py` (or via `preview.py`, which also renders the SVG).
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
    """Build the defender-ops topology elements."""
    reset()
    els: Elements = []

    # Three segments left to right: the attacker's NAT staging segment, the
    # ops segment, and the routed mgmt segment. The attacker and the bastion
    # straddle the staging/ops boundary (both are dual-homed).
    seg_y, seg_h = 40, 265
    for x, w in ((0, 240), (320, 240), (660, 220)):
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
    _, e = make_text(
        14,
        seg_y + 14,
        "staging · 10.90.10.0/24\nnat + scoped egress",
        12,
        MUTED,
        font_family=FONT_MONO,
    )
    els += e
    _, e = make_text(
        334,
        seg_y + 14,
        "ops · 10.90.20.0/24",
        12,
        MUTED,
        font_family=FONT_MONO,
    )
    els += e
    _, e = make_text(
        674,
        seg_y + 14,
        "mgmt · 10.90.30.0/24",
        12,
        MUTED,
        font_family=FONT_MONO,
    )
    els += e

    box_h = 55

    # Attacker and bastion straddle the staging/ops boundary (dual-homed).
    _, e = make_rect(
        215,
        95,
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
        270,
        95 + box_h + 8,
        ".10.2 / .20.2",
        12,
        MUTED,
        align="center",
        font_family=FONT_MONO,
    )
    els += e

    _, e = make_rect(
        215,
        205,
        110,
        box_h,
        "bastion",
        bg=HOST_BG,
        stroke=HOST_STROKE,
        stroke_width=2,
        font_size=14,
    )
    els += e
    _, e = make_text(
        270,
        205 + box_h + 8,
        ".10.10 / .20.4\ngate :8022 (keep up)",
        12,
        MUTED,
        align="center",
        font_family=FONT_MONO,
    )
    els += e

    # The web host inside ops.
    _, e = make_rect(
        425,
        140,
        110,
        box_h,
        "web",
        bg=HOST_BG,
        stroke=HOST_STROKE,
        stroke_width=2,
        font_size=14,
    )
    els += e
    _, e = make_text(
        480,
        140 + box_h + 8,
        "10.90.20.10\norderboard :8080\nstatus :8081",
        12,
        MUTED,
        align="center",
        font_family=FONT_MONO,
    )
    els += e

    # Router between ops and mgmt, joined by plain connectors.
    router_id, e = make_rect(568, 140, 84, box_h, "router", stroke_width=2, font_size=14)
    els += e
    mid_y = 140 + box_h / 2
    _, e = make_arrow(560, mid_y, 568, mid_y, end_arrowhead=None, end_id=router_id)
    els += e
    _, e = make_arrow(652, mid_y, 660, mid_y, end_arrowhead=None, start_id=router_id)
    els += e

    # The monitor inside mgmt.
    _, e = make_rect(
        710,
        140,
        110,
        box_h,
        "monitor",
        bg=HOST_BG,
        stroke=HOST_STROKE,
        stroke_width=2,
        font_size=14,
    )
    els += e
    _, e = make_text(
        765,
        140 + box_h + 8,
        "10.90.30.10\nopswatchdog :9090\nops log -> opslog",
        12,
        MUTED,
        align="center",
        font_family=FONT_MONO,
    )
    els += e

    # The payload: the ACL shape and the drawn variables.
    _, e = make_text(
        440,
        seg_y + seg_h + 22,
        "acl: deny ops->monitor tcp/22; allow ops->mgmt tcp/22,9090,icmp; allow 10.90.30.0/24->web tcp/8080,8081,icmp\n"
        "gate_code (int) and site_wing (choice) draw per sample; a boot unit rewrites the status board from the draws file",
        13,
        align="center",
        font_family=FONT_MONO,
    )
    els += e

    return els


def main() -> None:
    """Write `defender-ops.excalidraw` next to this script."""
    save(Path(__file__).parent / "defender-ops.excalidraw", build())


if __name__ == "__main__":
    main()

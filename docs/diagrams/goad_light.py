"""Generate `goad-light.excalidraw`, the topology diagram for the goad-light example.

See `goad-light-brief.md` for the design brief. Regenerate with `python3 docs/diagrams/goad_light.py` (or via `preview.py`, which also renders the SVG).
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
    make_rect,
    make_text,
    reset,
    save,
)


def build() -> Elements:
    """Build the goad-light topology elements."""
    reset()
    els: Elements = []

    # One flat subnet: an AD forest needs no routing to be hard.
    seg_y, seg_h = 40, 190
    _, e = make_rect(
        0,
        seg_y,
        660,
        seg_h,
        bg=CONTAINER_BG,
        stroke=CONTAINER_STROKE,
        stroke_style="dashed",
    )
    els += e
    _, e = make_text(
        16, seg_y + 14, "lab · 192.168.56.0/24", 12, MUTED, font_family=FONT_MONO
    )
    els += e

    # The attack box plus the three Windows Server guests, hostname in the box.
    box_y, box_h, box_w = 95, 60, 120
    _, e = make_rect(
        25,
        box_y,
        box_w,
        box_h,
        "attacker",
        bg=ATTACKER_BG,
        stroke=ATTACKER_STROKE,
        stroke_width=2,
        font_size=14,
    )
    els += e
    _, e = make_text(
        85,
        box_y + box_h + 10,
        "attack box\nassumed breach",
        11,
        MUTED,
        align="center",
        font_family=FONT_MONO,
    )
    els += e

    for x, label, note in (
        (185, "dc01\nkingslanding", "192.168.56.10\nforest root DC\ndefender: on"),
        (345, "dc02\nwinterfell", "192.168.56.11\nchild DC (north)\ndefender: on"),
        (
            505,
            "srv02\ncastelblack",
            "192.168.56.22\nIIS · MSSQL · WebDAV\ndefender: off",
        ),
    ):
        _, e = make_rect(
            x,
            box_y,
            box_w,
            box_h,
            label,
            bg=HOST_BG,
            stroke=HOST_STROKE,
            stroke_width=2,
            font_size=13,
        )
        els += e
        _, e = make_text(
            x + box_w / 2,
            box_y + box_h + 10,
            note,
            11,
            MUTED,
            align="center",
            font_family=FONT_MONO,
        )
        els += e

    # The payload: one forest, two domains; identity is the attack surface.
    _, e = make_text(
        330,
        seg_y + seg_h + 22,
        "forest sevenkingdoms.local · child domain north.sevenkingdoms.local",
        13,
        align="center",
        font_family=FONT_MONO,
    )
    els += e

    return els


def main() -> None:
    """Write `goad-light.excalidraw` next to this script."""
    save(Path(__file__).parent / "goad-light.excalidraw", build())


if __name__ == "__main__":
    main()

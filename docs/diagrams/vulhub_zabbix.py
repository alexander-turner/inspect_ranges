"""Generate `vulhub-zabbix.excalidraw`, the topology diagram for the vulhub-zabbix example.

See `vulhub-zabbix-brief.md` for the design brief. Regenerate with `python3 docs/diagrams/vulhub_zabbix.py` (or via `preview.py`, which also renders the SVG).
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
    """Build the vulhub-zabbix topology elements."""
    reset()
    els: Elements = []

    # One flat segment: a single dashed broadcast domain holding all five VMs.
    seg_y, seg_h = 40, 185
    _, e = make_rect(
        0,
        seg_y,
        640,
        seg_h,
        bg=CONTAINER_BG,
        stroke=CONTAINER_STROKE,
        stroke_style="dashed",
    )
    els += e
    _, e = make_text(
        16, seg_y + 14, "lab · 10.10.10.0/24", 12, MUTED, font_family=FONT_MONO
    )
    els += e

    # Hosts, ordered by the attack chain: attacker -> web -> server -> agent,
    # with mysql (the stack's database) last.
    box_y, box_h, box_w = 105, 60, 100
    _, e = make_rect(
        20,
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
        70,
        box_y + box_h + 10,
        "entry: external",
        12,
        MUTED,
        align="center",
        font_family=FONT_MONO,
    )
    els += e

    for x, name, note in (
        (145, "web", "10.10.10.14\n:80"),
        (270, "server", "10.10.10.12\n:10051"),
        (395, "agent", "10.10.10.13\n:10050"),
        (520, "mysql", "10.10.10.11\n:3306"),
    ):
        _, e = make_rect(
            x,
            box_y,
            box_w,
            box_h,
            name,
            bg=HOST_BG,
            stroke=HOST_STROKE,
            stroke_width=2,
            font_size=14,
        )
        els += e
        _, e = make_text(
            x + box_w / 2,
            box_y + box_h + 10,
            note,
            12,
            MUTED,
            align="center",
            font_family=FONT_MONO,
        )
        els += e

    # The payload: the real CVE entry and the escalation it opens.
    _, e = make_text(
        320,
        seg_y + seg_h + 22,
        "entry: CVE-2016-10134 (SQLi in zabbix-web)\nescalation: admin session hijack → RCE via server → agent",
        13,
        align="center",
        font_family=FONT_MONO,
    )
    els += e

    return els


def main() -> None:
    """Write `vulhub-zabbix.excalidraw` next to this script."""
    save(Path(__file__).parent / "vulhub-zabbix.excalidraw", build())


if __name__ == "__main__":
    main()

"""Generate `containment.excalidraw`, the nested containment-stack diagram for the overview.

See `containment-brief.md` for the design brief. Regenerate with `python3 docs/diagrams/containment.py` (or via `preview.py`, which also renders the SVG).
"""

from __future__ import annotations

from pathlib import Path

from _elements import (
    ATTACKER_BG,
    ATTACKER_STROKE,
    CONTAINER_BG,
    CONTAINER_STROKE,
    CONTROL,
    CONTROL_BG,
    EVIDENCE,
    FONT_MONO,
    HOST_BG,
    HOST_STROKE,
    INFRA_BG,
    INFRA_STROKE,
    MUTED,
    Elements,
    make_arrow,
    make_rect,
    make_text,
    reset,
    save,
)


def build() -> Elements:
    """Build the containment-stack elements."""
    reset()
    els: Elements = []

    # Outermost boundary: the Nitro instance. Overall width is kept near
    # 700 px so the diagram lands in a Word text column without the type
    # shrinking below the other diagrams'.
    _, e = make_rect(
        0, 0, 660, 372, bg="#ffffff", stroke=CONTAINER_STROKE, stroke_width=2
    )
    els += e
    _, e = make_text(20, 14, "EC2 Nitro instance", 14)
    els += e
    _, e = make_text(
        190,
        16,
        "one sample per instance",
        12,
        MUTED,
        font_family=FONT_MONO,
    )
    els += e

    # The sandbox-control port: the fixed on-instance endpoint of the control
    # channel, straddling the boundary. Deliberately silent about who drives
    # it (a co-resident worker, or a remote scaffold via the host interface).
    port_id, e = make_rect(
        477,
        -14,
        120,
        28,
        "sandbox control",
        bg=CONTROL_BG,
        stroke=CONTROL,
        font_size=12,
    )
    els += e

    # The range container.
    _, e = make_rect(30, 72, 600, 285, bg=CONTAINER_BG, stroke=CONTAINER_STROKE)
    els += e
    _, e = make_text(50, 84, "range container", 14)
    els += e
    _, e = make_text(
        175,
        86,
        "unprivileged · libvirtd + QEMU · cloud-hypervisor",
        12,
        MUTED,
        font_family=FONT_MONO,
    )
    els += e

    # VM row.
    vm_y, vm_h, vm_w = 132, 70, 125
    xs = [55, 195, 335, 475]
    router_specs = [
        (xs[0], "router VM", INFRA_BG, INFRA_STROKE),
        (xs[1], "web VM", HOST_BG, HOST_STROKE),
        (xs[2], "db VM", HOST_BG, HOST_STROKE),
        (xs[3], "agent VM", ATTACKER_BG, ATTACKER_STROKE),
    ]
    agent_id = ""
    for x, label, bg, stroke in router_specs:
        box_id, e = make_rect(
            x,
            vm_y,
            vm_w,
            vm_h,
            label,
            bg=bg,
            stroke=stroke,
            stroke_width=2,
            font_size=15,
        )
        els += e
        if label == "agent VM":
            agent_id = box_id
            # The attack box runs Cloud Hypervisor rather than QEMU (the most
            # adversarial guest gets the smaller VMM); annotate in the same
            # muted mono style as the container header.
            _, e = make_text(
                x + vm_w / 2,
                vm_y + 8,
                "cloud-hypervisor",
                10,
                MUTED,
                align="center",
                font_family=FONT_MONO,
            )
            els += e
        # Every guest carries the same vsock socket (host↔guest only, so no
        # fan of lines): a small violet notch straddling each VM's top edge,
        # echoing the sandbox-control port on the instance boundary.
        _, e = make_rect(
            x + vm_w / 2 - 13,
            vm_y - 6,
            26,
            12,
            bg=CONTROL_BG,
            stroke=CONTROL,
        )
        els += e

    # Bridges strip: every VM has a real NIC on a bridge, the agent included.
    bridge_y, bridge_h = 252, 40
    _, e = make_rect(
        55,
        bridge_y,
        545,
        bridge_h,
        "Linux bridges + generated nftables",
        bg=INFRA_BG,
        stroke=INFRA_STROKE,
        font_size=13,
        font_family=FONT_MONO,
    )
    els += e
    for x in xs:
        _, e = make_arrow(
            x + vm_w / 2, vm_y + vm_h, x + vm_w / 2, bridge_y, end_arrowhead=None
        )
        els += e
    _, e = make_text(
        70,
        bridge_y + bridge_h + 14,
        "bridges exist only in the container netns · egress: none",
        12,
        MUTED,
        font_family=FONT_MONO,
    )
    els += e

    # The vsock control channel: port → agent VM, through the container
    # border, bypassing the bridges entirely.
    _, e = make_arrow(
        537,
        14,
        537,
        vm_y - 6,
        color=CONTROL,
        stroke_width=2,
        start_id=port_id,
        end_id=agent_id,
    )
    els += e
    # Left-aligned with "one sample per instance" above it; "control" is
    # already carried by the port label, and the caption must end short of
    # the arrow at x=537.
    _, e = make_text(
        190,
        40,
        "virtio-vsock (not a network) to every guest",
        12,
        CONTROL,
        font_family=FONT_MONO,
    )
    els += e

    # Evidence streams off-instance: a labeled flow in the container's bottom
    # right whose arrow just crosses the container and instance borders.
    _, e = make_text(
        584,
        bridge_y + bridge_h + 36,
        "evidence streams off-instance",
        12,
        EVIDENCE,
        align="right",
    )
    els += e
    _, e = make_arrow(
        592,
        bridge_y + bridge_h + 43,
        685,
        bridge_y + bridge_h + 43,
        color=EVIDENCE,
        stroke_width=2,
    )
    els += e

    return els


def main() -> None:
    """Write `containment.excalidraw` next to this script."""
    save(Path(__file__).parent / "containment.excalidraw", build())


if __name__ == "__main__":
    main()

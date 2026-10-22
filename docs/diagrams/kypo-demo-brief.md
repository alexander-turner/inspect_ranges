# Design brief: the kypo-demo topology diagram

## What this is

The network topology for the `kypo-demo` example range, placed in the example page's Topology section. The one idea it must land: *two routed, IP-pinned subnets joined by an explicit router, with the trainee's foothold on one side and a randomized-port telnet target on the other.*

## Structure (fixed)

- Two segment containers side by side: `client-switch · 192.168.30.0/24` left, `server-switch · 192.168.20.0/24` right. Soft gray, dashed border.
- Left: the `client` VM (red — it is the attacker foothold, annotated `attacker foothold`, `192.168.30.5`).
- Right: the `server` VM (blue, `192.168.20.5`, annotated `telnetd :<telnet_port>` — the port is drawn per instance).
- The `router` (gray) between the segments, joined by plain connectors, with its two interface addresses (`.30.1` / `.20.1`).
- The payload annotation below, monospace, two lines: no ACL declared (the router forwards everything), and the telnet port is a declared variable (default 2323).

## Style

House style per `dmz-pivot-brief.md`: clean lines, soft solid fills, monospace for addresses/CIDRs, blue = target, red = attacker/foothold, gray = infrastructure, light theme, ~670 px content column.

## Open

Proportions, spacing, exact label placement. The structure and wording above are fixed.

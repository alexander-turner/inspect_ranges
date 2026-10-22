# Design brief: the cyris-basic topology diagram

## What this is

The network topology for the `cyris-basic` example range, placed in the example page's Topology section. The one idea it must land: *two segments joined only by a firewall VM that forwards two ports — and the firewall is itself a target with a weak account.*

## Structure (fixed)

- Two segment containers side by side: `office · 10.1.10.0/24` left, `servers · 10.1.20.0/24` right. Soft gray, dashed border.
- Left: the `desktop` VM (red — the attacker foothold, assumed breach, `10.1.10.5`).
- Right: the `webserver` VM (blue, `10.1.20.5`, annotated `:80 · :22`).
- The `firewall` (gray) between the segments, joined by plain connectors, annotated `gateway + target (weak ssh account)` — upstream marks it `is_host: true`.
- The ACL annotation below, monospace: `acl: office → servers · tcp/25, tcp/53 only`.

## Style

House style per `dmz-pivot-brief.md`: clean lines, soft solid fills, monospace for addresses/CIDRs/ACL text, blue = target, red = attacker/foothold, gray = infrastructure, light theme, ~620 px content column.

## Open

Proportions, spacing, exact label placement. The structure and wording above are fixed.

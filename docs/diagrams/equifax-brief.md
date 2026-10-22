# Design brief: the equifax topology diagram

## What this is

The network topology for the `equifax` example range, placed in the example page's Topology section. The one idea it must land: *three subnets with an asymmetric ACL — the attacker reaches the webservers, the webservers reach the critical network, and the attacker never reaches critical directly.*

## Structure (fixed)

- Three segment containers in breach order: `attacker_network · 192.168.202.0/24`, `webserver_network · 192.168.200.0/24`, `critical_company_network · 192.168.201.0/24`. Soft gray, dashed border; two-line labels (name over CIDR).
- Attacker segment: the `attacker` VM (red, `192.168.202.100`, `entry: external`).
- Webserver segment: `webserver_0` (`.10`) and `webserver_1` (`.11`), blue (the Struts CVE entry; the pivot SSH key lives on `webserver_0` only).
- Critical segment: `database_0` through `database_3` in a 2x2 grid (`.50` to `.53`), blue.
- One router (`router_external`, gray) below, joined to all three segments by plain connectors.
- The ACL annotation below the router, monospace, three lines: attacker ↔ webserver tcp, webserver ↔ critical tcp, attacker → critical denied (default deny).

## Style

House style per `dmz-pivot-brief.md`: clean lines, soft solid fills, monospace for addresses/CIDRs/ACL text, blue = targets, red = attacker, gray = infrastructure, light theme, ~690 px content column.

## Open

Proportions, spacing, exact label placement. The structure and wording above are fixed.

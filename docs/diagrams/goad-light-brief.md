# Design brief: the goad-light topology diagram

## What this is

The network topology for the `goad-light` example range, placed in the example page's Topology section. The one idea it must land: *one flat subnet, one AD forest with a parent and a child domain — the attack surface is identity, not routing — with Defender on at the DCs and off on the member server.*

## Structure (fixed)

- One segment container: `lab · 192.168.56.0/24`. Soft gray, dashed border.
- Four VMs left to right: `attacker` (red, the attack box, `assumed breach`), `dc01 / kingslanding` (`.10`, forest root DC, defender on), `dc02 / winterfell` (`.11`, child DC for north, defender on), `srv02 / castelblack` (`.22`, member server: IIS · MSSQL · WebDAV, defender off) — targets blue, hostname inside the box under the guest name.
- The payload annotation below, monospace: `forest sevenkingdoms.local · child domain north.sevenkingdoms.local`.

## Style

House style per `dmz-pivot-brief.md`: clean lines, soft solid fills, monospace for addresses and the per-host notes, blue = targets, red = attacker, light theme, ~660 px content column.

## Open

Proportions, spacing, exact label placement. The structure and wording above are fixed.

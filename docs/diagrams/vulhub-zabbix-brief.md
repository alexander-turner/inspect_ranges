# Design brief: the vulhub-zabbix topology diagram

## What this is

The network topology for the `vulhub-zabbix` example range, placed in the example page's Topology section. The one idea it must land: *one flat broadcast domain, four cooperating services, and the entry is a real public CVE in the web UI.*

## Structure (fixed)

- One segment container: `lab · 10.10.10.0/24`. Soft gray, dashed border.
- Five VMs left to right in chain order: `attacker` (red, `entry: external`), then `web` (`:80`), `server` (`:10051`), `agent` (`:10050`), `mysql` (`:3306`) — all blue, each annotated with its address and port.
- The payload annotation below, monospace, two lines: the CVE entry (`CVE-2016-10134`, SQLi in zabbix-web) and the escalation (admin session hijack → RCE via server → agent).

## Style

House style per `dmz-pivot-brief.md`: clean lines, soft solid fills, monospace for addresses/ports, blue = targets, red = attacker, light theme, ~640 px content column.

## Open

Proportions, spacing, exact label placement. The structure and wording above are fixed.

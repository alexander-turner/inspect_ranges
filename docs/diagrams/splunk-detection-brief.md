# Design brief: the splunk-detection topology diagram

## What this is

The network topology for the `splunk-detection` example range, placed in the example page's Topology section. The one idea it must land: *telemetry is the point — the instrumented Windows endpoint's logs flow to Splunk, and detection against that stream is what the range scores.*

## Structure (fixed)

- One segment container: `lab · 10.0.2.0/24`. Soft gray, dashed border.
- Three VMs left to right: `attacker` (red, the attack box, `operator foothold`), `win` (blue, `10.0.2.11`, Server 2022 with sysmon), `splunk` (blue, `10.0.2.10`, Splunk Enterprise `:8000`).
- The telemetry flow as an amber arrow from `win` to `splunk`, labeled `forwarder → :9997` (amber = evidence in the house palette; this stream is what scoring reads).
- The payload annotation below, monospace: `defense tier D2: detections recorded and searchable, not acted on`.

## Style

House style per `dmz-pivot-brief.md`: clean lines, soft solid fills, monospace for addresses/ports, blue = targets, red = attacker, amber = telemetry/evidence, light theme, ~620 px content column.

## Open

Proportions, spacing, exact label placement. The structure and wording above are fixed.

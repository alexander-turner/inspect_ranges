# Spike: network-services conformance — DHCP and DNS realization (networking-v0.2 §9, slices 5 and 7)

> **Superseded as a battery (2026-10-08):** this spike's apply glue is historical reference; the conformance checks now run against realizer-booted ranges via [realizer-batteries](../realizer-batteries/README.md).

*Two of the three v0.1-legacy ledger rows: `dhcp: true` and the `dns` shapes, realized by the production compiler (`inspect_ranges._compiler.render_dnsmasq_conf`, `resolvers_for`, and the hypervisor-address reservation in `allocate`) and proven in a booted range. Machinery carried from the earlier conformance spikes; the range image adds dnsmasq. Run on the m6i.metal devbox, 2026-10-06. `./run.sh` reproduces; `./run.sh down` tears down. The authoritative clean run is `tmp/run4.log` (8/8).*

## Verdict

**DHCP reservations and all three DNS shapes hold in a booted range: 8/8 checks, enforced-ready in 45.4 s.** DHCP is reservation-only (`dhcp-range=...,static` plus per-MAC `dhcp-host` entries from the allocation), so DHCP addressing is exactly as deterministic as static: guests receive precisely their allocated addresses. Range-served DNS runs as dnsmasq in the range netns on the reserved hypervisor address (`no-hosts`/`no-resolv`: nothing leaks from the hypervisor's own resolver), serving declared records with addresses derived from the allocation where not explicit.

## What the battery proved

| Check | Construct |
|---|---|
| N1/N2 web and the attacker hold exactly their allocated addresses | DHCP reservations from the allocation |
| N3 `web` resolves to its allocated address | derived record + the search-domain realization (below) |
| N4 `files.corp.example` resolves to its explicit address | explicit records |
| N5 the DHCP-handed resolver is the reserved service address | DHCP options carry resolver config |
| N6 net2 guests hold db-then-9.9.9.9 as resolvers | `authoritative` + `nameservers` ordering in the generated netplan |
| N7 lab cannot reach net2 | isolation unchanged by the services |
| N8 zero range bridges on the host | invisibility unchanged |

## Findings with design consequences

1. **Single-label discovery requires a search domain.** systemd-resolved does not send single-label names ("web") to unicast DNS, so the realization derives a search domain per records network (`<network>.internal`), hands it out via DHCP (or netplan `search` for static guests), and registers single-label records under both names. Without this, the vulhub-style "name-based discovery on flat networks" requirement silently fails on modern guests.
2. **`.local` names never reach unicast DNS on systemd-resolved guests** (reserved for mDNS). Caught live by the first fixture choice. Consequence recorded for AD ranges: GOAD-class zones under `.local` resolve fine for Windows guests, but Linux guests need resolver domain routing (as the goad-forest seed did); a semantic warning when records/authoritative zones end in `.local` is a cheap future validator.
3. **The hypervisor service address is a second declared exception** to "bridges carry no IP" (the first being nat/routed gateways): dhcp/records networks make the hypervisor addressable on that segment, port-scoped to DNS/DHCP (`port=0` when DHCP-only).

## Files

- `spec.yaml` — two segments: lab (dhcp + records, derived and explicit), net2 (authoritative + external nameservers)
- `compile.py` — production stages for allocation, service addresses, dnsmasq confs, resolver lists; spike glue for seeds (dhcp4 vs static netplan), bridges, boot
- `range/` — the shared range image plus dnsmasq; entrypoint assigns reserved addresses and starts one dnsmasq per rendered conf
- `run.sh` — validate, compile, boot, the 8-check battery
- `tmp/run4.log` — the clean run

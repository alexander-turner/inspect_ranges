# Spike: routed-egress conformance — mode: routed realization (networking-v0.2 §9, slice 6)

> **Superseded as a battery (2026-10-08):** this spike's apply glue is historical reference; the conformance checks now run against realizer-booted ranges via [realizer-batteries](../realizer-batteries/README.md).

*The last v0.1-legacy ledger row: `mode: routed`, realized as un-NATed two-way forwarding between the network's bridge and the range-netns uplink (`inspect_ranges._compiler.render_egress_nftables`), with the hypervisor gateway reserved by the allocator. The egress battery's sibling: isolated (hardened-container) and nat (egress spike) were already proven; this pins the third posture. Run on the m6i.metal devbox, 2026-10-06. `./run.sh` reproduces; `./run.sh down` tears down.*

## Verdict

**Routed egress holds in a booted range: 7/7 checks, enforced-ready in 48.3 s.** Guests on a `mode: routed` network reach the upstream with their real addresses (the upstream's log shows the guest's in-range address — the un-NATed proof), the upstream can route back in (two-way, the routed posture), no masquerade exists anywhere in the ruleset, and the attacker's `egress: none` still composes ahead of the posture.

## What the battery proved

| Check | Construct |
|---|---|
| RT1 workstation→upstream:443 completes | routed forwarding through the netns |
| RT2 the upstream logged `10.91.10.10` | **un-NATed: real source addresses leave the range** |
| RT3 upstream→workstation:22 connects | two-way routing (ingress direction of the routed posture) |
| RT4 attacker→upstream:443 dropped | `egress: none` override precedes the posture |
| RT5 zero masquerade rules | NAT stays scoped to `mode: nat` subnets (none here) |
| RT6 workstation default-routes via `10.91.10.1` | the allocator-reserved hypervisor gateway |
| RT7 zero range bridges on the host | invisibility unchanged |

## Realization notes

- `mode: routed` is deliberately two-way: the posture means the subnet is really routed toward the uplink, in both directions; ranges wanting ingress restrictions use ACLs or a different mode. Masquerade is rendered per `mode: nat` subnet, so nat and routed networks coexist without NAT leaking onto routed traffic.
- The deployment owns the return path: whatever sits upstream must route the range subnets back (here, one `ip route add` on the upstream container).

## Files

- `spec.yaml` — one `mode: routed` segment, attacker with `egress: none`
- `compile.py` — the netsvc compiler verbatim (no dhcp/dns in this spec)
- `compose.yaml` — range (static uplink address) + upstream with the return route, on a static-subnet simulated internet
- `run.sh` — validate, compile, boot, the 7-check battery
- `tmp/run2.log` — the clean run

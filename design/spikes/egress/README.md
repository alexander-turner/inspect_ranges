# Spike: scoped-egress conformance — the NAT battery for networking-v0.2 §3

*The lockstep conformance leg for slice 4 of [networking-v0.2](../../inspect-ranges/networking-v0.2.md), and the queued NAT-conformance item from [architecture.md](../../inspect-ranges/architecture.md) §13: `EgressPolicy` lives in the schema with its validators (`invalid-egress-entry`, `egress-requires-nat`, `egress-with-router-not-realized`, the `egress-fqdn-not-realized` and IPv6 gates), the allocator reserves a hypervisor gateway on routerless `mode: nat` networks, and `render_egress_nftables` realizes the allowlist in the range netns, where no guest can reach it. The hardened-container spike proved the no-egress case; this proves the granted case is exactly the allowlist. Run on the m6i.metal devbox, 2026-10-06. `./run.sh` reproduces; `./run.sh down` tears down.*

## Verdict

**Scoped egress holds in a booted range, first try: 8/8 checks, enforced-ready in 50.1 s.** The range container gets an uplink (`eth0` on a static-subnet compose network simulating the internet, with an upstream host at `198.51.100.7` listening on both 443 and 80); the corp segment allows `198.51.100.7:tcp/443` and `0.0.0.0/0:udp/123`; the attacker sits on the same segment with `egress: none`.

## What the battery proved

| Check | Construct |
|---|---|
| E1 workstation→443 completes (full handshake out and back) | the allowlisted flow NATs out through the netns |
| E2 workstation→80 dropped, listener up | **exactly the allowlist**: same host, unallowed port |
| E3 attacker→443 dropped | **the attacker override**: `egress: none` composes ahead of the network allowlist |
| E4 `udp dport 123` live in the netns ruleset | the `0.0.0.0/0:udp/123` entry realized |
| E5 masquerade live on the uplink | NAT follows the filter verdicts |
| E6 attacker↔workstation ping | same-segment L2 untouched by egress policy |
| E7 workstation's default route is `10.90.10.1` | the allocator-reserved hypervisor gateway on the bridge |
| E8 zero range bridges in the host netns | host invisibility unchanged (the uplink is the container's own eth0) |

## Realization notes

- Enforcement lives in the range container's netns, not on any guest: an agent that roots every VM still cannot widen egress (consistent with the hardened-container finding that the netns, not the router, is the external containment authority).
- The one exception to "bridges carry no IP": a routerless `mode: nat` network's bridge is its gateway and carries the reserved address. Isolated segments keep the hypervisor unaddressable.
- The egress-granting range container keeps a Docker network (its uplink), unlike the `network_mode: none` production default for no-egress ranges; deployment chooses the uplink.
- Gated forms behave as designed: the [egress-allowlist draft fixture](../../inspect-ranges/ranges-v0.2-drafts/egress-allowlist.yaml) now fails with exactly `egress-fqdn-not-realized` on its FQDN line (CIDR entries validate), and `egress-with-router-not-realized` rejects the router-attached combination until the plan stage formalizes it.

## Files

- `spec.yaml` — the v0.2 NAT allowlist spec (validates green)
- `compile.py` — production stages for allocation + NAT gateway election + the netns egress ruleset; spike glue for seeds/bridges/boot
- `compose.yaml` — range + upstream on a static-subnet simulated internet; `ip_forward` via sysctls
- `range/` — entrypoint extended to put the reserved gateway address on nat bridges
- `run.sh` — validate, compile, boot, the 8-check battery
- `tmp/run1.log` — the clean first-try run

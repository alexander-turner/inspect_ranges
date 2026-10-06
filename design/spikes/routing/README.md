# Spike: routing conformance — the booted battery for networking-v0.2 §2

*The lockstep conformance leg for slice 3 of [networking-v0.2](../../inspect-ranges/networking-v0.2.md): `gateway:` election and `routes:` live in the schema with their validators (`ambiguous-gateway`, `undeclared-gateway`, `unreachable-route`), election is a production compiler stage (`inspect_ranges._compiler.elect_gateways`), transit-router ACL endpoints relax from attachment-checked to reachability-checked, and this spike proves the chained topology on the wire. Machinery carried from [acl-v2](../acl-v2/README.md). Run on the m6i.metal devbox, 2026-10-06. `./run.sh` reproduces; `./run.sh down` tears down.*

## Verdict

**The routing model holds in a booted range, first try: 9/9 checks, 5 VMs across 3 chained segments enforced-ready in 50.8 s.** The spec is the chained-routers shape from the design round: `dmz — r1 — core — r2 — vault`, with the shared core segment declaring `gateway: r1` and static routes on both routers.

## What the battery proved

| Check | Construct |
|---|---|
| R1 agent→safe:443 refused-fast | **the two-hop path**: static routes on both routers, both ACLs accepting, stateful return across two hops |
| R2 agent→safe:22 dropped (sshd listening) | default deny holds across the chain |
| R3a app's default route is `via 10.80.20.1` | **gateway election**: explicit `gateway: r1` on the two-router core segment |
| R3b app→agent ping succeeds | election is functional, not just configured (r1 allows core→dmz icmp; r2 would drop it) |
| R4 safe→agent:22 dropped despite listener | reverse-chain default deny |
| R5 `10.80.30.0/24 via 10.80.20.2` live on r1; mirror on r2 | `routes:` realized in the guests' kernels |
| R6 `ip saddr 10.80.10.0/24` in r2's ruleset | **transit rendering**: a routed (unattached) ACL endpoint compiles to a subnet match |
| R7 zero range bridges in the host netns | host invisibility unchanged |

## Progress marker

With slices 1–3 landed, three of the four design-round acceptance fixtures validate green (`chained-routers`, `cage-nacl`, `mhbench-acl-lossless`); `egress-allowlist` waits on slice 4 (`egress:` allowlists).

## Files

- `spec.yaml` — the chained three-segment v0.2 spec (validates green)
- `compile.py` — production stages for allocation + election + rulesets; spike glue for seeds (router netplan carries the static routes), bridges, boot
- `run.sh` — validate, compile, boot, the 9-check battery
- `compose.yaml`, `range/` — carried unchanged from acl-v2
- `tmp/run1.log` — the clean first-try run

# Spike: ACL v2 conformance — the booted battery for networking-v0.2 §1

*The lockstep conformance leg for slice 2 of [networking-v0.2](../../inspect-ranges/networking-v0.2.md): the schema and semantic validation live in the package (`inspect_ranges.types`), allocation and the router ruleset come from the production compiler (`inspect_ranges._compiler`: `allocate`, `render_router_nftables`), and this spike proves the rendered policy on the wire. Seeds, bridges, and the boot plan are spike-grade glue carried over from [net-compile](../net-compile/README.md). Run on the m6i.metal devbox, 2026-10-06. `./run.sh` reproduces (needs the net-compile guest image once); `./run.sh down` tears down.*

## Verdict

**Every ACL v2 construct holds in a booted range, first try: 11/11 checks, enforced-ready in 49.5 s.** The spec (`spec.yaml`, schema v0.2) exercises the full vocabulary on one router: an ordered `deny` carve-out ahead of a broader allow, a guest source endpoint resolved to its allocated address at plan time, a CIDR `/32` source endpoint, `icmp`, and the unchanged v0.1 default-deny stateful baseline.

## What the battery proved

| Check | Construct |
|---|---|
| B1 agent→db:5432 refused-fast | network-endpoint allow, routing, stateful return |
| B2 agent→db:22 dropped (sshd listening) | **first-match: `deny` carve-out beats the later `tcp/22` allow** |
| B3 web→db:80 refused-fast; agent→db:80 dropped | **guest endpoint admits exactly its guest** (plan-time address resolution) |
| B4 agent→db ping | `icmp` realization (`meta l4proto icmp`) |
| B5 agent(10.80.10.2/32)→db:8080 refused-fast; web dropped | **CIDR endpoint specificity** |
| B6 db→web:22 dropped despite listener | default-deny asymmetry unchanged |
| B7 agent→web ping | same-segment L2 intact |
| B8 zero range bridges in the host netns mid-run | host invisibility unchanged |
| B9 `tcp dport 22 drop` + `policy drop` live on the router | the rendered ruleset is the running ruleset |

## Production pieces this validates

- `inspect_ranges._compiler.allocate`: deterministic addressing (router `.1`, attacker `.2`, hosts from `.10`, explicit IPs claimed first), content-derived MACs, spec-ordered CIDs — the B3/B5 checks depend on the allocator landing the attacker on exactly `10.80.10.2` and db on `10.80.20.10`.
- `inspect_ranges._compiler.render_router_nftables`: ordered first-match rendering with per-endpoint-form matches (interface names for networks, allocated-address matches for guests, address matches for CIDRs, no match for `0.0.0.0/0`), `deny` → `drop` in place.
- `inspect-ranges validate` accepts the v0.2 spec and rejects the malformed variants (unit-tested per code in `tests/test_diagnostics.py`).

## Files

- `spec.yaml` — the v0.2 conformance spec (validates green)
- `compile.py` — production stages for allocation + ruleset; spike glue for seeds/bridges/boot
- `run.sh` — validate, compile, boot, the 11-check battery
- `compose.yaml`, `range/` — carried unchanged from net-compile
- `tmp/run1.log` — the clean first-try run

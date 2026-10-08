# Spike battery: the shared conformance runner (realizer-v1 slice 4)

*The five networking conformance batteries (acl-v2, routing, egress, netsvc, routed) run against realizer-booted ranges through one shared runner: each spike's unchanged `spec.yaml` rendered at CID 3000+, applied with `inspect-ranges up` under the hardened image and v3 Go-daemon goldens, checked over the channel client by guest name, torn down with `down`. This retires each spike's private apply glue (their `run.sh` harnesses remain as historical reference) and is the regression harness the channel track's slice 7 re-points its conformance at.*

*Reproduce: `./run.sh` (all five, 43 checks; `only=<name>` runs one; `./run.sh down` sweeps). Needs the noble vendor image in the shared cache, the pinned Go toolchain for `daemon-bundle`, and docker. Serializes on the shared battery lock; state isolated via `XDG_STATE_HOME`. First full run: 43/43.*

## What each section proves

- **acl-v2** (A1-A9): the ACL v2 vocabulary on the wire: ordered deny carve-outs, guest and CIDR endpoints, icmp, default-deny asymmetry, the rendered ruleset live on the router, host netns invisibility.
- **routing** (R1-R7): two-hop allowed paths and default deny, declared and functional gateway election, static routes live on both routers, transit subnet matching.
- **egress** (E1-E8): the scoped NAT allowlist exactly (allowlisted flow completes, everything else drops, attacker override), udp entry and masquerade live in the range netns, the harness-supplied uplink network (`ensure_uplink` runs the upstream listener container).
- **netsvc** (N1-N8): reservation-only DHCP delivering exactly the allocated addresses, derived and explicit range DNS records, resolver handout (range service, authoritative plus external ordering), isolation without a router.
- **routed** (T1-T7): two-way un-NATed egress: real source addresses observed upstream, ingress reaching an in-guest listener (started over the channel; v3 goldens carry no listeners), attacker override, zero masquerade.

## Files

- `run.sh` — the runner (shared setup once: daemon-bundle artifact, one v3 golden named `noble-range-guest` as the specs reference)
- checks live inline, keyed by guest NAME via `design/spikes/_shared/chexec.py --boot <bundle>/boot.json`

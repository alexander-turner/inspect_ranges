# Spike: bundle conformance — the realization bundle applied end to end

> **Retired to reference (2026-10-08):** `apply.sh` was the spike-grade applier; the production path is `inspect-ranges up` ([realizer-v1](../../inspect-ranges/realizer-v1.md), batteried in [up-core](../up-core/README.md)). This spike's render-contract findings and tamper-refusal battery remain the historical record.


*The conformance leg for the ResolvedPlan/render stage (architecture.md §14; host-provider.md "render → apply"): `inspect-ranges render` emits a digest-manifested realization bundle, and a generic applier realizes a range **purely from bundle contents** — the deployment seam's self-sufficiency rule made executable. The applier here is spike-grade but is the specification for the production `apply` stage (provider phase). Run on the m6i.metal devbox, 2026-10-06. `./run.sh` reproduces; `./run.sh down` tears down.*

## Verdict

**The bundle path works end to end, under the hardened container profile: tamper-refusal, then render + apply to enforced-ready in 47.3 s, then 13/13 combined battery checks** (ACL v2's deny carve-out, guest and CIDR endpoint specificity, icmp; DHCP reservation exactness; derived and explicit range-served records; host invisibility). The spec is deliberately combined coverage, and nothing at apply time touches the repo's compiler: the applier consumes `manifest.json`, `compose.yaml`, `netns/*`, `guests/*/domain.xml`, `guests/*/seed/*`, and `boot.json`, verbatim.

## What the battery proved

| Check | Property |
|---|---|
| B0 `inspect-ranges render` | 25-file bundle, digest manifest, byte-deterministic (unit-tested) |
| B1 one flipped byte → applier refuses before acting | the seam's verify-then-act rule |
| B2 apply from bundle contents only, 47.3 s to ready | self-sufficiency: zero driver round trips after render |
| B3–B7 the ACL v2 battery | plan-resolved endpoints realized through the bundle |
| B8–B9 DHCP exactness + records | the dnsmasq stage realized through the bundle |
| B10 zero range bridges on the host | invisibility under the bundle's hardened compose |

## Findings with design consequences

1. **The capability floor widens measurably with services, and render now owns that decision**: dnsmasq failed under the eight-capability hardened floor first on `NET_RAW` (DHCP raw sockets), then on `NET_BIND_SERVICE` (binding 53/67). The rendered compose adds `NET_BIND_SERVICE` when any network serves dnsmasq and `NET_RAW` only when DHCP is served — each by observed failure, in the hardened-container spike's methodology. The earlier netsvc spike missed both because it ran the prototype (additive-caps) profile.
2. **This is the first battery run entirely under the hardened profile with range services on** (dnsmasq alongside libvirtd), at no measured cost (47.3 s vs ~45–50 s across the service spikes).
3. **Honest residue**: the spike's range image still carries the prototype `qemu.conf` (QEMU as container root); the hardened non-root-QEMU image configuration is production-applier work (provider phase), where the hardened-container spike's `range/` is the template.

## Files

- `spec.yaml` — the combined-coverage v0.2 spec (validates and plans green)
- `apply.sh` — the generic applier: manifest verification (refuse on mismatch or unlisted files), compose up on the bundle's own project, guest boot from `boot.json`, readiness waits
- `range/` — the range image the bundle's compose references (`inspect-ranges-range:dev`); entrypoint realizes `netns/*` per the render contract
- `run.sh` — render via the production CLI, tamper check, apply, the 13-check battery
- `tmp/run3.log` — the clean run

---
type: decision
title: "Range build: the manifest between topology and working challenge, and the checkpoint artifact"
status: accepted
tags: [inspect-ranges, build, images, checkpoint, provisioning, decision]
timestamp: 2026-10-04
---

# Range build: the manifest between topology and working challenge, and the checkpoint artifact

*Decision record, prompted by [external review](external-review.md) findings 4 and 5. The gap it fills: the documents defer guest provisioning while depending on prepared images and converged AD snapshots, leaving no named, reproducible artifact that turns a `range.yaml` into a working challenge. An individual VM image is not that artifact — a range's meaning includes domain membership, shared credentials, service dependencies, and planted vulnerabilities, none of which live in any single disk. The [schema v0.1 scope](schema-v0.1-scope.md) deferral of a general provisioning language stands; what cannot be deferred is a minimal build contract.*

## The split

**Build time** (per range version, expensive, cached): resolve logical images to digests, derive goldens, boot the range, run provisioning to convergence (AD promotion, joins, service setup, vulnerability planting), verify, and capture. The [ad-domain spike](../spikes/ad-domain/README.md) measured why this must be build-time: specialize 208 s, promotion 177 s, join 20 s per member — minutes of convergence that restore from snapshot in seconds.

**Run time** (per sample, cheap, from the manifest): instantiate from the captured artifacts, then apply only narrow per-sample setup — fresh proof secrets ([scoring-integrity](scoring-integrity.md)), clock correction, identity-preserving randomization explicitly declared by the range. Nothing structural happens per sample.

## The range build manifest

A versioned document, produced by the build and consumed by the runtime, containing:

- **Identity**: range name, schema version, spec content hash, manifest version.
- **Resolved inputs**: every image as a content digest (never a logical name), provisioning recipe versions, the topology allocation (the compiler's resolved plan: addresses, MACs, CIDs, generated names).
- **Captured artifacts**: per-guest disk references (digests) and, where captured, the checkpoint bundle (below), with the host-compatibility statement (CPU model, QEMU/libvirt versions).
- **Verification results**: the build's conformance evidence — range-ready reached, containment conformance passed, the challenge's behavioral checks (reference solution passes, insufficient attempt fails, oracle shortcuts fail) with timestamps.
- **Reproducibility inputs**: recorded seeds for any topology randomization. **Never secrets** — proof material (flags, canaries, principal-bound secrets) is generated per sample from independent entropy and recorded only at the evidence sink.

A runtime refuses to instantiate from a manifest whose digests it cannot verify or whose compatibility statement its host does not satisfy. Examples remain *translated requirements fixtures* until they pass a build and carry a manifest.

## The checkpoint artifact

`virsh save`/`restore` against a live disk proves suspend/resume, not fresh cloning: memory and disk state must correspond, and restoring memory against a changed disk corrupts the guest. The checkpoint is therefore a **bundle**, captured at the converged point:

- per-guest disk overlay copies taken at the save instant (the save stops the domain, making disk and memory consistent),
- the memory image,
- the domain XML (so instantiation does not depend on the defining host's libvirt state),
- for multi-guest ranges, all guests captured at the same quiesce point (saves are serialized after range convergence; inter-guest protocol state, e.g. Kerberos tickets, tolerates the seconds of skew — verified in the ad-domain spike by the post-restore secure-channel check, to be re-verified by the checkpoint-clone spike).

Each sample instantiates **fresh copies** from the bundle (overlay-on-bundle, never the bundle itself), restores, pushes host time via `guest-set-time`, and plants per-sample secrets. Previous samples' execution leaves nothing: their overlays are destroyed with their range.

**Portability**: the spikes use `-cpu host-passthrough`, which libvirt cannot compatibility-check across hosts; a checkpoint built on metal is not automatically restorable on another instance family. Checkpointed ranges use a named CPU model chosen per fleet (the checkpoint-clone spike tests this); the manifest records it, and `doctor` can check a host against it.

## Boot ordering is a dependency graph with health gates, mostly paid at build time (added 2026-10-05)

A reviewer (from Proxmox-provider experience) flagged that "boot all guests in parallel" fails for ranges with cross-guest provisioning dependencies, which needed a dependency graph plus healthchecks there. Correct, and the build/runtime split is the structural answer: dependency-ordered, convergence-gated orchestration runs **at build time** (the [goad-forest spike](../../spikes/goad-forest/README.md) is the demonstration: DC promoted and polled to convergence before the child domain promotes, child converged before the member joins), and the converged result is captured, so **per-sample startup is a parallel restore** with no ordering problem to solve (measured: 3 s for the AD pair, 48 s for the four-VM forest, trust and secure channels intact). For non-checkpointed ranges, parallel boot with per-guest readiness gating is measured fact (net-compile's 4-VM range; boot-storm's 96 VMs), and readiness already requires *every* guest's provisioning to complete before the range is ready. What the sequencer still needs when the deferred provisioning sections land in the schema: explicit dependency edges in the resolved plan (provision-after relationships with per-guest health conditions), applying to build-time orchestration always and to runtime first-boot ranges whose provisioning crosses guests. One assumption to retire with a test: checkpoint restores have so far been serial, DC first, by convention; restore-order tolerance is assumed rather than proven.

## Config injection is a per-image capability, not a guest requirement (added 2026-10-05)

A reviewer flagged that requiring cloud-init on every guest would over-constrain the ranges worth building (old vulnerable distros, appliances, and Windows mostly lack it). Agreed, and the architecture does not require it: the compiler emits each guest's desired configuration; *how it reaches the guest* is declared per image, and cloud-init is one injector among several. The menu: cloud-init seed (cloud-style Linux, the spike default), config baked at build via `virt-customize` (any Linux, no agent), unattend + qemu-ga (Windows — the entire AD path runs cloud-init-free, per the ad-domain and goad-forest spikes), DHCP reservation from a range-controlled server (`dhcp: true`; appliances and images that cannot be modified), or a pre-configured checkpoint (anything; the production default for complex ranges, where per-sample instantiation needs no boot-time config at all). The build manifest records which injector each image uses; the only in-guest component the runtime itself wants is the baked-in control daemon, and an image that cannot carry even that degrades to build-time-configured and externally observed, which the [scoring-integrity](scoring-integrity.md) trusted tiers already price in.

## What this does not decide

The provisioning language itself (how recipes are expressed — Ansible, scripts over the control plane, declarative sections in a later schema) stays deferred per schema-v0.1-scope. This record only fixes the boundary: whatever the recipes are, they run at build time, their versions land in the manifest, and the runtime never runs them.

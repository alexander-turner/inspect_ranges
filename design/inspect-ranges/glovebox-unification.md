# Position note: glovebox unification requests (PR #15)

Status: analysis for the pre-launch meeting, 2026-10-23. Not a decision record; decisions here are the maintainer's.

## The ask

The glovebox maintainer (the reviewer who contributed the Cloud Hypervisor agent-box change) proposes technical unification up to `provider: glovebox` on the attacker box, argued on three grounds: containment depth (L7 egress via Envoy, an in-guest execve witness off the kernel process connector), timing (APIs are cheap to move before launch; glovebox is merging into Hawk, so many Inspect consumers will run on it), and maintenance (glovebox already runs the CVE-tracking treadmill for Cloud Hypervisor, Envoy, kata, and the kernel, with CI gates and signed pinned images). Draft PR #15 ("RFC: opt-in provider: glovebox (externally-provided agent box)"): +1,518 lines over 12 files, including a 674-line `_host/glovebox.py` connector in-tree, schema surface on `types.py`, and compiler, applier, and provider touches.

## Claim assessment

- **L7 egress (accurate, no current consumer).** The L3/L4-vs-L7 analysis is correct and networking-v0.2 already concedes it: FQDN egress entries are in the vocabulary, gated `egress-fqdn-not-realized`, citing inspect-glovebox as the precedent. But the motivating policy ("allow GET to api.openai.com") solves agent-reaches-model-API, which Ranges does not have: Inspect relays model calls natively, API traffic never crosses the range, and every example runs `egress: none`. When a range genuinely needs agent internet egress, an Envoy-style gateway is a candidate realization of the reserved FQDN vocabulary, and glovebox could be one implementation. Demand-gated; the reopening condition is a real range needing agent egress.
- **execve witness (good idea, adoptable without the dependency).** A per-exec stream from the guest's top-level namespace is a vsockd feature plus one more evidence stream. It fits evidence-v1's poll-based posture (upgrades the timeline, not the source) and the scoring-integrity assurance tiers (his own caveat, guest root can tamper, is the declared-lower-assurance framing). Adopt natively, credit him.
- **Hardening credibility (earned, and the working model is cherry-picking).** The Cloud Hypervisor change was a win taken as a specific improvement, not a dependency. That is the pattern to continue.
- **Maintenance (real, but the trade is not free).** Adopting glovebox trades visible CVE-tracking work for governance risk you cannot see: "merging into Hawk soon" and "soft commitment from Neolithic" describe a project mid-reorganization, the wrong moment for a hard dependency.

## The PR, and the right-sized seam

PR #15 is the dependency shape to decline: a vendored glovebox connector inside `_host/`, maintained in this repo, with schema surface. But the obvious counter (the `INSPECT_RANGES_HOST` HostBackend seam) is also wrong-sized for his ask: that seam is all-or-nothing at the host level, so an attacker-only substitution through it would force glovebox to reimplement libvirt ranges wholesale. The PR's own file layout sketches the narrower seam that fits: render/plan changes are segment attachment, applier changes are the handoff, the provider change is exec routing for one guest.

The meeting position: **a generic per-attacker seam, implemented out of tree.** The range supplies an L2 attachment point on the foothold's segment and the sandbox exec surface for that one guest; an external provider supplies the VM behind both, registering like HostBackend does (protocol plus env-var or entry-point registration), with glovebox's package as the first implementation. The contract is proof obligations, not plumbing:

- The conformance sweep and the foothold wall must hold against the foreign box (the battery runs per substrate, owned by whoever owns the substrate; a published backend-conformance suite makes this "meet the bar anyone must meet" rather than "trust glovebox").
- Readiness semantics and teardown ownership defined; the reaper story intact.
- Evidence honesty: segment pcap and beacon corroboration survive (bridge-side), the console stream for a guest we do not run is lost and must be recorded as a declared capability drop, never silently absent.

## Recommended outcomes

1. Take the meeting before launch; he is a proven contributor and the timing point is right, aimed at the right API.
2. Decline the in-tree connector; offer the per-attacker seam design (out-of-tree registration, proof obligations attached) with his PR as the demand evidence and sketch.
3. Pre-launch API-stability pass on the published seams (HostBackend/Transport now, the attacker seam if designed), with him as the first external consumer.
4. Adopt the execve-witness concept natively in vsockd as an evidence stream, with attribution.
5. L7 egress stays parked behind `egress-fqdn-not-realized` with the named reopening condition.
6. Any PR response from an agent goes as a Comment, flagged as AI and not a maintainer, per the house rule.

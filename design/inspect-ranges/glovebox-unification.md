# Position note: glovebox unification requests (PR #15)

Status: analysis for the pre-launch meeting, 2026-10-23. Not a decision record; decisions here are the maintainer's. The seam sketched in "The seam, named" is designed and built as [attack-box-v1](attack-box-v1.md).

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

## The seam, named

**`AttackBoxProvider`**, registered as `INSPECT_RANGES_ATTACK_BOX=<module>.<factory>[:<config>]`, mirroring `INSPECT_RANGES_HOST` exactly: the value is the registration, persisted as the boot's origin so the reaper re-resolves teardown from disk. A factory bundle (`AttackBoxBackend`) carries the provider plus the optional doctor probe and reaper connector, the HostBackend shape. The compiled plan hands the provider a `FootholdAttachment` (the tap handle in the range netns, the allocated MAC and IP, the segment); the provider returns the one guest's exec surface and owns its lifecycle. "Attack box" is the right scope word: assumed-breach ranges have no attack box (their foothold is a content guest this project builds and captures), so the seam excludes them by construction; `FootholdProvider` would wrongly imply it covers them.

Two decisions attach to the name. First, provider selection is deployment knowledge, never `range.yaml` (the collectors.yaml precedent: poll mechanics stay out of the schema), so the same published spec hash runs on the default realizer or on glovebox with no semantic edit; PR #15's schema field is the wrong layer. Second, the published acceptance suite is the **attack-box conformance battery**: the foothold wall holds, the attacker-surface sweep is clean, the exec surface passes the existing `self_check` suite (the 44-check battery already ships and is the parity bar), readiness and teardown behave, and evidence drops are declared. A provider boots when it passes; that sentence is the whole governance story.

## Cost and risk

**Our-side work, roughly a one-to-two-week slice** (narrower than range-host-v1, with most machinery reusable): the boot plan marks a dedicated attack box external and skips booting it; attachment construction on the segment bridge; the provider's exec surface routed behind the sandbox for that one guest; readiness delegation; origin persistence and reaper reclaim (the generic machinery extracted for host backends reuses directly); a declared-capability-drop record in evidence for the missing console stream; the conformance battery assembled mostly from existing pieces (`self_check`, the attacker-surface sweep, wall probes); tests over the LocalEndpoint harness; docs and the decision record. Two adversarial review rounds per house discipline on top. The glovebox side seeds from their PR's own 674-line connector, moved into their package.

**Technical risk, ranked:**
1. **The netns invariant is the one genuinely tricky piece.** Today the host netns carries zero range state while a range runs; a glovebox cell is a foreign VMM process on the host needing a NIC inside the range container's netns. The attachment must be built so the invariant survives (tap created inside the range netns with the fd passed to the external VMM, never a bridge leg in the host netns). Cloud Hypervisor accepts tap fds, so this is feasible, but it is load-bearing security plumbing and the place a review round should camp.
2. **Exec-surface semantic parity.** Subtle differences (budgets, `user=`, truncation, signal exits) break checks and scorers quietly; mitigated by making `self_check` part of the battery, which is exactly what it was built for.
3. **Containment becomes a two-stack property.** The battery proves point-in-time behavior, not architecture; the honest posture is that a range with an external attack box carries the weaker of the two containment stories, stated in docs, with the battery as the floor.
4. **Lifecycle races across two owners** (interrupt mid-boot, reaper vs provider teardown); the origin-persistence pattern plus deny-first classification already encode the house answers.
5. **Seam stability pre-1.0.** Keep the protocol minimal (attachment in, exec surface and lifecycle out); every method added is API someone freezes against.
6. **Scope creep.** Pressure will arrive to extend the seam to content guests and routers; refuse by construction, since those carry built, verified content the external substrate cannot reproduce.

Implementation risk is low to moderate; the real risk budget is items 1 and 3, and both are policy-plus-review problems more than code volume.

## Recommended outcomes

1. Take the meeting before launch; he is a proven contributor and the timing point is right, aimed at the right API.
2. Decline the in-tree connector; offer the per-attacker seam design (out-of-tree registration, proof obligations attached) with his PR as the demand evidence and sketch.
3. Pre-launch API-stability pass on the published seams (HostBackend/Transport now, the attacker seam if designed), with him as the first external consumer.
4. Adopt the execve-witness concept natively in vsockd as an evidence stream, with attribution (deferred work, below).
5. L7 egress stays parked behind `egress-fqdn-not-realized` with the named reopening condition.
6. Any PR response from an agent goes as a Comment, flagged as AI and not a maintainer, per the house rule.

## Deferred work: the execve witness (added 2026-10-23)

The one piece of PR #15 worth adopting natively is deliberately not scheduled yet. The concept: vsockd subscribes to the kernel process connector (or an equivalent in-guest source) and ships an exec-event stream (`exec/<guest>`: pid, ppid, uid, argv, timestamp) as an ordinary evidence stream, giving scorers and reviewers a per-guest process timeline that corroborates what the pcap and consoles can only imply. Attribution to the glovebox PR travels with the implementation.

Why deferred rather than batched into current work: it is its own slice, not a rider. It changes the daemon (a new subscription loop, a new wire record type, backpressure under exec storms), which re-digests the daemon bundle and therefore re-keys and re-derives every golden; a change of that cost wants to share a rebake with other golden-touching work and carry its own conformance additions (mock-channel records, Windows posture stated, the evade interaction considered, since a process witness on a target is exactly what a stealth goal's agent is trying not to trip). Revisit at or after the glovebox meeting, where the seam discussion settles whether the witness also needs to be part of the attack-box conformance bar.

Scheduled: the slice is designed and under construction as [execve-witness-v1.md](execve-witness-v1.md), which supersedes the parameter list below (kept as the decision trail).

Slice parameters settled 2026-10-23 (user discussion, ahead of the design record):

- **Record-only v1.** No goal type and no `corroborate()` path reads the stream, so no existing range's score can move; wiring it into `execute`-goal corroboration or evade semantics is a separate, score-changing decision with its own amendment.
- **Linux-first is acceptable because the foothold is a Linux box on every range** (the Windows examples' attack box is the catalog image), so the agent's own exec stream is captured everywhere; only the Windows *target-side* witness is missing, recorded as a declared capability drop. The committed Windows v2 path is 4688 process-creation auditing with command-line capture shipped from the Security log, deliberately its own design pass because enabling global process auditing changes the scenario's defensive surface (on detection-class ranges the telemetry configuration IS the scenario).
- **Lazy-arm is the containment spine**: the subscriber starts only when the host first polls the new verb, so builds (the worst fork-storm case) never activate it and the field kill switch is a host-side setting, never a golden rebake.
- **The fork-storm battery gates on numbers, not completion**: ping/exec round-trips inside existing budgets during a sustained storm, zero listener restarts, floods absorbed by the bounded ring's drop counter (recorded as gaps) rather than memory.
- Mixed-version host/daemon handling deliberately out of scope (pre-release, no deployed consumers).

The remaining parked question (does the witness join the attack-box conformance bar) is settled 2026-10-23: it does, as must-serve; the decision and its reasons live in [attack-box-v1](attack-box-v1.md).

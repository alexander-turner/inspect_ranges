---
type: decision
title: "Attack-box provider seam: a deployment-registered external supplier for the dedicated attack box, held to a published conformance battery"
status: accepted
tags: [inspect-ranges, attack-box, provider, seam, containment, decision]
timestamp: 2026-10-23
---

# Attack-box provider seam: a deployment-registered external supplier for the dedicated attack box, held to a published conformance battery

*Decision record. Demand evidence and the declined shape are PR #15 (the glovebox maintainer's RFC: an in-tree `provider: glovebox` connector with `range.yaml` schema surface, proven end to end on a live range); the position analysis is [glovebox-unification](glovebox-unification.md). This records the seam as designed and built: the range supplies an L2 attachment point on the foothold's segment and routes the attacker's exec to the surface the provider returns; an external provider supplies the VM behind both and owns its lifecycle; the contract is proof obligations (the battery), not plumbing trust.*

## Decision

**`AttackBoxProvider`, registered as `INSPECT_RANGES_ATTACK_BOX=<module>.<factory>[:<config>]`, mirroring `INSPECT_RANGES_HOST` exactly** (`_host/backend.py` is the pattern): the variable's value is the registration, imported and called at resolution, and persisted verbatim as the project's attack-box origin (`attackbox.json`, the owner-record discipline) so any process re-resolves teardown from disk alone. The factory returns an `AttackBoxBackend` bundle: the provider (`boot(attachment) -> handle`; idempotent `teardown(project, reclaim_token)`), an optional teardown-by-origin reclaim connector (default synthesized from `provider.teardown`), an optional doctor probe, and declared capabilities. Protocols public in `inspect_ranges.attackbox`. Code: `src/inspect_ranges/_attackbox/`.

Scope is dedicated attack boxes only, by construction: an assumed-breach foothold is a content guest this project builds and captures, so a foothold range realizes normally with one INFO line. Pressure to extend the seam to content guests and routers is refused for the same reason: they carry built, verified content the external substrate cannot reproduce.

### Selection is deployment knowledge, never `range.yaml`

The spec carries no provider field (PR #15's schema surface was the wrong layer; the collectors.yaml precedent). `boot.json` gains only descriptive plan facts: every entry's `kind`, and the attacker's sizing plus per-interface `network`/`ip`/`prefixlen`/`gateway`, emitted unconditionally so the same published bundle digest realizes identically on the default realizer or an external provider with no re-render. The variable is consulted where `up()` runs: the driver on the co-resident path, the applier (its own environment) on the separated path. The build path pins it off: proof boots run on the range the build captures, never on a foreign box.

### The attachment is a tap fd, by construction

The invariant (architecture.md: the host netns carries zero range state while a range runs) survives structurally, not by review: a verbatim in-container helper (the capture-supervisor pattern, the boot script's compose-exec transport) `TUNSETIFF`s one non-persistent tap per attacker interface inside the range netns, applies the libvirt `fe:` tap-MAC rule before enslaving to the segment bridge, and ships the open fds to the realizing process over `SCM_RIGHTS`; the provider receives `FootholdAttachment` (project, guest name, CID as a pure addressing token, sizing, per-interface tap fd + allocated MAC/IP facts, optional seed dir) and owns the fds from `boot` on. The fd is the tap's lifetime (and the netns bounds it regardless); teardown order in `down` reclaims the provider's VMM before the netns, so the box never outlives its NIC. Taps carry `IFF_VNET_HDR`, matching what QEMU and Cloud Hypervisor request themselves. A veth or bridge leg in the host/node netns (PR #15's stitch, the l2-attach spike's helper) is exactly what this construction exists to avoid. This is also why fd-passing is not a style choice: today's attack box receives a tap *name* and resolves it only because the VMM shares the netns; an external VMM cannot.

### The exec surface is the hybrid-vsock shape, held to the wire protocol

`boot` returns a `HybridEndpoint` (unix socket + expected peer uid, `SO_PEERCRED`-enforced at every dial) serving the Cloud Hypervisor hybrid-vsock preamble (`CONNECT <port>` / `OK <port>`) then the daemon wire protocol, one request per connection. This rides shipped plumbing end to end (readiness channel, `GuestState.hybrid_vsock`, the provider's `guest_sockets`, the applier's relay and `_ch_sockets`) with no new routing code and no public relay-registration API: the CID stays the external box's addressing token. Readiness holds the box to daemon liveness (ping) through `up`'s existing strict loop, failing the boot with per-guest diagnostics (the strict-fail contrast with PR #15's log-and-serve-dead-sandbox); the battery holds the deeper bar. Holding the provider to the wire protocol rather than a Python object is what makes inspect-ai's sandbox `self_check` suite the parity bar verbatim, and turns PR #15's assurance holes (stdout-sentinel rc forgeable by the in-cell agent, no `command_ms` enforcement, no process-tree kill) into battery obligations instead of review promises.

### Teardown is deny-first through `down`

`down()` reads `attackbox.json` before touching any compose resource and resolves the origin first (the reaper's rule): an unresolvable origin or a failed provider teardown refuses the whole teardown with the remedy named, because killing the netns strands a live foreign VMM. On success the record clears; a second `down` is a no-op. The reaper needed no changes (both lease-origin paths end in `down()`); the standing sentence extends to two origins: the provider's package must be installed where the reclaiming process runs. `up` writes the record before the provider boots (crash-window discipline) and, inside its own failure path, attempts the idempotent provider teardown directly.

### Evidence: the console is a declared drop

The provider's box produces no console file; before this slice the stream would simply not exist (no chunks, no gap, no seal entry) and the `hijack` goal's corroboration would downgrade opaquely. Now `CaptureStreamer` records one in-chain gap (`console-external-attack-box`) on `console/<guest>` at start and never polls the guest, so the absence is verifiable offline; doctor carries a standing warn. Segment pcap and beacon corroboration are untouched by construction (bridge-side capture sees the foreign box's frames). `capabilities.console_stream=True` is refused as unimplemented: there is no ingest path, and claiming the capability without one would be the silent degradation the evidence posture forbids.

### The battery is the governance story

`inspect-ranges attackbox verify --spec <range.yaml>` realizes the spec through the registered provider and holds the obligations as report rows: capabilities declared honestly; realize (attach, boot, strict readiness through the real `up`); foothold-reach (the box HOLDS its reserved address, probed from the shared-segment defender before the sweep, because an L2-absent box also answers the sweep with silence, by ARP timeout, which lies about the obligation and burns the exec budget: measured); the attacker-surface sweep against the foreign box (`run_conformance_checks` reused unchanged, its first live-range entry point; previously it ran only inside the build's proof boot); daemon-session stability across dials; exec parity (the full `self_check` suite, EMPTY xfail pin: the live box is where CI pins evaporate); teardown (box reclaimed before the netns, record cleared, re-dial refused, second down a no-op). Every obligation lands as a row, never an abort, and the battery leases its CID block from the shared registry so it coexists with live ranges on the host (a fixed base collided with a running eval, measured). A provider boots when it passes; that sentence is the whole governance story. The canonical battery spec is `dmz_pivot` (dedicated attack box, Linux defender sharing its segment).

Proven live (2026-10-23, this devbox, dmz_pivot through the boot-nothing fake provider): capabilities, realize (the attach helper ran in the real range container, the fds crossed `SCM_RIGHTS`, the external attacker joined strict readiness alongside the booted guests), session-stability, and teardown all green; foothold-reach and attacker-surface honestly FAIL (the fake has no network stack, so it never holds the reserved address: the battery refusing a non-bootable provider is the gate working), and exec-parity fails only `test_exec_as_user` (host-user provisioning, the known CI-host limit). The fake's full CI value is the `self_check` transport kind (44/44 over the production dial path) plus the handoff validation.

## The assurance posture, stated

A range with an external attack box carries the weaker of the two containment stories. The battery proves point-in-time behavior, not architecture; it is the floor, recorded in doctor's standing warn and the docs, never implied away. Exec-surface honesty (exit codes, truncation, budgets) is likewise battery-floor: the surface's operator controls its implementation, which is the same trust position as guest root on a content guest, declared rather than hidden.

## Recorded deviations (as built, 2026-10-23)

- The battery holds exec parity by running inspect-ai's `self_check` programmatically; the pytest-coupled `PortableChannelSuite` (RTT budgets) stays a CI artifact rather than moving into the package. A provider is still held to it in CI via the fake-provider parametrization pattern.
- The hybrid-vsock `CONNECT`/`OK` preamble turned out to be part of the exec-surface contract (the dialer speaks it); it is stated on `AttackBoxHandle` rather than left implicit.
- An explicit `vmm: qemu` dedicated attack box refuses under an external provider (`up`, verify-bundle) instead of the compose mount condition widening: regression safety for existing specs won over the corner case, which has no use (the VMM is irrelevant for a box the realizer never boots).
- Admission still charges the external box's cpus/memory to host capacity, deliberately conservative (same host, same RAM budget pressure from the foreign VMM).
- `FootholdAttachment` omits the spec's attacker image reference: the provider brings its own box and the battery is the equivalence claim.
- The driver on the uds path no longer fabricates `GuestState(ready=True)`: readiness folds from the host's terminal report (behavioral no-op today; honest provenance for a guest the host never reported).

## Review rounds (2026-10-23)

Two adversarial rounds ran per house discipline (one camped on the netns/fd plumbing, one general-correctness across the branch); the netns invariant, injection surface, handoff theft/forgery coupling, MAC rule, and lifecycle ordering were verified sound. Fixed from the findings: the handoff `recvmsg` is now deadline-bounded with a peer-credential accept loop (the 0666 socket is reachable by every in-container uid during the window; a hostile connector could previously wedge `up` forever or at least steal the one accept slot) plus `MSG_CTRUNC` refusal and non-inheritable fds; the attack-box record writes atomically and parses leniently, and present-but-unreadable now REFUSES teardown instead of reading as "no external box" (a torn write would otherwise strand the live foreign VMM, the exact deny-first bypass); `console_stream=True` refuses on the boot path, not only in doctor and the battery; the applier reads the env var inside its error-folding path (a malformed value previously killed the realize task and leaked the admission charge); the separated path's post-`boot` gap allowance covers the attach window plus the provider's boot, which `up` now bounds at its readiness timeout; the evidence call sites read the external guest from the record instead of re-deriving from the ambient env; and the battery's second-`down` probe and custom-state-dir staging were corrected.

## Deferred

- The execve witness (PR #15's one natively-adoptable piece) stays deferred per [glovebox-unification](glovebox-unification.md): its own slice, re-keys every golden, wants a shared rebake; whether it joins the battery's obligations is settled when it lands.
- L7 egress stays parked behind `egress-fqdn-not-realized` with its named reopening condition (a real range needing agent internet egress).
- Entry-point scheme aliases for the registration grammar remain a compatible future addition, as for `INSPECT_RANGES_HOST`.

---
type: document
title: "Decision: Windows/AD v1"
audience: inspect-ranges development
status: accepted
tags: [inspect-ranges, windows, active-directory, goad, attack-range, splunk, phase-plan, decision]
timestamp: 2026-10-19
---

# Decision: Windows/AD v1

*Phase plan for the Windows phase of the ratified arc (phase 4 of the 2026-10-18 sequencing), promoting the two translated Windows fixtures — [goad-light](ranges/goad-light/notes.md) and [attack-range-windows](ranges/attack-range-windows/notes.md) — to built, verified, solved ranges, on the substrate the early spikes proved ([ad-domain](../spikes/ad-domain/README.md), [goad-forest](../spikes/goad-forest/README.md): the full GOAD-light forest built unattended in ~17 min from Server 2022 eval media, cross-domain Kerberos verified, whole-forest restore in 48 s). The exit criterion: both fixtures build from clean caches and their reference chains score through real evals, Windows guests first-class through render/build/provider.*

## Ratified inputs (user, 2026-10-19)

- **Base media is the Server 2022 eval ISO** (cached, spike-proven; GOAD's 2019→2022 deviation recorded as version-independent in the goad-forest spike).
- **Windows artifacts are local-only, recipes-not-images**: the repo ships unattend files and recipes; eval media is fetched from Microsoft per machine; built goldens/realized images live in the local cache and are NEVER published anywhere (the catalog-phase ratification stands). Rebuild-from-media is the transfer mechanism; eval time-boxing makes the rebuild cadence an operational fact of the fixture records. Private off-box storage is deferred pending a decision outside this repo.
- **Both fixtures are in scope** (user choice over the goad-only recommendation): goad-light first (the AD substrate), then attack-range-windows (which brings the Splunk/defense-telemetry tier).
- Standing decisions that bind this phase: cold boot from converged disk checkpoints is the default, memory restore stays an experimental opt-in ([memory-restore-ad](memory-restore-ad.md)); router provisioning lands here if a fixture needs it (linux-examples parked entry 2).

## The slices

**Slice 1: the Windows guest, first-class.** The Windows golden derive path (eval ISO → unattended install → virtio drivers → the Windows control daemon from the bundle's Windows sources → `sysprep /generalize` → golden qcow2, the ad-domain spike's hard lesson baked in), render/up boots Windows clones with per-boot specialization, readiness over the daemon, and the `windows-render-not-supported` gate lifts exactly as far as the proven path. Battery: a Windows guest boots through render/up on the production pipeline, daemon exec answers, teardown clean.

**Slice 2: the Windows build pipeline.** PowerShell recipes through the executor, the verify engine attributing Windows listeners, capture/scrub for Windows overlays, and cross-guest ordered provisioning proven for domain mechanics (declaration-order recipes already run sequentially across hosts; the forest promotion rides that). Battery: a two-guest domain (DC + sysprep'd member join) builds, verifies, captures, and a consumer boots the captured pair with the secure channel intact.

**Slice 3: whole-range converged capture.** The AD-shaped extension: a build whose recipes mutate OTHER guests' state (every domain member changes when the DC promotes) captures ALL guests at one quiesce point after a converge health battery, not just recipe-carrying ones. Battery: the full goad-light forest (root, child with DNS delegation, member) builds and captures; per-sample boots restore the forest with cross-domain auth intact.

**Slice 4: goad-light built, verified, solved.** The flagship fixture end to end like the Linux examples: recipes realize the forest and its seeded attack surface, behavioral trios prove its challenges, a real eval scores the reference chains through the declared foothold. Router provisioning lands here if the fixture's topology demands it (the parked plan).

**Slice 5: the defense-telemetry tier.** attack-range-windows's substrate: the Splunk server (a Linux host recipe), the Windows endpoint with sysmon and the universal forwarder, telemetry flows declared and consumed by `detection` goals (the challenges-v1 machinery exists; this slice realizes a live collector for it).

**Slice 6: attack-range-windows solved + the exit.** The second fixture end to end, then the phase exit: both fixtures from clean caches, every reference eval green, docs (the examples page grows its Windows rows; Windows-specific operational notes), CHANGELOG, the house two-round phase review.

## Non-goals

No Windows artifact publication anywhere (ratified; local cache only, and the fixture records carry only the operational rebuild-cadence facts); no memory-restore default (opt-in stays experimental per the standing decision); no new goal types; no GOAD-full (the 5-VM two-forest original) — goad-light is the fixture; no Windows client-OS media this phase (the endpoint realizes on Server 2022 eval, deviation recorded, unless slice 5 proves that unworkable).

## Parked for the user

Accumulated in [windows-ad-v1-parked-decisions.md](windows-ad-v1-parked-decisions.md) per the AFK protocol.

## Ledger

| Slice | Status |
|---|---|
| 1 Windows guest first-class | |
| 2 Windows build pipeline | |
| 3 whole-range converged capture | |
| 4 goad-light solved | |
| 5 defense-telemetry tier | |
| 6 attack-range-windows solved + exit | |

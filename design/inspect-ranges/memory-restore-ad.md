---
type: document
title: "Memory-snapshot restore for AD ranges: what rollback risk remains, and the proposed posture"
status: draft (for discussion — no decisions recorded yet)
tags: [inspect-ranges, checkpoints, snapshots, active-directory, vmgenid, discussion]
timestamp: 2026-10-05
---

# Memory-snapshot restore for AD ranges: what rollback risk remains, and the proposed posture

*Discussion document for reviewer follow-up. Prompted by reviewer feedback (2026-10-05): "AD is super sensitive to time and machine-account state and so rolling back to live snapshots can be a source of instability and unpredictable behaviour (especially when Kerberos, certificates and scheduled tasks are in play). I'm sure this can be mitigated with appropriate health-checks as well as VMGenID (which is supported by libvirt)." This document lays out how our restore model relates to the known AD-rollback failure modes, what the feature buys, the mitigations we propose, and the open questions we want the reviewer's read on. Nothing here is adopted yet.*

## How our restore model differs from the usual rollback scenario

The classic AD snapshot disasters come from **partial rollback against a world that moved on**: a member restored to an old machine-account password while its DC rotated it (secure-channel death), or a DC rolled back after replicating with partners (USN rollback). Our checkpoint model ([range-build](range-build.md)) excludes that scenario by construction, on three assumptions:

1. **Whole-range atomicity**: every guest is captured at the same quiesce point and restored together; there is no un-rolled-back partner to disagree with.
2. **Closed world**: each sample's range is an isolated L2 island; nothing outside it ever observed the post-checkpoint "future". Parallel samples from one checkpoint are identical closed universes that never meet.
3. **Single use**: a restored instance serves one sample and is destroyed; divergent timelines are never re-joined.

Measured so far (restores minutes after capture): secure channel, parent-child trust, cross-domain auth, and DNS chains all intact after whole-range restore — the 2-VM domain ([checkpoint-clone](../spikes/checkpoint-clone/README.md), destructive sample A then pristine sample B) and the two-domain forest ([goad-forest](../spikes/goad-forest/README.md), 4 VMs in 48 s).

## The exposure that remains: checkpoint age

What consistency-by-construction does not solve is the **time axis**. We push wall-clock forward at restore (`guest-set-time`), and a large jump (checkpoint age) is where the reviewer's list bites: in-memory Kerberos tickets expire at resume (mostly self-healing, transiently noisy); machine-account password age crosses the 30-day rotation policy (rotation storms — though consistent ones, since DC and members share the checkpoint instant); ADCS certificates and CRLs age out (GOAD deliberately includes ADCS); and scheduled tasks fire missed-run backlogs at exactly sample start. None of this is tested beyond minutes-old checkpoints. Note that most of it is a property of **checkpoint age, not of memory restore**: a 60-day-old *disk* checkpoint cold-boots with the same expired certificates and stale password age. The memory-specific slice is the resume-time artifacts (stale RAM state, missed-task triggers on resume, the clock-push itself).

## What memory restore buys (why we want the feature at all)

Against the alternative — cold-booting the same converged disk checkpoint — the value is concentrated entirely in AD and service-heavy Windows ranges:

| Range class | Cold boot from converged disks | Memory restore | Verdict |
|---|---|---|---|
| Linux | ~10–15 s | ~1–3 s | not worth any complexity |
| Simple Windows | 6.5 s boot + service settling | 1.3 s | marginal |
| AD / heavy Windows | est. 1–3 min to DCs-fully-answering + members + services (unmeasured; best-case convergence measured at 6–42 s) | 3 s (pair) / 48 s (4-VM forest), converged state intact | **1–2.5 min per sample, plus startup determinism** |

The determinism half matters as much as the speed: restore starts every sample from a bit-identical converged state; cold boot re-converges with natural variance, which is noise at t=0 of a measurement. The proposed scoping follows the table: **disk checkpoints are the universal default; memory restore is the standard profile for AD/heavy-Windows ranges only.**

## Proposed mitigations (the reviewer's two, plus three)

1. **Post-restore health checks** (reviewer's suggestion — adopted as proposed): the battery already run ad hoc in every restore spike (`Test-ComputerSecureChannel`, `Get-ADDomain`, SRV resolution through the real DNS chain, KDC reachability, time status) becomes the formal AD range-readiness gate, executed in the provider's *verify* stage (which the sample state machine already defines); failure marks the sample invalid/infrastructure per [scoring-integrity](scoring-integrity.md)'s validity states, never silently scored.
2. **VMGenID** (reviewer's suggestion — adopted as an explicit decision, with the default inverted): standard guidance exposes a generation change on restore so AD performs its rollback safety measures (invocation ID reset, RID pool discard). That guidance assumes partial rollback against live partners. Under assumptions 1–3 above, the divergence it protects against cannot occur, and triggering the safety dance every sample costs per-sample AD churn for nothing — so the proposed default is a **stable genid across restore** (what the spikes effectively did; everything held), recorded as a decision resting on the three named assumptions rather than an accident. The compiler emits explicit domain XML ([min-devices](../spikes/min-devices/README.md)), so genid is directly controllable; a per-range override to signal generation change remains available (it is guest-visible, and some scenarios may want Windows to notice the restore).
3. **Checkpoint freshness policy**: the build manifest records capture time and a max age; the provider refuses stale checkpoints. Caps the time-jump exposure structurally and applies to disk checkpoints too.
4. **Image hygiene**: range goldens disable the missed-task storm sources (update scans, maintenance tasks) at build — wanted for determinism regardless.
5. **Frozen-time alternative** (recorded as an option, not the default): skip the clock push and let each sample run at capture time. Every sample starts at the identical logical instant — certificates always valid, no rotation pressure, no task backlog, maximal determinism — at the cost of in-guest timestamps disagreeing with host-side evidence (correlatable via a recorded offset) and anything comparing against true time. For isolated ranges this is a defensible trade and possibly the better default for determinism-sensitive scoring.

## The empirical gap, and the spike that closes it

Max safe checkpoint age is currently folklore. A cheap **checkpoint-aging spike** converts it to a number: restore the forest checkpoint, push time forward in steps (+1 h, +1 d, +35 d, +400 d) in separate samples, run the health battery at each step, and record where degradation appears (ticket expiry, rotation behavior, certificate validity, task backlogs) — under both the stable-genid default and the genid-change override, and optionally under frozen time. Day-scale on existing machinery; its output sets the freshness policy's max age.

## Questions for the reviewer

1. Does any failure mode from your experience survive the three assumptions (whole-range atomic restore, closed world, single-use instances) — i.e., was the instability you saw from partial rollbacks, or did it also occur with globally consistent ones?
2. Any objection to the stable-genid default *given* those assumptions, with genid-change as a per-range override rather than the default?
3. Is the proposed health battery missing checks you found necessary (DFSR/SYSVOL state, w32tm stratum, specific ADCS/CRL probes, scheduled-task quiescence)?
4. From your operational experience, what checkpoint age did things start breaking at — does a 30-day max-age (inside the machine-account rotation window) match your intuition before we measure?

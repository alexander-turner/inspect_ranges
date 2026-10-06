---
type: decision
title: "Memory-snapshot restore: an opt-in optimization, not the default"
status: accepted
tags: [inspect-ranges, checkpoints, snapshots, active-directory, vmgenid, decision]
timestamp: 2026-10-05 (decided 2026-10-06)
---

# Memory-snapshot restore: an opt-in optimization, not the default

*Originally a discussion document prompted by reviewer feedback (2026-10-05): "AD is super sensitive to time and machine-account state and so rolling back to live snapshots can be a source of instability and unpredictable behaviour (especially when Kerberos, certificates and scheduled tasks are in play). I'm sure this can be mitigated with appropriate health-checks as well as VMGenID (which is supported by libvirt)." The reviewer's follow-up (2026-10-06) recommended: "I would suggest making it an optional optimisation feature but not the default. It should be okay for most Linux configurations as well as non-AD Windows environments." Adopted as the decision below; the analysis that follows is retained as the record of why.*

## The decision

**Cold boot from the converged disk checkpoint is the universal default for every range class, including AD.** Memory restore stays in the design as an explicitly experimental per-range opt-in, gated behind the same verify-stage health battery, with its preconditions documented below. No further investment on the memory path beyond what the spikes already proved until a real workload asks for it.

The cost-benefit that drives this: the saving is 1–2.5 minutes per sample on AD ranges (see the table below), against samples that run tens of minutes to hours of agent time, so low single-digit percent of wall clock. Against that, a default memory path carries a second restore path with real correctness risk, an unanswered empirical question (max safe checkpoint age under the clock push), and a non-standard VMGenID posture that inverts Microsoft guidance. The determinism half of the original case is also weaker than it first appeared: the health battery gates sample start for cold boots too, so cold-boot variance becomes "converged, verified state" with bounded settling noise rather than uncontrolled re-convergence. If a specific measurement later proves sensitive to residual startup variance, that is the moment to reach for the opt-in, with evidence in hand.

One scoping inversion worth recording: the reviewer scoped the opt-in as safe for "most Linux configurations as well as non-AD Windows environments", which is exactly where the table shows it buys almost nothing (10–15 s down to 1–3 s), while the one class where it bought something meaningful (AD) is the one class where it is risky. The feature's remaining niche is therefore narrow but legitimate: fast iteration while developing a range, CI smoke runs, and determinism-sensitive scoring if the need is demonstrated. Users who enable it accept the health gate, the freshness cap, and the genid caveats with eyes open.

## How our restore model differs from the usual rollback scenario

The classic AD snapshot disasters come from **partial rollback against a world that moved on**: a member restored to an old machine-account password while its DC rotated it (secure-channel death), or a DC rolled back after replicating with partners (USN rollback). Our checkpoint model ([range-build](range-build.md)) excludes that scenario by construction, on three assumptions:

1. **Whole-range atomicity**: every guest is captured at the same quiesce point and restored together; there is no un-rolled-back partner to disagree with.
2. **Closed world**: each sample's range is an isolated L2 island; nothing outside it ever observed the post-checkpoint "future". Parallel samples from one checkpoint are identical closed universes that never meet.
3. **Single use**: a restored instance serves one sample and is destroyed; divergent timelines are never re-joined.

Measured so far (restores minutes after capture): secure channel, parent-child trust, cross-domain auth, and DNS chains all intact after whole-range restore — the 2-VM domain ([checkpoint-clone](../spikes/checkpoint-clone/README.md), destructive sample A then pristine sample B) and the two-domain forest ([goad-forest](../spikes/goad-forest/README.md), 4 VMs in 48 s). These results stand; they are preconditions of the opt-in, not evidence for a default.

## The exposure that remains: checkpoint age

What consistency-by-construction does not solve is the **time axis**. We push wall-clock forward at restore (`guest-set-time`), and a large jump (checkpoint age) is where the reviewer's list bites: in-memory Kerberos tickets expire at resume (mostly self-healing, transiently noisy); machine-account password age crosses the 30-day rotation policy (rotation storms — though consistent ones, since DC and members share the checkpoint instant); ADCS certificates and CRLs age out (GOAD deliberately includes ADCS); and scheduled tasks fire missed-run backlogs at exactly sample start. None of this is tested beyond minutes-old checkpoints. Note that most of it is a property of **checkpoint age, not of memory restore**: a 60-day-old *disk* checkpoint cold-boots with the same expired certificates and stale password age — which is why the freshness policy below applies to the default path too. The memory-specific slice is the resume-time artifacts (stale RAM state, missed-task triggers on resume, the clock-push itself).

## What memory restore buys (the measured case, and why it lost to the costs)

Against the default — cold-booting the same converged disk checkpoint — the value is concentrated entirely in AD and service-heavy Windows ranges:

| Range class | Cold boot from converged disks | Memory restore | Verdict |
|---|---|---|---|
| Linux | ~10–15 s | ~1–3 s | not worth any complexity |
| Simple Windows | 6.5 s boot + service settling | 1.3 s | marginal |
| AD / heavy Windows | est. 1–3 min to DCs-fully-answering + members + services (unmeasured; best-case convergence measured at 6–42 s) | 3 s (pair) / 48 s (4-VM forest), converged state intact | 1–2.5 min per sample, plus startup determinism |

An earlier draft proposed memory restore as the standard profile for AD/heavy-Windows ranges on the strength of the last row. The decision above supersedes that: the absolute saving is small relative to sample runtime, and the risk sits precisely in that row.

## Mitigations

### Adopted regardless of restore path

1. **Range-readiness health checks** (reviewer's suggestion): the battery already run ad hoc in every restore spike (`Test-ComputerSecureChannel`, `Get-ADDomain`, SRV resolution through the real DNS chain, KDC reachability, time status) becomes the formal AD range-readiness gate, executed in the provider's *verify* stage (which the sample state machine already defines) for cold boots and memory restores alike; failure marks the sample invalid/infrastructure per [scoring-integrity](scoring-integrity.md)'s validity states, never silently scored.
2. **Checkpoint freshness policy**: the build manifest records capture time and a max age; the provider refuses stale checkpoints. Caps the time-jump exposure structurally; a 60-day-old disk checkpoint has the expired-certificate and password-age problems whether or not memory is restored.
3. **Image hygiene**: range goldens disable the missed-task storm sources (update scans, maintenance tasks) at build — wanted for determinism regardless.

### Preconditions and options of the memory-restore opt-in

4. **The three assumptions** (whole-range atomicity, closed world, single use) are preconditions, not defaults to argue from: a range may only enable memory restore if its deployment satisfies all three.
5. **VMGenID — stable across restore, within the opt-in**: standard guidance exposes a generation change on restore so AD performs its rollback safety measures (invocation ID reset, RID pool discard). That guidance assumes partial rollback against live partners, which the preconditions exclude, and triggering the safety dance every sample costs per-sample AD churn for nothing — so the opt-in defaults to a stable genid (what the spikes effectively did; everything held). The compiler emits explicit domain XML ([min-devices](../spikes/min-devices/README.md)), so genid is directly controllable; a per-range override to signal generation change remains available (it is guest-visible, and some scenarios may want Windows to notice the restore). This stance is documented as a property of the opt-in rather than defended as a project default.
6. **Frozen-time option**: skip the clock push and let each sample run at capture time. Every sample starts at the identical logical instant — certificates always valid, no rotation pressure, no task backlog, maximal determinism — at the cost of in-guest timestamps disagreeing with host-side evidence (correlatable via a recorded offset) and anything comparing against true time. Recorded as an option within the opt-in; if the opt-in is ever promoted for determinism-sensitive scoring, this is likely the mode to pair it with.

## The empirical gap, and the (shrunk) spike that closes it

Max safe checkpoint age is currently folklore, and the freshness policy's number is needed for the **disk default**, not just the opt-in. The checkpoint-aging spike therefore shrinks to its disk arm: cold-boot the forest checkpoint with time pushed forward in steps (+1 h, +1 d, +35 d, +400 d) in separate samples, run the health battery at each step, and record where degradation appears (ticket expiry, rotation behavior, certificate validity, task backlogs). The memory-restore arms (stable genid vs. genid-change, frozen time) are deferred until a range actually wants the opt-in for real workloads.

## Disposition of the original reviewer questions

The original draft closed with four questions. Their status after the follow-up:

1. *Do any failure modes survive the three assumptions?* Not answered directly; the recommendation to keep memory restore off the default path makes the answer non-blocking. The question stands as the thing to re-ask before the opt-in is ever promoted.
2. *Any objection to the stable-genid default given the assumptions?* Mooted for defaults; the stance survives as a documented property of the opt-in (mitigation 5).
3. *Is the health battery missing checks (DFSR/SYSVOL, w32tm stratum, ADCS/CRL probes, scheduled-task quiescence)?* Still open, and now attaches to the default path: the battery gates cold boots too.
4. *What checkpoint age did things break at?* Still open; the disk-arm aging spike measures it, and any operational intuition from reviewers still helps set the initial cap.

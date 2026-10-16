---
type: record
title: "Quality review 2026-10: whole-codebase correctness, robustness, and coverage audit"
status: closed
tags: [inspect-ranges, quality, review, coverage, record]
timestamp: 2026-10-16
---

# Quality review 2026-10: whole-codebase correctness, robustness, and coverage audit

*Close-out record for the first whole-codebase quality round, run 2026-10-16 after evidence-v1 and challenges-v1 closed. Every prior review had been diff-scoped (per slice, per chunk); this round read whole modules and cross-module flows as they exist post-integration, measured test coverage for the first time, and fixed what it found under a charter that forbade the two classic review failure modes: re-litigating recorded design decisions, and adding code for hypothetical edge cases. The working inventory with per-finding dispositions is [findings.md](../spikes/quality-review/findings.md); the brief for the planned second round is [round-2-brief.md](../spikes/quality-review/round-2-brief.md).*

## Scope and method

All of `src/inspect_ranges/` (~24.4k Python lines) plus the Go and C# daemons (~4.9k lines), ops surface at a lighter tier, spike/battery scripts excluded as recorded artifacts. Eight fresh-context review units (spec+compiler, channel, daemons, provider+host+runtime, evidence, challenges, cross-cutting seams, ops) plus a coverage pass; every reviewer read the relevant design records first, probes were mandatory for blocking-severity claims, and each unit shipped a considered-and-declined list. Adjudication consolidated and classified; the user triaged the full findings list before any fix; seven subsystem fix workers landed one finding per commit with regression tests and live battery re-runs; one integrator assembled the branches; a final fresh-context verification reproduced every claim independently.

## Results

- **Findings**: 6 blocking and ~25 further correctness defects, all probe-demonstrated or concretely traced, all fixed with regression pins; ~16 test additions; a mechanical sweep; one record correction. Full disposition table in findings.md. Headlines: the daemon fd CLOEXEC leak (an unrooted agent could intercept driver connections and read plant values; also the true root cause of the recorded exec budget-hold, which collapsed from ~180 s to 0.01 s measured live); attacker scoped egress not scoping (battery-proven fixed, including the live-listener non-leak); telemetry cursor stripping as an agent-craftable alert-suppression primitive; windowed evade/detection excluding delivered-but-uncommitted alerts (a free stealth pass, adversarially timeable); degrade double-counting; the finalize-timeout and cli_cleanup sealing-lifecycle holes; the identifier-namespace family (path traversal, bridge-name collisions, goal-id grammar) closed by one validation discipline; the multi-guest readiness/realize envelope mismatch (reproduced and fixed on real hardware); the doctor's derived-sink pass-green.
- **Coverage**: first measurement 87% line+branch (10,777 statements); after the round 88% over 11,142, with every previously-uncovered region triaged (load-bearing gap, battery-covered with the battery cited, or justified exclusion) in [coverage-triage.md](../spikes/quality-review/coverage-triage.md). `make coverage` is now a standing target. The biggest pure gap found: `exfiltrate` was the one goal type with no test anywhere; it now has CI contract tests and a live battery row.
- **Verification**: suite 1335 -> 1414 passed (75 skipped / 3 xfailed unchanged) with both REQUIRE flags; `make check` clean; all live batteries green with zero residue on the integrated code (seam 42, telemetry 19, oracle 25, evade 12, observed 24 incl. the new fd-hygiene checks, refchains 23 incl. the exfiltrate row, egress incl. the new scoped phase, A10's dedicated demonstration 5/5); wire vectors and the rejection table byte-identical throughout; an accidental 605 MB artifact commit on one fix branch was caught by scan and rebuilt out before reaching main.

## The charter held

Zero submitted findings were declined at adjudication; the discipline worked upstream: the eight units collectively recorded roughly sixty considered-and-declined items (recorded deviations correctly not re-reported, non-reachable constructions, deliberate postures) instead of submitting them, and those lists live in the unit reports' summaries within findings.md's provenance. One finding was scoped down (C# connection handling to idle-timeout parity; full concurrency bounding judged speculative at measured densities), one grammar question was settled against a reviewer's severity rating with reasons (underscores/dots stay legal: recorded fixtures use them, and the real hazard, derived-device collision, is refused precisely), and two fixes landed with declared shape deviations (goal-id grammar on the model rather than cross-validation; a plan-derived realize allowance rather than keepalives, which would have violated the strictly-increasing stage rule).

## Systemic lessons (the round-2 hunting map)

The defects clustered in classes that diff-scoped review structurally cannot see: cross-layer envelopes that are each sane alone with an unowned sum; sibling arms that drift; the newest feature missing from the oldest recovery path; test fixtures more permissive than the production seams they fake; authored identifiers flowing into device names, paths, and grammars unvalidated; and OS-resource surfaces (fd inheritance, non-monotonic clocks, special-file opens) invisible to wire-level verification. Two meta-lessons: verifier probes that are deliberately left uncommitted prove a behavior once without pinning it (this round converted the load-bearing subset into durable tests), and never-raise guard layers, each locally correct, are collectively the mechanism by which cross-layer mistakes become invisible.

## Residuals, each deliberate and recorded

T7 (the host-seal-fallback binding test) is the one approved test proposal that landed nowhere this round. C# behavioral validation remains gated on the recorded Windows-runner follow-up (the C# fixes are compile- and vector-verified). The Go kill path's microsecond pid-reuse window predates the round and is documented. B10's per-platform divergence (Go serves char/block devices per a pinned contract; C# refuses all non-disk types) is documented at the C# helper. A second-cancellation abandoned boot leaves an owner record recoverable only by `inspect-ranges down`, not `cli_cleanup` (noted in the C2 test comments). `_in_window_chunks` would mis-handle a span shape the single production assembly cannot emit (recorded, not hardened, per the charter). `FakePlantSession` is duck-typed in two test files (consolidation candidate). The egress spike's `compile.py` keeps its spike-local bridge-name copy (recorded artifact). The doctor's evidence rows carry one duplicated fix-string literal (cosmetic).

## What follows

Round 2 runs with a fresh-context agent against the merged state, cutting along flows instead of packages and taking the test suite and this round's own fix code as first-class subjects: [round-2-brief.md](../spikes/quality-review/round-2-brief.md). Expected to find less; obligated to say so plainly if it does.

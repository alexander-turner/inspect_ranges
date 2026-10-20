---
type: document
title: "Build/images subsystem quality review: close-out"
status: final
tags: [inspect-ranges, build, images, quality-review]
timestamp: 2026-10-18
---

# Build/images subsystem quality review: close-out (2026-10-18)

*The two full fresh-context review cycles of the image subsystem the user pre-ratified before going AFK, run after build-v1 completed (slices 1-7 plus the scripted phase exit). Shape per the house quality rounds: round 1 cut by unit (six reviewers: recipes+guesttool, orchestrate, verify+capture, manifest+gate, behavioral+range content, tests+batteries as subject), round 2 cut by flow plus round 1's fix diff (four reviewers: the author loop, the consumer path, failure and recovery, the fix diff at line level). Findings and dispositions: [round-1](../spikes/quality-review-build/round-1-findings.md), [round-2](../spikes/quality-review-build/round-2-findings.md).*

## The numbers

- Round 1: 6 blocking, 24 non-blocking after adjudication; all fixed; 30 regression tests (two new test files, the first unit coverage for capture and for the behavioral runner's own logic); suite 1559.
- Round 2: 2 blocking + 1 promoted, ~15 non-blocking after dedupe (two pairs found independently by two reviewers each); 2 adjudicated declines recorded with reasons; all the rest fixed; suite 1565.
- Round 2's fix-diff reviewer verified every round-1 blocking fix as a real closure, with 29 of 30 new tests demonstrated failing against the pre-fix tree.
- Both rounds re-batteried in full: era-golden 12/12, build-manifest 11/11, and the phase exit 13/13 (which itself re-runs build-v1 13/13, build-cmd 9/9, build-verify 8/8, vulhub-build 10/10, the Journey A transcript, and the real `inspect eval` with both goals pcap-corroborated).

## What the rounds actually bought

The headline class in both rounds was the same: the subsystem's central invariant (nothing unproven is ever consumable) held on every path its authors had reasoned about and leaked on paths one seam away. Round 1 closed the deferred-save gaps (a saved-then-failed manifest consumable under Ctrl-C or a teardown failure; a prior same-spec manifest surviving a failed re-proof; silent check skips; an inert battery assertion that was the only check of "a failed build mints no manifest"). Round 2 closed the composition seams between round 1's own fixes (the retraction racing the locked stamp; the golden verified at the gate but not at the applier; the checks-removal inverse of the misnamed-metadata guard) plus the one remaining stage arm without broad disposal. The verification engine, the invalidation algebra, and the capture discipline came through both rounds with only fail-closed edge corrections (dpkg status words, `~`/`+really` version shapes).

## Residuals, recorded not fixed

- The same-spec concurrent-build refusal does not cover the behavioral phase's `-bx` window (documented in the orchestrate docstring; the identity-matched retraction keeps a sibling's green manifest safe; a build-scope lock is a parked question).
- Ctrl-C mid-re-proof performs no retraction: an aborted proof equals never-having-started, and the checks digest keeps the fast path invalidated (adjudicated decline, round-2 F4-4).
- The provider surfaces gate refusals without the remedy hint (`IssueError.__str__` is message-only); the CLI consumers all carry hints now.
- Reviewer considered-and-declined lists stand in their reports (session transcript); the "Parked for the user" list in build-v1.md gained three entries across the rounds (range-name grammar unification, build-time corroboration strength, behavioral-failure reuse cost — restated) on top of the earlier parked items (realized-image GC, baked build-egress artifacts, manifest deferrals).

## State for the user

build-v1 is complete: slices 1-7 done with per-slice review gates, the scripted phase exit green with measured timings closing the requirements doc's derive and Linux-build UNMEASURED entries, and the two subsystem rounds done, fixed, and re-batteried. All commits are local on `main` (push needs your credentials). The vulhub-zabbix range is a built, verified, behaviorally proven example whose reference chain a real `inspect eval` executes to 1.0/valid with corroborated beacons. The decisions waiting on you are exactly the "Parked for the user" list in build-v1.md.

# Quality review round 2: consolidated findings for user triage

*Adjudicated consolidation of the six round-2 unit reports (this directory, `unit-1` through `unit-6`), run 2026-10-16 against main at c68cc93 per [round-2-brief.md](../round-2-brief.md). Reviewers worked read-only in detached worktrees (`.claude/worktrees/r2-u1` through `r2-u6`, retained for the fix phase; probe scripts live uncommitted there at the paths each unit report cites). Nothing has been fixed. This document is the FINDINGS CHECKPOINT: the user triages this list before any fix lands.*

## Adjudication summary

The six units submitted 27 findings. Two pairs were cross-unit duplicates (units 2+3 and units 3+5 independently found the same two defects, which is corroboration, not noise), merged below into R2-3 and R2-5, leaving 24 adjudicated findings: 8 correctness, 9 test/battery fidelity, 7 mechanical groups. Zero findings were declined at adjudication; the charter held upstream again, with roughly 70 considered-and-declined items across the six unit reports. Zero blocking findings; R2-1 is the one candidate for blocking severity and carries the mandatory probe.

The round found less than round 1 (round 1: 6 blocking plus ~25 correctness), as the brief predicted. Two systemic observations for the close-out: (1) every correctness finding above R2-7 is a round-1 taxonomy class recurring one arm beyond where the round-1 fix stopped (the name grammar missed one field, the realize allowance covered one gap of four, the A6 phase split missed the shutdown arm, the producer-stop share protects the seal but not sibling producers); (2) the test-suite findings share one root, shared fixtures slightly kinder than the seam they fake (`fake_up`, `FakeDocker`, `FakeGuest`, the fast fake tap behind the aclose pin), which is the round-1 fixture-fidelity lesson surviving in the shared-fixture layer the round-1 fixes did not sweep.

Charter notes. R2-2 was checked against the recorded applier-restart limitation: the limitation records the in-memory loss; the finding is the unrecorded composition in which the surviving driver's successful teardown releases the lease and makes the promised reap-seal permanently unreachable, so it stands as distinct. R2-4 was checked against the recorded second-cancellation owner-record residue (mid-acquisition) and is a different path (mid-finalize) with a different end state, so it stands. R2-18 (validate tracebacks) and R2-1 (range name) were greped against the round-1 findings/dispositions; neither appears as a prior decline or residual.

## Tier A: correctness (recommend fixing all; user confirms and picks shapes where noted)

**R2-1 (unit 5 F1; probe-demonstrated; candidate blocking). `RangeMeta.name` escapes the A9 name grammar and traverses filesystem paths through the CLI `up` path.** A `meta.name` like `../../../../ESCAPED` passes validation, becomes the compose project, and `write_owner` mkdirs plus teardown rmtrees a path outside the state dir (probe wrote `owner.json` six levels up). The provider arm already sanitizes (`_provider/naming.py`), proving this is the missed sibling. Fix shape: one more entry in `_name_issues` using the A9 grammar, plus a traversal pin. Disposition recommended: fix.

**R2-2 (unit 3 F2; probe-backed). Applier restart with a surviving driver leaves the host evidence record permanently unsealed; the promised reap-seal can never fire.** The new applier's `_stop_evidence` is a no-op, `read_host_seal` only warns, then `_release_host` removes the lease that both the reaper and `cli_cleanup` iterate, so no recovery path remains and in-code comments promise one that is unreachable. Unsealed-at-rest means the capture record of a completed sample stays forgeable. Fix shape: driver-side `seal_abandoned` on the `read_host_seal` miss path (the driver sits at exactly the reaper's ordering point), plus a composition pin and corrected comments. Disposition recommended: fix.

**R2-3 (unit 3 F1 and unit 5 F2, merged; traced arithmetic). The realize per-report allowance (180 s) covers only the verify gap; three other gaps legally exceed it, worst the pre-first-report first-use image build bounded at 1800 s.** B21 sized `ensure_range_image` at 1800 s and the doctor blesses build-on-first-use, but the build runs before the stage log exists, so the driver's 180 s first-report window starves; `ChannelBudgetError` is not a respin class, so the sample fails infra-shaped while the orphaned boot continues against freed CIDs holding its admission charge. Construct-to-boot (360 s) and boot-to-verify (300 s) also exceed 180 s. Fix shape is a user decision: the recorded A10 growth path (wire-carried envelope fields on `RealizeRequest`), or floor the first-report allowance at the image-build bound, or gate applier startup on the range image. Disposition recommended: fix, shape at user's choice.

**R2-4 (unit 2 F2; probe-backed). A cancelled `finalize` is latched as finalized, so the retried teardown seals nothing, writes `seals={}`, and releases the lease, leaving a permanently unsealed, unreferenced record.** `self._finalized = True` is set before any work and never reset on `CancelledError` (the second-ctrl-C family during teardown). Strictly worse than driver death because the successful retry destroys the only retry anchor. Fix shape: do not latch on cancellation (or make the retry re-enter finalize), plus a pin. Disposition recommended: fix.

**R2-5 (unit 2 F3 and unit 3 F3, merged; probe-backed both directions). `Applier.aclose` wraps `_stop_evidence` in a 5 s outer timeout whose inner bounds sum to ~22-32 s, reintroducing the A6 anti-pattern the teardown arm explicitly avoids.** Whenever a stop exceeds 5 s the cancellation lands mid-write, the promised `applier-shutdown` gap records and checkpoint never land, and the loss is unmarked (the one forbidden shape). The existing pin uses a fast fake tap so the envelope can never fire in CI (the unit-4 fixture theme). Fix shape: remove or resize the outer timeout per the teardown-arm pattern, plus a slow-tap pin. Disposition recommended: fix.

**R2-6 (unit 2 F1; probe-backed). One shared producer-stops timeout starves every later producer's stop; a starved Prober leaks and probes forever.** Registration order puts TelemetryPoller first; a legitimately slow telemetry stop (wedged guest) consumes the 6 s share and the Prober's tasks are never cancelled, spawning probe clients every 2 s against the sealed writer for the remaining life of the driver process. The seal itself is protected (round-1 pin holds); the leak is the defect. Fix shape: cancel or flag all producers before awaiting any, or per-producer shares; regression pin. Disposition recommended: fix.

**R2-7 (unit 1 F1). `DetectionGoal.signal` is a scoring-time regex the schema never validates, while both sibling arms validate the identical shape; the one shipped detection fixture authors signals as prose that can never match.** A non-compiling signal dies infra-shaped after the full episode; the attack-range fixture (validate-only today) would make the detect goal always fail and the `stealth: true` variant a free stealth pass when the Windows arc makes it runnable. Fix shape: a `_signal_compiles` bytes-domain validator matching `SeverityFilter`, regex semantics stated in schema docstring and challenges.qmd, fixture signals re-authored. Disposition recommended: fix.

**R2-8 (unit 1 F2). On the range_spec-omitted dataset path, an unknown `answer` variable runs the full sample and scores an opaque indeterminate; the docstring claims a sample-time re-check that does not exist for spec cross-references.** Fix shape is a user decision: correct the docstring parenthetical to what the gate re-checks, or add the cheap sample-time cross-reference in `run_setup` (the spec is in the oracle's handle) so the refusal lands before the agent starts. Disposition recommended: fix, shape at user's choice.

## Tier B: test and battery fidelity (unit 4's class-d charter extension; recommend fixing 9-11, triaging the rest cheaply)

**R2-9 (unit 4 F1; mutation-proven). The applier synthetic-failed-report pin is retired by fixture infidelity.** `fake_up` feeds `on_stage` before raising, which real `up()` cannot do for pre-stage-log failures, so the `except UpError` synthetic feed is behaviorally dead in every CI run; mutation removing the feed passed the suite. It guards the only path by which an early bundle failure reaches the driver as a typed `failed` report. Fix: make `fake_up`'s pre-stage-log failures raise without feeding `on_stage`. Recommended: fix.

**R2-10 (unit 4 F2). `FakeDocker` discards `timeout`, so B21's subprocess bounds (the whole substance of that fix) are unpinned; deleting every `timeout=` kwarg is invisible to the suite.** Fix: record `timeout` per call and assert non-None at compose-up, guest-boot, and down call sites. Recommended: fix.

**R2-11 (unit 4 F3). Battery checks that cannot fail or pass vacuously:** oracle disk-sweep (pipeline rc is `sort`'s, plants never asserted present), observed nonce-binding negative (vacuous on empty records), three unconditional/cannot-fail counted checks padding recorded counts. Recommended: fix the scripts (small edits), re-run affected batteries in the fix phase.

**R2-12 (unit 4 F4). The battery wrappers run `down --all` before counting containers, so the recorded zero-residue PASS verifies the sweeper, not the battery;** `run.sh:53` also reads a `docker ps` failure as zero residue, and egress has no failure-path teardown. Recommended: count before sweeping (keep the sweep), fix the rc check; egress posture is the user's call.

**R2-13 (unit 4 F5). Battery README and close-out bookkeeping drift:** fd-hygiene checks live in the oracle battery (now 24) but the README says 22/22 and nests the subsection under Slice 5; the close-out record attributes "observed 24 incl. fd-hygiene" wrongly; stale refchains docstring; one README claim ("unwound events in the stream") not matching what is checked. Recommended: record corrections (README, close-out erratum).

**R2-14 (unit 4 F7; probe-demonstrated). The disclosed-value frame-scrub pin inspects only locals named `value`; a failed-disclose frame retains the value as an int `address`.** Low (disclosed values are agent-visible by design) but the pin's claim and assertion diverge; the stronger repr-over-all-locals pattern already exists in the oracle tests. Recommended: strengthen the pin.

**R2-15 (unit 4 F8; probe-proven). The sessionless-pong hostile scenario is driven through `read_file` instead of `ping`, so it passes even with the session requirement gone** (backstopped by the wire-vector reject table). Fix: a `ping` branch in `_drive`. Recommended: fix.

**R2-16 (unit 4 F9). `FakeGuest` dedupes/stores ping and diag; neither daemon does,** so the fake's durable-store accounting diverges from both daemons and its docstring overclaims. Recommended: align the fake and docstring.

**R2-17 (unit 4 F6). Battery checks weaker than their README wording** (five traced items: filtered-vs-refused, unread `corroborated` field, stealth negative living in CI rather than the battery, two evidence-v1 wordings). None hides a live defect. Recommended: triage individually; mostly wording downgrades or one-line assert additions.

## Tier C: mechanical

**R2-18 (unit 6 F1; the highest-value mechanical). `validate_range`/`validate_challenges` raise raw tracebacks on `OSError`/`UnicodeDecodeError` despite an explicit never-raises docstring, and `validate`/`plan`/`render` relay them.** `validate` is the first command an external author runs and this is the one remaining raw-traceback surface. Fix: catch into a positioned file-level `Issue`, exactly as both functions already do for `yaml.YAMLError`. Recommended: fix.

**R2-19 (unit 3 M1). The applier's admission never charges its resident host-writer evidence buffer while the driver's admission symmetrically does** (~3 GiB unaccounted at the 48-range density point); sibling-site drift against evidence-v1's settled accounting decision. Recommended: fix.

**R2-20 (unit 1 F3). `JudgeType.check` spends a judge-model generate when nothing was submitted and `compare` unconditionally discards it.** Fix: short-circuit on empty submission. Recommended: fix.

**R2-21 (unit 5 F3). The A6 phase budgets (6 s / 10 s) exist as four unanchored literal copies across `_provider/evidence.py` and `_host/applier.py`;** drift at any call site silently invalidates the written budget composition. Recommended: single-source (and note R2-5 will touch the same lines).

**R2-22 (unit 5 F4). The C# accept loop sleeps while holding `Native.InheritLock`, contradicting its own fast-calls-only comment** (error path, bounded, no deadlock). Recommended: fix comment at minimum; moving the sleeps outside the lock is three lines, user's call given the zero-wire-drift rule (no codec surface touched either way).

**R2-23 (unit 6 F2 and F3). Docs: networks.qmd annotates the attacker's allocated address as .2 where allocation gives .1; two unmarked docs examples refuse at planning (guests.qmd hosts block, networks.qmd dns-ad block) and the docs harness only checks the classed direction.** Recommended: fix the annotation, mark the blocks (plus the dns-ad gating note), and add the inverse harness assertion.

**R2-24 (units 2 and 4 sweep). Small mechanical items:** `task_cleanup(cleanup=False)` comment describes only the uds arm (unit 2 F4); duplicated hand-built observation fixtures in evade/observed tests; the vacuous `shlex.quote` pin; verbatim-duplicated `Clock` and `RestartAcrossDelivery` test helpers; a misattributing comment in test_channel_loopback; dead test code bits; the poller battery's KeyError-instead-of-FAIL row; the wording-fragile "cap" substring check (unit 4 F10). Recommended: one mechanical-sweep commit.

## What the round verified (not findings; carry to the close-out)

Every round-1 fix was spot-checked at line level by unit 5 (full disposition table in its report): all hold, three with notes that are themselves round-2 findings (A9 -> R2-1, A10/B21 -> R2-3, A6 -> R2-21). Units 1-3 independently confirmed the fixes hold in flow context (A2-A8, A11, B1-B25 as crossed). Unit 4's mutation probes on A3/A4/A5 pins all fired; the wire-vector triangle regenerates byte-identical; CI runs both REQUIRE flags; the knob inventory is fully clean with every default matching docs. The user surface, the scoring composition on the recommended path, and the evidence format core drew explicit clean bills.

## Next steps

1. User triage of this list (confirm dispositions; decide shapes for R2-3, R2-8, R2-12 egress posture, R2-22).
2. Fix workers by subsystem, one finding per commit, regression test per correctness fix, affected batteries re-run, per-worker review pass.
3. Integration (blob-scan every branch), fresh-context verification of the integrated diff, close-out record, user merge checkpoint.

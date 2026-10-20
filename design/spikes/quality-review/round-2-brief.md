# Quality review, round 2: brief for a fresh-context agent

*You are starting with no session history. This document is your charter, context, and direction for the second whole-codebase quality round. Round 1 ran 2026-10-16; its artifacts are `findings.md` (with per-finding dispositions appended) and `../../inspect-ranges/quality-review-2026-10.md` (the close-out record) in this repo. Precondition: round 1's fix branch is merged to main (the close-out record exists and `make coverage` works); if either is missing, stop and ask the user.*

## The goal

Button up correctness and robustness of the shipped code before the images arc and first external users. This is a verification round, not a feature or redesign round. The user's two explicit anti-failure-modes, which round 1 enforced successfully and you must too:

1. Do not revisit design decisions. The design records under `design/inspect-ranges/` are the spec of record; every deliberate deviation and limitation is written down there and in the two findings/close-out documents. Re-reporting a recorded decision or residual is itself a review defect.
2. Do not add code for hypothetical edge cases. A finding is valid only as: a correctness defect on a reachable path (probe-demonstrated or concretely traced), a test gap on a load-bearing path (breakage would silently corrupt scoring, evidence, containment, or lifecycle, with no CI test or named VM battery covering it), or a mechanical defect (dead code, docstring contradicting behavior, duplicated logic with drift risk, resource leaks on paths that run). For unit 4 only (the test suite as subject) a fourth class is valid: fixture, pin, or assertion infidelity on a load-bearing seam, reported with the production seam it diverges from and the divergence it could hide. Probes are mandatory for blocking-severity claims. Every reviewer ships a considered-and-declined list.

## Process shape (what worked in round 1; reuse it)

Fresh-context reviewer agents per unit, working read-only in worktrees with uncommitted probes; reviewers read the relevant design records FIRST. Then one consolidated adjudication (dedupe, charter check, dispositions recommended, declines written). Then a FINDINGS CHECKPOINT with the user before any fix: nothing is fixed until the user has triaged the list. Then fix workers by subsystem (one finding per commit, regression test per correctness fix, affected VM batteries re-run, per-worker code-review pass), one integrator (watch for large blobs in worker branches: round 1 caught a 605 MB artifact commit; scan every branch), one final fresh-context verification of the integrated diff, a close-out record, and a user merge checkpoint. House rules bind throughout (CLAUDE.md; also: no em dashes in prose, plant/secret values never in logs, zero daemon/codec/wire-vector changes without the drift guards proving parity, batteries under the shared flock with zero residue).

## What round 1 found (so you aim elsewhere)

Round 1 cut the codebase BY PACKAGE (spec/compiler, channel, daemons, provider+host+runtime, evidence, challenges, cross-cutting, ops) plus a coverage pass. It found 6 blocking and ~25 further correctness defects, all fixed. The defect taxonomy, which is your hunting map because second instances kept appearing all round:

- Cross-layer envelope mismatches (each layer's budget sane alone, the sum unowned).
- Sibling-arm drift (one of N parallel paths diverged).
- Newest feature missing from oldest recovery path.
- Test fixtures more permissive than the production seam they fake (two scoring bugs hid behind hand-built fixtures).
- The identifier namespace (authored strings flowing into device names, paths, grammars).
- OS-resource surfaces invisible to wire-level verification (fd inheritance, non-monotonic clocks, special-file opens).

## Round-2 direction: cut along DIFFERENT axes

Round 1's package cut means package-internal code got deep reads while flows got one cross-cutting pass. Invert it. Suggested units (adjust against what you find):

1. **The scoring flow end to end** as one read: challenges.yaml -> dataset -> plant -> agent window -> poll -> submit -> score -> corroborate -> validity, crossing every package boundary on the way. You own the composition; packages were covered.
2. **The evidence flow end to end**: capture/poll/probe producers -> writer -> sink -> seal -> binding -> verify -> consumers (scoring reads, doctor probes), both topologies.
3. **The lifecycle flow end to end**: acquire -> realize -> execute -> finalize -> destroy, plus every recovery path (reaper, cli_cleanup, down, task_cleanup, applier restart) against every feature that must survive it.
4. **The test suite itself as the subject** (~21k lines, round 1 gave it only vacuity skims): fixture fidelity against production seams (the `_FakeSession` class of bug; round 1 fixed two fakes, audit the rest), pins that do not pin, over-mocking, assertions that cannot fail, battery scripts' checks versus their READMEs' claims (batteries were excluded from round 1 scope as recorded artifacts; they are load-bearing verification and deserve one honest pass). The battery audit is static by default: trace the scripts against the README claims; a live run is permitted only when a specific claim cannot be settled statically, must take the shared flock, and must leave zero residue.
5. **Round 1's own fix code** (the youngest code in the repo; every phase of this project found its defects clustered in the newest, least-adversarially-read corners): the fix-round diff as a unit, read whole. This unit owns the line-level read of the fix commits; units 1 through 3 skim them only for flow-composition effects, and adjudication dedupes anything found twice.
6. **The user surface**: docs/*.qmd claims against behavior, CLI ergonomics for the misleading-error class, the knob inventory for drift since round 1.

## What NOT to re-report (verify fixed, do not re-find)

The dispositions in `findings.md` list every round-1 fix with its commit. The close-out record lists the open residuals, which are RECORDED, not findings: T7 (host-seal fallback binding test, the one open test proposal), C# behavioral validation (gated on the recorded Windows-runner follow-up), the second-cancellation owner-record residue (recoverable via `down`, noted in test comments), the pid-reuse window in the Go kill path (documented), per-platform B10 divergence (documented), and everything in the units' considered-and-declined lists. Spot-checking that a round-1 fix actually holds is in scope and welcome; re-reporting its documented limitation is not.

## Calibration

Round 1's baseline after fixes: suite ~1414 passed / 75 skipped / 3 xfailed with INSPECT_RANGES_REQUIRE_GO=1 INSPECT_RANGES_REQUIRE_DOTNET=1; coverage ~88 percent line+branch via `make coverage`; all live batteries green with zero residue (READMEs record the runs). Expect round 2 to find LESS. If a unit finds nothing above mechanical, that is a valid and useful result; say so plainly rather than inflating. The declines list is as much the product as the findings list.

## Deliverables

Same as round 1: per-unit reports (findings ranked with probes, declines, a quality paragraph), the consolidated findings document for the user checkpoint, fixes only after user triage, an integrated and verified branch, a dated close-out record appended to or siblinging `quality-review-2026-10.md`, and the user merge checkpoint. The user authorizes execution; checkpoints are theirs.

# Round 2, Unit 1: the scoring flow end to end

Composition read of challenges.yaml -> dataset -> plant -> agent window -> poll -> submit -> score -> corroborate -> validity, across `_challenges`, `_compiler`, `_provider`, `_evidence`, and the dataset/task surface. Worktree `/home/USER/inspect_ranges/.claude/worktrees/r2-u1-scoring` at c68cc93; all 272 challenges CI tests pass there; probes were run uncommitted in the worktree. No blocking findings. Three findings total (two correctness at the lower end, one mechanical), which matches the round-2 expectation of finding less than round 1.

## Findings

### F1 (correctness): `DetectionGoal.signal` is a scoring-time regex that the schema never validates; the sibling goal type validates the identical shape, and the one shipped detection fixture authors signals the regex semantics can never match

- `DetectionType.compare` compiles the authored field as a regex: `re.compile(goal.signal.encode(), re.MULTILINE)` at `src/inspect_ranges/_challenges/observedtypes.py:388`.
- The schema model (`DetectionGoal`, `src/inspect_ranges/_challenges/schema.py:412-431`) carries no compile validator. Its sibling arms both do, in the bytes domain, added by the evade work: `SeverityFilter._coherent` (schema.py:449-510) and `EvadeGoal._coherent` for `match` (schema.py:549-562). This is the round-1 sibling-arm-drift class: the newest sibling (evade, post-close) got the validation discipline, the older arm (detection, slice 4) never did.
- Reachable path 1 (the B15/A8 class): a non-compiling signal validates green at authoring and dies inside the scorer's never-raise guard at end of run, after the full agent episode, as an infra-shaped `indeterminate`. Probe:

```python
from inspect_ranges._challenges.schema import DetectionGoal, SeverityFilter
import re
goal = DetectionGoal(id="alert-fires", collector="splunk", signal="CPU usage > 100% (critical")
# schema accepted signal: 'CPU usage > 100% (critical'
re.compile(goal.signal.encode(), re.MULTILINE)
# scoring-time compile raises: error missing ), unterminated subpattern at position 17
SeverityFilter(pattern="(unbalanced", floor=4)
# sibling refuses at schema: ValidationError "severity pattern does not compile"
```

- Reachable path 2 (fixture semantics drift, currently gated): nothing user-facing states regex semantics. The schema docstring says "a search or event description the engine evaluates" (schema.py:421) and docs/challenges.qmd:78 says the stream "contains ... `signal`". The one shipped detection fixture, `design/inspect-ranges/ranges/attack-range-windows/challenges.yaml`, authors prose under "Splunk search" semantics (`signal: "ATT&CK T1003.001 LSASS credential-dumping events from the win endpoint"`). It compiles as a regex but can never match a real export record (probe: searched against a plausible Splunk event line, no match). The pair is recorded VALIDATE-ONLY until the Windows arc, but when it becomes runnable the detect goal always fails and the `stealth: true` variant becomes a free stealth pass over any complete, flowing window: achieved=True regardless of what actually fired. The completeness precondition cannot see this because the hole is semantic, not coverage.
- Fix shape (not applied): a `_signal_compiles` validator on `DetectionGoal` matching the SeverityFilter pattern (bytes-domain compile), the schema/docs docstrings stating the regex semantics plainly, and the attack-range fixture's signals re-authored as patterns.

### F2 (correctness, lower): an unknown `answer` variable on the no-range_spec dataset path runs the full sample and scores an opaque indeterminate; `challenge_dataset`'s docstring claims a sample-time re-check that does not exist for spec cross-references

- `challenge_dataset` with `range_spec` omitted documents itself as "structural validation only (the planning gate re-checks at sample time)" (`src/inspect_ranges/_challenges/dataset.py:68`). The gate that actually runs at sample time (`run_setup`, `src/inspect_ranges/_challenges/setup.py:166-173`, plus the collector-spec check in `plant_goals`) re-checks observers and supplied collector specs only, never hosts, segments, or variables against the range. Plant-bearing goals fail loudly at plant time by accident of the plant itself; the `answer` family has no plant and nothing re-checks it.
- Consequence: a typo'd `variable` (or an oracle-read `answer` naming a wrong host) builds green, the agent runs the whole episode, the poller skips the goal silently (`poller.py:209-213`), and the scorer's check raises `KeyError` at `goaltypes.py:103`, caught at `scorer.py:114-132` into `indeterminate` with reason "check failed: KeyError": the A8 class, an authoring slip surfaced as infrastructure trouble, at full-episode cost. Probe (fixture-backed, run in-worktree):

```python
challenge = Challenge(id="c", prompt="p", goals=[AnswerGoal(id="which-port", variable="telnet_prot")])
challenge_dataset(Challenges(challenges=[challenge]))   # builds green, 1 sample
# scored against a real spec lacking the variable:
# validity: indeterminate | indeterminate: True | reason: check failed: KeyError
```

- Scope honestly stated: the recommended path (docs/challenges.qmd shows `challenge_dataset("challenges.yaml", range_spec="range.yaml")`) catches this with a positioned `unknown-answer-variable` issue; the hole is only the documented range_spec-omitted usage. Fix shape: either correct the docstring parenthetical to what the gate actually re-checks, or add the cheap sample-time cross-reference (the spec is in the oracle's handle) so the refusal lands before the agent starts.

### F3 (mechanical): `JudgeType.check` spends a judge-model generate when nothing was submitted; `compare` unconditionally discards it

- `observedtypes.py:565-577`: `submitted = submissions.value(goal.id) or ""` and the `get_model().generate(prompt)` call runs regardless; `compare` (observedtypes.py:580-583) returns "no submission" whenever `reads["submitted"] == b"0"`, discarding the grade. One wasted model call (and a judge prompt carrying an empty submission block) per unsubmitted judge goal per scoring pass, on a path that runs in every mixed challenge where the agent never reached the judge goal. Probe: stubbed `get_model`, scored a judge goal with `Submissions([])`; observed `generates with zero submissions: 1`, result `False / no submission`. Fix shape: short-circuit before the generate when `submitted` is empty.

## Considered and declined

- Invalid/indeterminate samples still flow into the scorer's built-in `accuracy()` metric: docs/challenges.qmd:99 explicitly instructs "Treat invalid and indeterminate samples as excluded from accuracy, not as zeros"; the posture is documented user responsibility, and a validity-aware metric is a feature, not a defect.
- `answer` variable goals score against the spec default until draws land (poller and scorer both read `declared.default`, verified no sibling drift): recorded residual in challenges-v1.
- kypo's port answer is guessable/low-entropy: recorded residual (attempt-policy open item).
- Degrade with no declared measure returns `partial=0.0` instead of `None` ("None means binary" per `GoalResult`): no scoring or latch effect; cosmetic contract nit, below the bar.
- Availability/degrade windows anchor at the last delivered probe record and detection/evade at the last delivered meta wall: documented batch-granularity and trailing-window semantics (observedtypes module docstring).
- The probe surface (sha256 of the nonce) is re-implementable by anyone with code execution on the target host:port: recorded scenario-design contract in challenges-v1.
- The tamper needle rides probe argv: recorded by design (disclosed value, driver-side process).
- mhbench exfiltrate plants target paths that may pre-exist in built images (the plant script refuses pre-existing targets): recorded images-arc interaction; the refusal is the designed behavior.
- goad-light Windows `secret_path` values would be treated as record-only plants by `_unwind` (no leading `/`): validate-only fixtures, gated on the images arc and stated in the fixture header.
- `_in_window_chunks` span-shape edge: explicitly recorded residual, not re-reported.
- Positional span misalignment in `stream_chunks_with_spans` when a foreign object occupies a gapped seq (write-once-conflict): traced, but every consumer routes a gapped stream to indeterminate/tamper handling first, so no scoring verdict can be built on the misaligned spans.
- `oracle.pcap` loads the whole stream into memory at scoring: measure-first posture with per-writer volume caps, recorded.
- The prober's 20 s stop budget exceeds the finalize producers' 6 s share, so a wedged probe loop loses its unflushed tail and seals `incomplete`: the deliberate A6 phase-split envelope; the seal reserve is the guarantee and the loss is recorded in the seal status.
- `score_challenge` calls `goal_type(goal.type)` outside its per-goal try (bare KeyError on an unregistered type): unreachable for dataset-built samples; the YAML union is closed to the fourteen built-ins, which register on package import (scorer import pulls `_challenges/__init__`), and the metadata round-trip re-validates against the closed union.
- Latch upgrade/window interplay (a poller latch upgraded to corroborated=True keeps its early wall while the confirming flow may be later): traced safe; corroborate's presence scan is deliberately unwindowed over the delivered capture, and absence can only fire when the same superset scan found nothing.
- ReDoS via authored severity/match/signal patterns over agent-influenceable telemetry bytes: authored (trusted) content under the measure-first posture.
- `_norm` strip duplicated between `goaltypes._norm` and corroborate's `value.strip()`: one line, identical semantics, drift risk negligible.
- Explanation string counts actual latches, not milestone-implied credit: cosmetic; metadata carries the full per-goal detail.
- T7 (host-seal fallback binding test): recorded open residual, out of this unit.

## Test gaps

None beyond the pins F1 to F3 would carry with their fixes. The composition seams I traced are all pinned in CI: dataset probe-segments metadata both sides of the provider boundary, contradiction reaching Score validity, the candidate cap and `uses_submissions` fan-out gate, the corroborated-upgrade latch, A4 span inclusion through the shared `telemetry_observations_from` assembly, and the temporal check. The battery set covers the live arcs.

## Quality

The flow reads as one coherent system, which was not a given for code assembled across seven slices and a quality round. The integrity lines are enforced consistently at every crossing I traced: plants precede guest state and never ride argv or logs, first-pass-wins latching is shared verbatim between poller and scorer, the scan-first presence/absence asymmetry in corroborate matches its docstring exactly, completeness preconditions route every incomplete window away from definite verdicts, the identity rules (guest IP, probe MAC exclusion) are single-sourced so compare and corroborate cannot drift, and the never-raise guards in the scorer are each paired with an honest degradation (fallback records, incomplete flags) rather than silence. The round-1 fixes hold where this flow crosses them (A4, A5, A8, B15, B16, B20 all verified in situ). What remains is edge wear, and both correctness findings are the same shape round 1 kept finding: a validation discipline applied to the newest sibling but not back-propagated (F1), and a gate whose docstring promises more than the composition delivers (F2). Nothing here corrupts a score on the recommended path; the risk concentrates where an author or operator steps off it.

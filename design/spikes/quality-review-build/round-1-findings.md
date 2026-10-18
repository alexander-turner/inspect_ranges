# Build/images subsystem quality review, round 1: consolidated findings

*Fix round complete 2026-10-18: every disposition below landed; `make check` clean, suite 1559 (30 new regression tests incl. two new files, test_build_capture.py and test_build_behavioral.py), and the full re-battery green in one sitting: era-golden 12/12, build-manifest 11/11 (strengthened M4/M7), phase-exit 13/13 (which re-runs build-v1 13/13, build-cmd 9/9 with armed kill legs, build-verify 8/8, vulhub-build 10/10, Journey A with the fixed J2b existence check, and the eval with both goals corroborated).*

*Six fresh-context unit reviewers (recipes+guesttool, orchestrate, verify+capture, manifest+gate, behavioral+range content, tests+batteries as subject), 2026-10-18, under the round-2-brief charter adapted to the build subsystem: design records as spec of record, probes mandatory for blocking claims, no VM boots, green batteries trusted, parked items excluded. Adjudicated by the session agent per the user's pre-ratified AFK mandate (two full review cycles, everything fixed and re-batteried). Dispositions appended after the fix round.*

## Blocking (deduped)

| id | finding | source | disposition |
|---|---|---|---|
| R1-A | A failing behavioral re-proof over a prior same-spec green manifest retracts nothing: the gate keeps consuming the stale manifest while the identical reused artifacts just failed their current checks (the slice-6 deferred save covered first builds only; probed end-to-end by both reviewers). The ratified rule and three docs claim otherwise, and the error text "no manifest was written" is false in this state. | U2#1 + U4#1 | fixed: behavioral failure now deletes a spec-matched prior manifest (stage-logged), the raised message names which of the two states holds, and a rebuild-over-prior-green regression test landed |
| R1-B | The staging bundle is rmtree'd while the range survives on three reachable paths: `--keep` + boot failure (up keeps the range, `kept` never set), success-path teardown failure (error says "retry with down" while the bundle the range mounts is deleted), and BaseException between up and teardown. Violates the module's stated range-survives-iff-staging-survives invariant on exactly the diagnostic paths. | U2#2 | fixed: `kept` is set from `options.keep` when `up` raises, true from successful boot until a teardown actually succeeds; tests for the keep-boot-failure and teardown-failure paths |
| R1-C | The chain of trust stops at the overlay: `swap_realized_spec` re-hashes only the realized image; `golden_digest`/`base_images` have zero consumers, and goldens mutate in place under the same cache name (recipe-version bumps, daemon updates re-derive at the same path), so a consumer boots overlay-over-G2 compositions that were never verified, under a proven claim (probed: gate passed with no golden in the cache at all). | U3#1 | fixed: the gate now resolves each content guest's `golden_reference` and refuses on digest mismatch or absence (`range-not-built`, "the golden changed since the build; rebuild"); tests for moved and missing goldens |
| R1-D | A `checks/` tree without `challenges.yaml` (or with the metadata file misnamed) silently skips the ENTIRE behavioral phase and mints a consumable manifest with `checks_sha256=""`: the root-level instance of the silent-skip class the slice-6 review eliminated one level down. | U5#1 | fixed: build refuses (`behavioral` stage) when `checks/` exists without `challenges.yaml`; unit test |
| R1-E | The phase-exit J2b assertion is inert: `grep -q "manifest" manifest.json` tests file content (which a real manifest never matches), not existence, and it was the only check anywhere of "a failed build mints no manifest" (probed against the green run's own artifact). | U6#1 | fixed: existence test in run.sh plus a verify-failure-leaves-no-manifest unit test |
| R1-F | Authored recipe vars with NUL bytes (YAML-expressible) or `=`/NUL in input keys pass pre-boot validation, then crash `Popen` mid-build with a raw ValueError that escapes the recipe stage's narrow catch: no stage log, no disposal, the egress-enabled range left up, a raw traceback at the CLI. The one stage arm that missed the broad-catch retrofit of prior reviews. | U1#1 | fixed: `validate_vars` refuses NUL in values and NUL/`=`/empty in keys with a typed issue (pre-boot via `resolve_provisioning`), and the launch stage catches ValueError alongside OSError |

## Non-blocking (fixed unless noted)

- U1#2 guesttool host-side OSError → one-line error + usage exit (was: raw traceback inside the pass-through rc space). Fixed.
- U1#3 `exec --script` + non-root `--user` cannot work (agent-owned 0700 staging). Documented restriction in guesttool and building.qmd. 
- U1#4 `exec --script` silently drops trailing argv. Fixed: refused as usage error.
- U1#5 duplicated default exec budget literal. Fixed: guesttool imports the constant.
- U2#3 `_strip_stage` mangles guest-less BuildErrors (substitutes/doubles the diagnosis in the raised message). Fixed: strips the known `[stage] ` prefix instead of splitting on ": "; test.
- U2#4 invalid `--build-nameserver` raises a raw ValueError. Fixed: coded issue.
- U2#5 + U6#6 the cached fast path ignores `--keep` (diagnostic no-op). Fixed: keep bypasses the cache; test.
- U2#6 uplink create/inspect TOCTOU across concurrent first builds. Fixed: re-inspect after a failed create.
- U4#2 render write-back lost-update over a concurrent same-spec rebuild. Fixed: locked read-modify-write helper in manifest.py; the CLI stamps through it.
- U4#3 three range-name grammars disagree (schema vs manifest module vs the spine's Q1); the manifest grammar is unreachable and its docstring misattributes the containment. Docstring corrected; grammar unification PARKED for the user (spine one-slash names vs schema's no-slash grammar).
- U4#4 `realized_file_name` ambiguous across range/guest boundaries (collisions cause spurious refusals + rebuild thrash). Fixed structurally: `guest_build_key` now includes the range and guest names, so colliding content yields distinct keys and file names (a rename rebuilds, which is correct: names are identity).
- U4#5a `up --from-spec <dir>` crashes on a directory. Fixed: resolves through `resolve_spec_path`.
- U4#5b `build --build-cache` is invisible to plan/render/up/provider (env var only). Documented in building.qmd; flag-plumbing question parked.
- U4#6 gate refusal branches (missing realized image, missing guest record) untested. Tests added.
- U3#2 `version_matches` fail-open on deep `~` pre-releases and `+really` downgrades. Fixed: `~` anywhere in the post-prefix upstream remainder refuses; `+really` matches against the effective (post-really) version; table extended.
- U3#3 dpkg probe lists removed-but-not-purged packages with versions. Fixed: Status filter (install ok installed); parser test.
- U3#4 `.capturing` crash temps invisible to `images list` and unpruned. Fixed: unmanaged filter knows the suffix.
- U3#5 sidecar placed before the image (incoherent window). Fixed: image first.
- U3#6 shutdown failure indistinguishable from success. Fixed: nonzero poweroff rc carried into the wait-timeout diagnosis.
- U3#7 capture module has zero unit coverage. Focused tests added (temp cleanup under the lock, placement order, timeout shape).
- U5#2 insufficient/forged can pass vacuously (indeterminate validity scores 0.0; zero SUBMIT lines; truncated stdout). Fixed: all three checks require validity `valid`; insufficient/forged require >=1 parsed submission; truncation refuses.
- U5#3 `_SUBMIT` requires exactly one ASCII space (silent drops on tab/double space; duplicated in journey_eval.py). Fixed: `\s+` in both.
- U5#4 docs claim beacon corroboration that a stock build cannot produce (10 MB default chunk vs 1.5 MB filler). Docs corrected to state the chunk-rotation condition; enforcement question noted with the parked corroboration items.
- U5#5 the mysql57 recipe splices `${agent_ip}` into a guest shell string: the exact pattern building.qmd marks UNSAFE, in the range the docs call the worked reference. Fixed: the retarget SQL is generated host-side and IR_PUSHed.
- U5#6 behavioral `SampleHandle.staging` points at the shared staging root (latent rmtree hazard on drift). Fixed: the bx staging dir.
- U5#7 plant removal in `_run_one`'s finally is unguarded (masks the primary diagnosis; silent rm failures misattribute one check later). Fixed: guarded per-plant, logged, primary preserved.
- U5#8 the behavioral runner's own logic (SUBMIT parsing, trio expectations) has zero unit coverage. Table-driven tests added.
- U6#2 build-cmd C7/C8 kill legs fall through on timeout (vacuous pass). Fixed: timeout fails the leg.
- U6#3 build-manifest M7 asserts less than its README row claims. Script strengthened (recipes-skipped and no-recapture greps).
- U6#4 build-verify/build-cmd/era-golden write to the developer's REAL builds cache. Fixed: isolated `INSPECT_RANGES_BUILD_CACHE` exports.
- U6#5 doctor manifest glob misses nested slashed-name manifests; one tautological test assert. Fixed: both depths globbed; slashed-name test; the tautological assert replaced.
- U6#7 conjunction-of-independent-greps in build-cmd C6b and build-manifest M4. Tightened to single-record patterns.

## Declined by adjudication (reviewer-proposed, not fixed)

- U1#3 full stage-and-promote for `exec --script --user`: documented instead; no range uses the combination and the push path covers owned placement.
- U5#4 enforcing `corroborated` for execute reference goals at build time: would fail stock builds by default; the honest doc fix landed and the enforcement/chunk-size question is recorded alongside the corroboration notes.

Reviewer considered-and-declined lists stand as recorded in their reports (session transcript); none were promoted.

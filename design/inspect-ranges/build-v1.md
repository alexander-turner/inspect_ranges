---
type: decision
title: "Build v1: guest content to a built, verified range, in seven slices"
status: accepted
tags: [inspect-ranges, build, images, recipes, verification, manifest, decision]
timestamp: 2026-10-17 (accepted 2026-10-17)
---

# Build v1: guest content to a built, verified range, in seven slices

*Phase plan for the first vertical slice of the build/images arc, with vulhub-zabbix as the forcing example. The exit criterion is literal: the [Journey A transcript](build-images-journey-a.md) executes command for command on `ranges/vulhub-zabbix`, ending in a real `inspect eval` against a built, verified range. The phase executes under the accepted [spine](build-images-spine.md) (reference grammar, invalidation algebra, artifact ledger) and [scenario-vs-recipes](build-images-scenario-vs-recipes.md) records, and it is the first consumer of [recipe-references](recipe-references.md), whose bundle contract it implements as specified (promoting that record from proposed to exercised). The build/runtime boundary and manifest commitments come from [range-build](range-build.md); the spec vocabulary from [guest-config-v0.3](guest-config-v0.3.md). Everything in [Journey B](build-images-journey-b.md) (push, pull, mirror, publish, registries) is a later phase: build v1 is strictly local.*

## What exists versus what is new

Existing and load-bearing: the compiler's plan/render pipeline with byte-deterministic bundles and digest verification at `up`; the realizer's `up`/`down` with ownership-keyed crash cleanup, stage logs, and the debug-bundle pattern; golden derivation for noble with the derivation-key cache; the daemon exec/file planes with the in-guest conventions from the challenges batteries (full-budget execs that leave background children, `read_file(user="root")` for 0600 files, `setpriv` for service launches); and the challenges behavioral-check harness, built for drop-in once guest content realizes. New in this phase: recipe bundles as code, a `build` verb and its orchestration, the verification engine, the build manifest, a second vendor class for `images derive`, and the first deletion of `guest-config-not-realized` (the `services` and `vulnerabilities` sections, demand-ordered per [build-images-requirements](build-images-requirements.md) section 7.3).

## Module layout

New code lives in `src/inspect_ranges/_build/` (`recipes.py`, `orchestrate.py`, `verify.py`, `manifest.py`; no leading underscores inside the private package). Import rules: `_build/` may import `_compiler/`, `_runtime/`, and `_channel/` (it renders, boots via the realizer's machinery, and talks to guests over the channel client); nothing imports `_build/` except `_cli/`. The build is a consumer of `up`/`down`, never a reimplementation: build-time ranges are ordinary projects with ordinary ownership records, so crash cleanup is inherited, not rebuilt.

## Build-time egress (decided 2026-10-17)

Online recipes install software, so build-time guests get network access: the build boots the range with an egress-enabled variant of its network plan, runs recipes, and the sample-time plan is untouched (isolated ranges stay isolated at runtime). The manifest records that the build used egress. Offline recipes (mode `offline`, operating on disk images) and vendored-input recipes remain per-recipe options, not requirements. The egress variant is a build-plan transformation, not a spec change: authors never declare build networking.

## Verification structure (decided 2026-10-17)

Vulnerability declarations are assertions, verified exactly like services: the declared version is installed and serving, and the vulnerable configuration is present (for vulhub: zabbix-web 3.0.3 on port 80, guest login enabled). Verification is mechanical, derived from the spec, with no per-CVE authoring. Proof of exploitability lives in exactly one place: the challenge's behavioral checks (reference solution passes, insufficient attempt fails, oracle shortcuts fail, per [challenges-scoring-integrity](challenges-scoring-integrity.md)), which run at build and land in the manifest per the existing [range-build](range-build.md) commitment. There is no per-vulnerability exercise tracking and no probe-to-vulnerability bookkeeping: an earlier two-tier proposal (per-vuln "exercised" labels fed by reference-chain steps) was rejected because the chain-to-vuln mapping is an annotation that rots as chains evolve, and the product's actual claim (the challenge is solvable) is exactly what behavioral checks prove. Recipe exit status is never sufficient: a recipe that exits 0 but leaves a declaration unverified fails the build.

## Period-correct content (decided 2026-10-17)

The vulhub stack is 2016-era (Zabbix 3.0.3 needs PHP 5.x/7.0; MySQL 5), which is a wrong-userland problem on noble, not a pinning problem. The default pattern: an era-appropriate golden (xenial-class for vulhub) plus era archives fetched at build time under the egress posture (old-releases.ubuntu.com, the Zabbix 3.0 repo). Archive fragility is a builder-only risk: published build outputs insulate consumers and mirrors, and rebuilders are first-party CI, which notices breakage. Per-recipe vendored packages are the fallback where an archive proves flaky; extracting content from upstream docker images is documented as a fidelity last resort, not used here. The vendor catalog grows on demand only: this phase adds xenial and nothing speculative.

## Disciplines inherited from realizer-v1

The lockstep rule: implementation plus failure modes plus conformance battery plus docs plus fresh-context review, or the slice is not done. Stage logs and the debug bundle are the observability seams; every build failure names the stage, guest, and recipe and carries a log path. The CID partition and host battery flock apply to build-time ranges as to any other. Spec-taking verbs default their argument to the current directory. Schema changes land inside the slices that need them (the Q1 grammar enforcement for `image:` and `range.name`, including the one-slash rule); there is no separate schema slice.

## The slices

**Slice 1: recipe bundles and the executor.** `recipe.yaml` (`name`, `version`, `entrypoint`, `inputs`, `mode`) per [recipe-references](recipe-references.md); resolution order range directory then local recipe cache; bundle digesting; invocation with validated vars as environment, the bundle directory as cwd, and the target connection (control channel address for `online`, disk path for `offline`; v1 implements `online`, with `offline` schema-accepted and refused with a typed issue until a recipe demands it). Execution against one booted guest with explicit budgets and a stage log per recipe run. Tested on the existing noble golden with fixture recipes; no new golden required. Failure modes: unresolvable recipe (same shape as `image-not-in-cache`), vars failing `inputs` validation (refused before boot), nonzero exit (named, logged), budget overrun including the exec-leaves-background-children case (the challenges-battery lesson: budgets are explicit or the drain is recorded). Battery: fixture recipes covering success, each failure mode, and digest stability of a rebuilt-identical bundle.

**Slice 2: the `build` verb.** Orchestration: resolve images and recipes, boot the range under the egress build plan, run each guest's `provisioning` steps in declaration order, tear down on success and on failure (`--keep` for diagnosis, as `up`), with the Journey A output format (stage-prefixed lines, the house coded refusals). Builds are ordinary projects: ownership records, deterministic names, crash cleanup inherited from `_runtime/`. Failure modes: mid-build `kill -9` leaves nothing (the realizer crash matrix, rerun against `build`); a failing recipe names guest, recipe, and log and fails the build after teardown; a second concurrent `build` of the same range refuses, naming the running project. Battery: fixture-range build end to end, the crash matrix, failure-output assertions (the battery checks the message content, not just the exit code).

**Slice 3: the xenial-class golden (parallelizable with slice 2).** `images derive` gains a second vendor class. The empirical risks this slice exists to surface early: xenial's cloud-init vintage (fallback is the bake-at-build injector from range-build's config-injection menu) and the daemon on old userland (expected fine: static Go binary, xenial has systemd). Battery mirrors the realizer's slice-1 golden battery: derived golden boots, daemon answers on vsock, no listeners at boot, corrupted vendor refuses before any cache write; plus the derivation-key discipline (noble and xenial goldens coexist in one cache under distinct keys).

**Slice 4: the verification engine.** `services` and `vulnerabilities` assertions verified against the booted, provisioned range over the channel: port listening, version serving as declared, vulnerable configuration present, with per-declaration results in the build report. Verification runs after all recipes complete, whole-range, independent of recipe claims. Failure modes produce the Journey A shape: a coded refusal (`service-not-verified`, `vulnerability-not-verified`) carrying the observed-versus-declared delta and the log path. Battery: a deliberately wrong fixture (newer package than declared, the Journey A scenario), a dead service, a missing config toggle, each caught and named; plus the all-green path.

**Slice 5: the build manifest and invalidation.** The manifest per [range-build](range-build.md) and the spine: identity, resolved `(name, digest)` images, recipe `(name, version, digest)` triples, verification results including behavioral checks, seeds, never secrets; wraps-by-reference to the bundle manifest; render ordered last. Invalidation per the spine's two-key algebra: a recipe edit reruns exactly that recipe and dependents (`unchanged, skipped` in the output and true), a golden change reruns everything downstream, a spec-only edit re-renders without touching recipes. Verification caches all-or-nothing: a build with every key unchanged reports the recorded verification with its timestamp; any change triggers a full re-verify; `build --reverify` forces it. The `up` digest-mismatch refusal gains the stale-bundle cause hint (re-derived or updated image since render; re-render). Battery: the incremental matrix (edit recipe, edit spec, re-derive golden, no-op), cached-verification reporting, `--reverify`, and the stale-bundle hint.

**Slice 6: the vulhub conversion.** The range becomes real: recipes authored under `./recipes/` (vendoring upstream vulhub config content, fetching era packages from the archives), the spec rewritten under the Q1 grammar (xenial golden reference; the upstream docker-tag strings and the command annotation migrate to `notes.md` as provenance), the Q1 grammar enforced in schema for `image:` and `range.name`, and `guest-config-not-realized` deleted for `services` and `vulnerabilities` on the realized path (other sections keep the gate). The challenge's CVE-2016-10134 reference chain and behavioral checks run at build and land in the manifest. Acceptance is the phase exit: the Journey A transcript executes command for command, including the verification-failure detour (induced wrong-version build) and the incremental rebuild, ending in a real `inspect eval` solving against the built range. The range's example status flips per range-build's rule: it has passed a build and carries a manifest.

**Slice 7: close-out.** Docs: a recipe authoring guide (the bundle contract, budgets, era-archive pattern, the in-guest conventions) and the `build` command reference with its failure modes; the guest-config and CLI pages updated for the deleted gates and new verbs. Doctor gains the build-phase checks (recipe cache health, xenial vendor presence where configured). The fresh-context review gate closes the phase.

## Verification (the phase proves itself)

One scripted run on the devbox, under the battery flock: slice 1's fixture-recipe battery; slice 2's crash matrix; the vulhub build battery (first build, incremental rebuild after a recipe edit, no-op cached build with cached-verification reporting); the verification-failure battery (the wrong-version scenario produces the Journey A refusal verbatim in shape); then the Journey A transcript executed command for command ending in a real `inspect eval`. `make check` and the unit suite green. The phase-exit record lands in this file with measured timings (first build, incremental, no-op), which also closes two UNMEASURED entries from the requirements doc (derive wall time for the new class, build wall time for a Linux range).

## Non-goals

- No Journey B surface: no push, pull, mirror, publish, registry resolution, or auto-pull in `task_init`; resolution in this phase is pin and local cache only, with the registry tier arriving with the distribution phase.
- No Windows render, no checkpoints, no memory restore; cold-boot Linux ranges only.
- No scenario-image promotion (`publish`); recipe outputs stay in the local cache as build intermediates.
- No gate deletion beyond `services` and `vulnerabilities`; `users`, `data`, `defense`, `misconfigurations`, `roles`, `scheduled_activity`, `active_directory`, and `randomization-not-realized` stand.
- No recipe-runner container pinning (deferred per recipe-references until tool drift bites) and no remote recipe registry.

## Decisions (resolved 2026-10-17)

1. Build-time egress is the posture for online recipes; runtime isolation is untouched; the manifest records build egress use.
2. Vulnerabilities are declarative assertions; exploitability proof is the challenge behavioral checks; no per-vuln exercise bookkeeping.
3. Era golden plus era archives is the period-content pattern; vendoring per recipe as fallback; extraction as last resort; catalog grows on demand (xenial only this phase).
4. The golden slice runs early and parallel (slice 3), so recipe authoring against the real base starts while the manifest work proceeds.
5. Verification caching is all-or-nothing with `--reverify`; checkpoint keying and clean-rebake rules (decided in the spine) are restated here only as the contract later phases inherit.

## Ledger

| Slice | Status |
|---|---|
| 1 recipe bundles and executor | pending |
| 2 `build` verb | pending |
| 3 xenial golden | pending |
| 4 verification engine | pending |
| 5 manifest and invalidation | pending |
| 6 vulhub conversion | pending |
| 7 close-out | pending |

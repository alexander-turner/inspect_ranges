---
type: decision
title: "Challenges v1: the goal-type engine, oracle, prober, and scorer, in seven slices"
status: accepted
tags: [inspect-ranges, challenges, goals, scoring, oracle, prober, decision]
timestamp: 2026-10-15
---

# Challenges v1: the goal-type engine, oracle, prober, and scorer, in seven slices

*Phase plan for the challenges track, successor to [evidence-v1](evidence-v1.md). It implements the design of record: the [challenges-and-goals reviewer document](../challenges-overview.qmd) (circulating externally; the two-track plan keeps the vocabulary open for its feedback while the mechanics build now) and [challenges-scoring-integrity](challenges-scoring-integrity.md) through its eighth amendment. Nothing exists today: `challenge_dataset` and `challenge_scorer` are named in docs only, and the six examples' `challenges.yaml` files are legacy seeds predating the design (vulhub's uses the forbidden fixed-marker `/tmp/pwned`). New code lives in `src/inspect_ranges/_challenges/` (files inside drop the underscore). Lockstep rule throughout: implementation plus failure modes plus battery plus docs plus fresh-context review, or the slice is not done.*

## Scope

In, per the user's decisions (2026-10-15): the full core goal-type table (`flag`, `answer`, `exfiltrate`, `execute`, `control`/`privilege`, `degrade`, `tamper`, `availability`, `detection`, `judge`) plus two of the designed types pulled forward: `hijack` (crash-record proof from the continuous console stream, declared `guest-corroborated` floor, synthetic crash-target in the battery) and `patch` (the vulhub defender dual, re-running the in-repo reference chain at scoring time, explicitly measured). The oracle, plant machinery, submit tool, latching, aggregation, validity states, the mid-run poller, `corroborate()`, the active prober, migration of all six examples' `challenges.yaml`, in-repo reference chains with behavioral checks for the public six, docs. Out, recorded not implied: `eviction` (an absence proof; its own design names the introspected channel as the trigger, and pulling it in pulls `guest-snapshot` into scope); the introspected channel itself (demand-gated, see evidence-v1's close); the generation layer's per-instance draws (kypo's drawn `answer` scores against the resolved default until the draw lands; the gate stays `randomization-not-realized`); `attack_path`; Windows reference chains (goad-light and attack-range-windows migrate validate-only until the images arc delivers Windows-through-provider).

## Settled decisions

- **Two-track discipline**: external-review feedback lands as record amendments plus per-type `Spec`/vocabulary changes without engine churn (the registry isolates types); anything that would change engine semantics comes back to the user before being resolved.
- **Reference solutions live in-repo for the public six** (user decision): they reproduce already-public exploits (exploit-db IDs, vendored upstream READMEs), so their chains land under the battery conventions and run in devbox gates. The dual-use split is explicit: held-out or generated content and novel chains never land in this repository.
- **Performance is measure-first** (user decision): no budget knobs in v1. Every `setup()` and every scorer stage records wall-clock per goal into the eval log, and the batteries produce measurement tables (setup per challenge, score per challenge, corroborate time against evidence size). The user's rule is codified as a design gate: a scorer taking minutes is acceptable; anything measured or projected at fifteen minutes or more is flagged and mitigations are discussed with the user before the phase closes, and every future goal-type design states its scoring cost against this gate. The named future cases that will trip it (introspected dump analysis, TCG-twin replay) are already designed off the scoring path. Design-level efficiency is still design, not budgeting: corroboration scans are scoped by latch timestamp plus segment, and `detection` reads the local exported telemetry stream rather than querying the in-range collector live.
- **The oracle binds the raw channel**: never the provider's convenience wrappers (the oversized-exec wrapper persists argv and env as an on-guest script, the recorded residue leak). `write_file` carries atomic `mode` on the wire; owner assignment is write-0600-as-root then `chown` via raw exec, so only the path ever rides argv. `PlantStore.record` writes the `plants` evidence stream (the reservation from evidence-v1 closes here): host-side T1, never guest-ward. `nonce()` draws independent entropy per call; `resolved()` exposes the sample's `ResolvedPlan` for `answer` goals. The behavioral residue pin from the scoring record is a battery check: a scoring run deposits no plant bytes into guest-visible argv, environment, disk, or wire.
- **The engine**: goal types register through the inspect_ai entry point (`_registry.py`); each type is a `Spec` pydantic model (strict, like the range schema), `setup`/`check`/`compare` with `compare` pure and host-side, declared observers (a deployment that cannot supply one refuses the challenge at planning, positioned issues, the house gate pattern), and `assurance` plus `primitive` labels recorded in the log. Latching is first-pass-wins, timestamped, in the Inspect sample store, shared by the mid-run poller and the end-of-run scorer. Submissions bind through a `submit(goal_id, value)` tool with completion-text fallback for single-goal challenges. `aggregate` covers weights, milestones with `later_implies_earlier`, coverage fractions, and hint penalties; every `Score` carries the validity state (`valid` | `invalid` | `indeterminate`), and infrastructure failure is never read as agent failure.
- **The poller is cheap-tier only**: mid-run ticks check submissions and inexpensive reads for unlatched goals; expensive verification (evidence scans, exploit re-runs) happens once, end-of-run. Poll cadence is a knob with a conservative default; tick outcomes are observable.
- **`corroborate()` detects, never grades**: pcap/console/session evidence is scanned scoped by latch window and segment; a contradiction marks the sample invalid; a coverage gap only flags. Scan time is a first-class measurement row.
- **Detection** evaluates its completeness precondition from the exported telemetry stream's watermark and poll records (evidence-v1 machinery): stall, quiet, and poll failure are distinguished from the sealed record alone, and "no alert" over an incomplete window is indeterminate, never a stealth pass.
- **The reflection rule** (third amendment) is enforced in `tamper` and `exfiltrate`: compared values originate beyond the agent's reach; in-flight canary plants ride oracle sessions, and the placement rule applies to every plant.
- **`hijack`**: the agent steers the fault address to a per-sample disclosed value; the proof is the crash record read from the continuous console stream (T2) with a guest read as corroboration; the declared floor (forging the record costs root on the target) is logged as the assurance scope. The battery target is a small deliberately-crashable binary with a controllable fault address; it is a test artifact, not range content.
- **`patch`**: scoring re-runs the challenge's reference chain (expect fail) and the functional probe (expect pass), BountyBench's shape; the re-run is the phase's one known minutes-scale scorer and carries its own measurement row.
- **The prober** is nonce-bound with declared windows, records DOWN/MUMBLE/degradation measures into its own evidence stream mid-run (the scorer reads recorded results; no end-of-run probing wait), and its attachment mechanism is the phase's one genuine unknown, settled by the spike: the architecture keeps bridges IP-less and the hypervisor unaddressable from any segment, while scoring rule 2 makes visible checks acceptable. The spike weighs a declared probe endpoint in the range container netns against transient attach and AF_PACKET userspace probing, with the containment cost (an addressable endpoint L2-adjacent to the container's stack) and agent visibility stated honestly; the chosen mechanism gets a security paragraph in this record before slice 4 builds it.
- **Battery CID band**: 30500 and up, documented beside the existing bands.
- No licensing commentary anywhere (standing policy).

## The spike (before slice 4)

`design/spikes/challenge-prober/`: probe a real guest HTTP service from outside every VM under the hardened profile. Mechanisms measured: (a) declared probe veth with an IP on the bridge inside the range container netns; (b) transient attach during probe windows only; (c) AF_PACKET raw-socket probing with no IP (userspace TCP for an L7 nonce check). For each: viability of a nonce-bound HTTP probe, what an in-range `arp -a` and a port scan from the agent box show, and the containment conformance battery still green. House spike conventions; output feeds slice 4 and this record.

## The slices

**Slice 1: schema and dataset (pure CI).** `_challenges/schema.py` (challenges, goals with per-type `Spec` dispatch, scoring modifiers, hints, `primitive` defaulting from type), cross-validation against the `RangeSpec` (goal hosts and segments declared; required observers deliverable), `dataset.py` with `challenge_dataset()` producing Inspect Samples. Migrate all six examples' `challenges.yaml` to the schema (the Windows pair validate-only). Acceptance: strict round-trips; positioned refusals for unknown hosts, unknown types, and undeliverable observers; all six examples validate green.

**Slice 2: oracle and plants (CI plus devbox).** `oracle.py` on the raw channel with the write-then-chown owner flow; `plants.py` (`PlantStore` writing the plants evidence stream); `plant_goals()` solver running every goal's `setup()` before the agent acts and refusing up front on a missing observer; the `submit` tool and `submissions_from`. Battery: a scoring run on a live range followed by the residue sweep (no plant bytes in guest argv, environment, or disk; no plaintext plant bytes in the segment pcap, which is ours to check). Failure modes: a plant write failing mid-setup (the sample refuses before the agent starts, never half-planted); chown targets that do not exist (positioned error naming the principal).

**Slice 3: engine and submission types (CI plus devbox).** The registry, latching, `challenge_scorer`, `aggregate`, validity states; `flag`, `answer`, `exfiltrate`, `execute`, `control`/`privilege`. The real-eval gate: migrated vulhub-zabbix scores accuracy 1 under a scripted reference solver and 0 under the cheapest forgeries (a fixed-marker write, a replayed prompt-visible value). Setup and score timings recorded from this slice on.

**Slice 4: prober, prober types, detection, judge, hijack (devbox, spike-informed).** The prober per the spike's mechanism with probe records streaming to evidence mid-run; `availability`; `degrade` (sign-inverted, partial credit via the declared measure); `tamper` (the written value observed from outside, placement rule enforced); `detection` from the exported stream with the completeness precondition (stall, quiet, and poll failure distinguished in tests from sealed records); `judge` (hardened template, weight cap, CI with mockllm); `hijack` against the synthetic crash-target with the forgery negative demonstrating the declared floor (a root-written fake kmsg line passes exactly as the documented guest-corroborated scope says it can). Nonce-binding proven: canned and replayed probe responses fail.

**Slice 5: poller and corroborate (devbox).** The mid-run milestone poller (cheap tier only), latch timestamps feeding window-scoped `corroborate()` over pcap, console, and session evidence; contradiction invalidates, gaps flag; the full timing instrumentation lands here (per-goal rows in the eval log, the measurement tables' machinery in the battery).

**Slice 6: reference challenges and behavioral checks (devbox).** In-repo reference chains for the Linux-bootable four: vulhub-zabbix end-to-end mandatory (the public CVE-2016-10134 chain), kypo-demo's three-level ladder, cyris-basic and mhbench-equifax-small validate-plus-chain-where-feasible with the scoping recorded honestly. Per reference challenge, the three behavioral checks: the reference solution passes through the foothold alone, an insufficient attempt fails, the cheapest known forgery fails. `patch` lands here as the vulhub defender dual reusing the same chain artifact. The measurement table closes the performance story: setup and scorer wall-clock per challenge, corroborate time against evidence size, the patch re-run's own row, each reviewed against the fifteen-minute gate with any approach to it flagged for discussion before close.

**Slice 7: docs and record close.** `docs/challenges.qmd` (authoring challenges, the goal-type reference, custom types, the submit tool, the performance expectations stated plainly); CHANGELOG; this record's ledger and residuals closed against reality; a dated amendment to [challenges-scoring-integrity](challenges-scoring-integrity.md); evidence-v1's `plants` and `session`-consumer residuals closed; proposed (never direct) edits to the user's overview where implementation taught something.

## Conformance trajectory

Slice 3: the vulhub real eval at accuracy 1 with forgeries at 0. Slice 4: nonce-binding negatives and the hijack floor demonstration. Slice 6: the behavioral-check battery across the reference set with the full measurement table.

## Logging and debuggability

Every goal logs one structured line at setup (goal id, type, host, assurance, primitive, elapsed) and one at scoring (verdict, latch timestamp, corroboration status, elapsed); plant values never appear in any log at any level. Poller ticks log outcomes at debug with the per-tick cost. `corroborate()` logs each scan's scope (stream, window, segment) and duration. The scorer's aggregate logs the mode, the per-goal contributions, and the validity state, so a surprising score is explainable from the log alone.

## Review discipline

Every slice closes with a fresh-context review scoped to the slice diff, findings fixed in their own commits; an integrator-spawned fresh-context verification runs per chunk with demonstrated probes before any merge. Standing review weights: no plant material in anything guest-visible or logged; `compare` purity; the forgery negatives actually exercising the cheapest forgery rather than a strawman; timing instrumentation that measures what the tables claim. The daemons, codecs, and wire vectors are untouched by design; every review verifies that.

## Non-goals and recorded follow-ups

`eviction` and the introspected channel (demand-gated per their own records); per-instance variable draws (generation layer; kypo's drawn answer upgrades when it lands); `attack_path`; Windows reference chains (images arc); in-process instrumentation (declined in the scoring record); scorer budget knobs (deliberately absent in v1 per the measure-first decision; the measurement tables are where budgets would be derived if ever needed).

## Ledger

| Slice | Status |
|---|---|
| spike: prober attachment | pending |
| 1 schema + dataset | pending |
| 2 oracle + plants | pending |
| 3 engine + submission types | pending |
| 4 prober types + detection + judge + hijack | pending |
| 5 poller + corroborate | pending |
| 6 reference challenges + behavioral checks | pending |
| 7 docs + record close | pending |

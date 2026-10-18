---
type: document
title: "build-v1 parked list: decisions"
status: accepted
tags: [inspect-ranges, build, images, decisions]
timestamp: 2026-10-19
---

# build-v1 parked list: decisions (user, 2026-10-19)

*Resolutions for the "Parked for the user" list accumulated in [build-v1.md](build-v1.md) during the unattended build-v1 run and its two quality rounds. Each entry records the decision, the rationale discussed, and the implementation shape. Implemented together as one follow-up batch; the ledger row below the parked list records the outcome.*

## 1. Realized-image generation GC — automatic at build success, plus a prune verb

**Decision.** Superseded realized generations are garbage-collected automatically when a build saves its manifest: scoped to that range, keeping the immediately-previous generation per guest (free revert-the-edit rollback), excluding any file a running project references (precise, from the ownership registry plus each live project's `boot.json`), each deletion stage-logged with bytes reclaimed. `inspect-ranges images prune` handles what auto-GC cannot reach (orphans from refused/retracted manifests, generations a crash stranded, cross-range cleanup, `.capturing` temps, orphan sidecars); it reports and requires confirmation, and refuses while ranges run unless forced. `images list` and doctor's Build group surface reclaimable bytes.

**Why.** Measured on vulhub-zabbix: one generation is ~6.9 GB (mysql alone 4.2 GB), and every key-moving edit orphans the edited guest's prior generation, so an afternoon of recipe iteration strands tens of GB; the phase-exit battery's single one-line edit left a 942 MB orphan. An explicit verb alone fails the disks-fill-unknowingly case because the author doing the most legitimate work fills the disk fastest. Build success is the one moment "superseded" is crisply true, the deletion is announced in build output, and the three guards remove the hazards that argued against automation (concurrent consumers, rollback cost, silent destruction). Steady state: at most two generations per range, no user action required. The policy composes with the distribution phase unchanged: "referenced by a manifest" remains the liveness invariant when pulled manifests arrive.

## 2. Baked build-egress artifacts — fix now, at capture and at render

**Decision.** The capture phase cleans the guest before shutdown: `cloud-init clean --logs` (so the realized image carries no instance state and every runtime boot seeds fresh) and removal of the build seed's rendered network config, so neither the build's nameserver (a deployment's VPC resolver IP) nor the already-run marker survives into the captured disk. Belt and braces at the consumer: the runtime render keys each guest's cloud-init instance-id to its image file name (which embeds the build key for realized guests), so even an image captured by an older build re-applies runtime seeds.

**Why.** The recorded hazard was exactly these two artifacts: runtime per-instance config silently skipped as already-run, and a published image embedding the building deployment's resolver. Fixing at capture makes the realized image a clean golden-like artifact; the instance-id keying covers images that predate the fix. Verified live in the battery (the realized runtime guest's network config carries no build nameserver and cloud-init re-ran).

## 3. Manifest deferrals — affirmed, no work

**Decision.** Stand as recorded: `bundle_sha256` populates at render (live since slice 6), `seeds` stays empty until the generation layer, topology allocation remains render-time data in the bundle's plan.json.

## 4. Behavioral failure — keep a refused manifest instead of deleting

**Decision.** A failing behavioral phase saves the manifest WITH its failure recorded in `verification.behavioral_checks` (check failures carry their records; an infra failure carries a synthetic phase-failure record). The gate refuses any manifest whose behavioral checks are not all passes, with a new `range-unproven` code naming the failing check and the rebuild hint. The build's cached fast path requires a fully-proven manifest; guest reuse does not, so the next build after a check-script fix reuses every guest and re-runs only the proof. Deletion (and the retraction machinery it required) goes away: the failing build's own refused manifest atomically replaces whatever was there, under the per-range lock.

**Why.** Proof-or-refuse holds exactly as before (nothing consumable is unproven: the gate refuses), while the iteration cost drops from a full ~8-minute rebuild to a boot-and-prove cycle. Check authoring is iterative (our own vulhub checks took three cycles). This also simplifies the concurrency story the reviews worked through: saving our own build's manifest under the lock replaces the identity-matched deletion.

## 5. Range-name grammar — the schema's strict slug is the contract

**Decision.** The schema grammar (`[a-z0-9][a-z0-9_-]*`, no slash, no dot) is the v1 contract everywhere; the manifest module's grammar aligns to it instead of carrying the spine's one-slash form as unreachable defense. The spine's org-prefixed, one-slash published names arrive with the distribution phase, where they name something (push/publish targets); the spine records that explicitly. The slice-6 ledger wording that overclaimed Q1-grammar enforcement is corrected.

**Why.** Names flow into cache paths and device names; the strict grammar is the safe one, and loosening it today has no consumer. One grammar, one place, until distribution needs more.

## 6. Build-time corroboration — enforced for beacon-declaring goals

**Decision.** The build's bx boot defaults `CAPTURE_CHUNK_MB=1` (environment override respected), and a reference check passes only if every goal that declares `beacon_segment` comes back pcap-corroborated, in addition to the existing 1.0/`valid` bar. Docs state the contract: declare a beacon, prove it lands in capture (chains push filler traffic to rotate the chunk; the vulhub reference chain already does).

**Why.** A beacon that never has to corroborate is theater, and the manifest's "proven" record silently carried weaker assurance than the docs implied outside the battery environment. The chunk-size default makes corroboration attainable in stock builds; the enforcement makes the declaration mean something.

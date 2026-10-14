# Spike: checkpoint cloning — fresh samples from a converged AD range

*Settles queued confirmation spike 4 from the [external review](../../inspect-ranges/external-review.md) (finding 4) and demonstrates the checkpoint artifact defined in [range-build](../../inspect-ranges/range-build.md): the ad-domain spike proved suspend/resume of a converged domain in place; this spike proves what a per-sample runtime actually needs — repeatable, independent clones from a bundled checkpoint, with no state leaking between samples, on a named CPU model instead of `host-passthrough`. Run on the m6i.metal devbox, 2026-10-04. `./run.sh` reproduces everything; `./run.sh down` tears down.*

## Verdict

**The checkpoint model works, and per-sample instantiation costs 3 seconds.** A converged two-VM AD forest (DC + joined member, built on `Skylake-Server-noTSX-IBRS`) was captured as a bundle (disk overlays moved in + memory images + domain XML, 3.5 GB, 19 s capture), the container was recreated to drop every trace of libvirt state, and two samples were instantiated from the bundle in sequence. Sample A planted a secret, verified domain health, then deliberately vandalized the range (deleted the `tester` domain user, dropped files). Sample B instantiated fresh in 3 s and was pristine: the deleted user present, sample A's files and secret absent, a new per-sample secret planted, Kerberos secure channel intact.

## Measurements (metal, wall-clock)

| What | Result |
|---|---|
| Build: boot clones → converged, verified domain (sysprep parallelized with promotion) | **394 s** (vs 554 s sequential in ad-domain; excludes one-time golden install) |
| Checkpoint capture: save both + move disks + dumpxml | **19 s** |
| Bundle size (2 × 4 GB guests) | **3.5 GB** (1.5 G + 0.9 G memory, 0.6 G + 0.5 G disk overlays, 8 KB XML each) |
| Per-sample instantiation: fresh overlays + restore pair + agents up + clocks pushed | **3 s** (both samples) |
| Sample independence | all five checks pass: user restored, files absent, old secret absent, new secret round-trips, secure channel OK |
| Survives libvirt state loss | bundle restored after full container recreation (restore uses the XML embedded in the save image; nothing predefined) |

## How instantiation works (the part that makes clones cheap)

The bundle's disks are never touched: each sample creates qcow2 overlays *at the paths the saved memory image expects*, backed by the bundle's disks (`live/dc01.qcow2 ← ckpt/dc01.qcow2 ← win-golden.qcow2`). `virsh restore` then resumes the pair against disks that are bit-identical to the save instant, which is what makes memory/disk correspondence safe — the hazard the libvirt documentation warns about (restoring memory against changed disks) is structurally excluded because the restored domain only ever sees a fresh overlay of the saved state. Discard = destroy the transient domains and delete the overlays.

Per-sample setup after restore, as [scoring-integrity](../../inspect-ranges/challenges-scoring-integrity.md) requires: clock pushed via `guest-set-time` (Kerberos survived in both samples), fresh proof secret planted from independent entropy.

## Consequences for the design

1. **AD convergence is a range-build-time cost, now in the strong sense**: not just "snapshot restores fast" (ad-domain) but "N independent samples come from one build at 3 s each, provably free of each other's state."
2. **Named CPU models work end to end** (build, save, restore) — the checkpoint carries `Skylake-Server-noTSX-IBRS` as its compatibility statement, which a `doctor` check can verify on a target host. Cross-instance-family restore remains to be demonstrated on an actual second host type (single-host spike).
3. **Multi-guest skew is tolerable at this scale**: the two saves are serialized (~10 s apart) and the secure channel survives in every restore; ranges with tighter inter-guest protocol state should re-verify.
4. The capture ordering matters and is cheap to get right: save (which stops the domain) → move disks into the bundle → dumpxml → undefine. Nothing copies; the 19 s is dominated by writing 2.4 GB of memory images.
5. Remaining for the range-build pipeline: bundle checksums + the manifest wrapper, eviction of memory images from hot cache, and the second-host restore test.

## Files

- `run.sh` — build (parallel sysprep/promotion), checkpoint capture, container recreation, destructive sample A, pristine-verification sample B
- `assets/boot-ad.sh` — clones on the named CPU model
- `ga.py`, `assets/{autounattend.xml,install.sh}` — copied from the ad-domain spike
- `tmp/run1.log` — the clean first-try run

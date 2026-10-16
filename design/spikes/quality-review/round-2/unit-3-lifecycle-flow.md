# Round 2, Unit 3: lifecycle flow end to end, report

Worktree: `/home/USER/inspect_ranges/.claude/worktrees/r2-u3-lifecycle` (detached at c68cc93). Probes kept uncommitted: `probe_host_seal_hole.py`, `probe_aclose_envelope.py` (both runnable; tmp data removed). Implicated tests re-run green: `test_provider_lifecycle.py`, `test_host_reaper.py`, `test_host_applier.py`, `test_evidence_sealer.py`, `test_evidence_session.py` (85 passed).

Method: read the five named design records plus range-host-v1.md and evidence-v1.md first, then the composition acquire -> realize -> execute -> finalize -> destroy across `_provider/provider.py`, `_provider/evidence.py`, `_host/{leases,reaper,local,remote,applier,stages}.py`, `_runtime/{up,down,ownership,rangeimage}.py`, `_cli/{upcmd,reapercmd,appliercmd,evidencecmd}.py`, and `_channel/channel.py`'s realize/teardown verbs; then each recent feature (evidence sealing, owner records, scoped egress, readiness allowances, fd hygiene, admission charges, lease anchors) checked against each recovery path (reaper, cli_cleanup, down/down --all, task_cleanup both arms, applier restart).

## Findings

### F1 (correctness, traced arithmetic, the A10 class on its sibling gaps): the realize per-report envelope covers only the verify->terminal gap; three other report gaps can legally exceed the 180 s allowance

Round-1 A10 added a plan-derived allowance for exactly one gap (`src/inspect_ranges/_host/remote.py:148-154`; consumed at `src/inspect_ranges/_channel/channel.py:952-959`). Every other gap keeps the flat 180 s channel allowance (`_channel/protocol.py:31`, applied at `channel.py:951,961`). The applier's `up` legally spends longer than that inside three of those gaps:

1. **request -> first report (`fetch`)**: everything before `up`'s first stage-log write happens silently, per-guest image sha256 verification (`_runtime/up.py:430-437`, multi-GB reads) and `ensure_range_image` (`up.py:439-444`), which on first use runs a full docker build bounded at **1800 s** (`up.py:42`). The first `on_stage` event only fires at `up.py:449-451`, after the build. This cold-image leg is reachable by design: the doctor records a missing range image as a *warning* with the fix text "`inspect-ranges up` builds it on first use" (`_doctor/checks.py:680-687`), and the applier's startup gate is the readiness subset only, platform, virtualization, docker (`checks.py:79-103`, `_host/applier.py:171-177`). So the first realize on a fresh applier host spends up to ~30 min before its first report while the driver's realize allows 180 s.
2. **`construct` -> `boot`**: the construct report is emitted at `range-image ok` (`up.py:451`, `_host/stages.py:29`); the next report is at `guest-boot start` (`up.py:508`). Between them sits `compose up -d --wait --wait-timeout <readiness_timeout>` bounded at readiness_timeout + 60 = **360 s** (`up.py:489-501`).
3. **`boot` -> `verify`**: the boot script exec is bounded at readiness_timeout = **300 s** (`up.py:509-514`).

Each layer is sane alone (B21 bounded `up`; A10 bounded the verify gap); the sum of up-side stage bounds vs the realize per-report allowance is unowned for these three gaps, the exact round-1 "cross-layer envelope mismatch" and "sibling-arm drift" classes (the verify arm got the allowance, its siblings did not).

Consequences when a gap trips: the driver raises `ChannelBudgetError` (`channel.py:970-972`), which is **not** an `UpError`, so (a) it bypasses the layer-3 respin classification entirely (`_provider/provider.py:389-406` respins only `UpError` with a transient stage) and fails the sample on a self-resolving condition (the image build completes and would be a cache hit on the respin); and (b) the unwind's teardown (`provider.py:506-527`) runs while the applier's deliberately detached `_execute` task is still driving `up` (`applier.py:473`, realize execution survives client loss by design), so a successful unwind releases the CID lease and host lease while the orphaned boot can still bring up VMs on those freed CIDs until it eventually fails. Local topology is unaffected (no per-report budget). The recorded growth path from the A10 disposition (wire-carried readiness/envelope fields on `RealizeRequest`) is the natural home for a fix; flooring the first-report allowance at the image-build bound, or gating the applier's startup on the range image, are smaller shapes. Not fixed, per charter.

### F2 (correctness, probe-backed): an applier restart mid-sample leaves the host evidence record permanently unsealed; the promised reap-seal recovery can never fire because the surviving driver releases the lease

The chain, each leg individually by design: applier restart empties `Applier._evidence` (recorded limitation, `applier.py:9,157`). The surviving driver's sample fails on the lost relay map; `_destroy` runs: driver-side `finalize()` seals the **driver** writer; `down` goes through the NEW applier whose `_stop_evidence` is a no-op (`applier.py:679`, entry absent), so the **host** writer's record is never sealed; `read_host_seal()` misses and only warns "binding carries the driver seal only" (`_provider/evidence.py:309-335`); then `_release_host` **removes the lease** (`provider.py:544`, `_host/local.py:214-218`). The reaper's sweep selects only leases that still exist (`_host/leases.py:188-206`, `_host/reaper.py:97`), and `cli_cleanup`'s reap-seal also iterates leases (`provider.py:671-694`), so the recovery every comment promises never runs. There is no manual seal verb either (`_cli/evidencecmd.py` is verify-only).

Probe (`probe_host_seal_hole.py`, output verbatim):
```
no host seal at .../evidence after teardown (the applier's seal failed or evidence was off host-side); binding carries the driver seal only
reaper sweep outcomes: []
driver sealed=True (complete)
host sealed=False  <- permanently unsealed, no recovery path
```

Why it matters: evidence-v1's claim is "the lifecycle makes unsealed-at-rest an anomaly (finalize and the reaper both seal)", and an unsealed record is extendable as well as truncatable, here the pcap/console capture record of a completed sample stays forgeable at rest after a *normal* driver-driven teardown. The recorded A6 wording covers only the sink-unresponsive variant and says so honestly; the restart variant's own messages actively promise the unreachable recovery: `applier.py:674` ("the reaper reap-seals it honestly (the recorded restart limitation)"), `applier.py:703-708` ("the reaper reap-seals after lease expiry"), module docstring `applier.py:5`, and `evidencecmd.py:90` ("unsealed-at-rest means neither happened", here both happened). Natural fix shape (not applied): driver-side `seal_abandoned` on the `read_host_seal` miss path, the driver is at exactly the reaper's point in the ordering (after teardown, before lease release) and `seal_abandoned` already exists and skips sealed writers. The `cleanup=False` and kill-9 variants are fine (lease survives, reaper covers them); only the surviving-driver composition is holed. CI pins the shutdown half (`tests/test_host_applier.py:731`) but no test covers this composition.

### F3 (correctness, probe-backed, lower consequence): `Applier.aclose`'s 5 s outer timeout is smaller than `_stop_evidence`'s own internal bounds, reintroducing the A6 anti-pattern on the shutdown path

`aclose` wraps each lease's `_stop_evidence(lease_id, seal=False)` in `asyncio.timeout(5.0)` (`applier.py:230-231`). Inside, `streamer.stop(stop_timeout_s=6.0, harvest_timeout_s=10.0)` is internally bounded at roughly two stop windows plus one harvest (~22 s, `_evidence/capture.py:303-308`), and the applier-shutdown gap records plus `checkpoint()` follow under a further 10 s reserve (`applier.py:694-709`). The teardown-path sibling deliberately has *no* outer timeout because "an outer timeout would cancel its own gap-recording handlers mid-write (review finding on A6)" (`applier.py:681-684`); the shutdown arm drifted back to one, and sized it below the phase it wraps. So whenever a stop takes more than 5 s (the wedged/slow tap is the exact case gap records exist for), the stop is cancelled mid-write, the promised explicit `applier-shutdown` gaps and the checkpoint never land (the entry is already popped at `applier.py:678`, so nothing retries), and the unsealed record shows no trace of the cutoff.

Probe (`probe_aclose_envelope.py`), both directions:
```
PROBE_STOP_S=7.0:  aclose took 5.0s   sealed=False gap causes=set()        applier-shutdown gap present: NO (promise broken)
PROBE_STOP_S=0.1:  aclose took 0.1s   sealed=False gap causes={'applier-shutdown'}   applier-shutdown gap present: YES
```
Fixture note (the round-1 "fixture more permissive than the seam" class): the existing pin `test_applier_shutdown_leaves_evidence_unsealed_with_gaps` uses the CI dead tap whose stop returns instantly, so the 5 s envelope can never fire there and the mismatch is structurally invisible to the suite.

### M1 (mechanical, envelope accounting drift): the applier's admission never charges its resident host-writer evidence buffer, while the driver's admission symmetrically does

Driver side: `resolve_evidence_session` adds one 64 MiB buffer cap per *driver-resident* writer to the sample's memory charge (`provider.py:186-198`, `evidence.py:117-120`, `sink.py:47`). Applier side: `_refusal` charges `plan.totals` only (`applier.py:536-541`), yet `_start_evidence` creates a 64 MiB-capped host writer resident in the applier process (`applier.py:641-647`). evidence-v1.md's settled decision says evidence volume joins the `WeightedAdmission` accounting; the applier's own gate misses its share (~3 GiB unaccounted at the 48-range density point). Small but it is the same drift pattern round 1 kept finding between sibling admission sites.

## Considered and declined

- Reaper teardown racing a still-running realize (expired lease mid-`up`): needs a wedged `up` outliving a whole 600 s TTL after B21's bounds; residue converges via `down --all`; the driver-triggered variant is folded into F1.
- Driver teardown reply budget (180 s) vs applier teardown worst case (~750 s under a wedged docker, `down.py:23` per call): only trips when docker is already failing loudly; converges through the task_cleanup/reaper retry anchors with idempotent teardown.
- `down --all` deleting the whole staging root including concurrent samples' bundles: `--all` is the kill-everything sweep by design; it tears those projects down anyway.
- `cli_cleanup` under uds with a dead applier strands projects until lease expiry (no direct-down fallback, unlike the reaper): the asymmetry is the deliberate B18/slice-3 charge-leak rule; the reaper is the recorded recovery.
- Reaper socket from `lease.origin` vs cli_cleanup socket from `INSPECT_RANGES_HOST`: immaterial on the one-host v1 topology.
- Reap-seal best-effort then lease release (one sealer failure loses the retry anchor): recorded "evidence trouble never blocks reclamation", and B14's `bounded_put` already retries inside.
- Local-topology `cleanup=False` seals `complete` at abandonment while the range keeps running: documented "honest to the abandonment point" (provider.py:588-595).
- Driver session disabled (open failure) skipping `read_host_seal`, losing a host seal that exists: behind an already-loud "sample proceeds WITHOUT evidence" failure; cosmetic.
- `_lease_locks` entries from refused realizes, `_runs` growth: popped at teardown; the 64-run FIFO cap and its eviction edge are documented in code (`applier.py:72-76`).
- Heartbeat guest states persisting as `failed` after a failed realize until the next one: honest in the interim.
- StageRecorder buffering failed-attempt stages until a boot succeeds: documented deliberately (`evidence.py:9`).
- Second-cancellation owner-record residue, applier-restart charge/relay/replay loss, Go pid-reuse window: recorded residuals, not re-reported (F2 reports only the unrecorded sealing *composition* consequence of the restart, not the restart limitation itself).
- Emit-vs-`run.finish()` ordering in `_execute` (run_coroutine_threadsafe): traced safe, uncontended `Condition` acquire never yields, and all emits are queued before the to_thread continuation.

## Quality paragraph

The lifecycle flow is in strong shape. The core ordering invariants, ownership written before any resource exists, nothing freed before a successful teardown, the host lease as the last-removed retry anchor, admission charged exactly once and released symmetrically, are enforced consistently and identically across all five recovery paths, and the round-1 sealing fixes (A6, A7) genuinely hold where they were aimed: finalize is phase-split with a protected seal reserve, cli_cleanup reap-seals before releasing the lease, and the reaper's order is correct and crash-resumable. What remains clusters exactly where the round-1 taxonomy predicted it would: budget sums across layers that nobody owns (F1 is A10's own fix pattern un-applied to its sibling gaps; F3 is the A6 anti-pattern re-grown on the one arm the A6 review did not touch; M1 is the admission-site twin of both), and the newest feature missing from a recovery composition (F2: every leg of the applier-restart story is individually recorded and correct, but the composition with a surviving driver silently defeats the sealing lifecycle and every comment that promises otherwise). Nothing found rises to blocking, nothing touches containment or scoring directly, and the volume is well below round 1, which is the expected and honest result for this unit.

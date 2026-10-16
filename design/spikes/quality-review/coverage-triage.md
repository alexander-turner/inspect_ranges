# Coverage triage (quality review, phase 1)

Measured 2026-10-16 via `make coverage` (new target: branch coverage, CI suite only, both REQUIRE flags; 1335 passed / 75 skipped / 3 xfailed). Headline: **87% line+branch across 10,777 statements**. This document triages every uncovered region into three buckets: (a) load-bearing gap with a proposed behavior-named test, (b) VM-battery-covered with a verified citation, (c) justified exclusion. Method honesty: regions in bucket (a) and all battery citations were read directly (source and battery script); micro-branches grouped at the end were classified from their line ranges and the surrounding read code, not line-by-line.

## Per-module headline (modules below 95%)

| Module | Cover | Dominant reason |
|---|---|---|
| `_challenges/evidenceread.py` | 15% | both public helpers never run in CI (bucket a) |
| `_devbox/__init__.py` | 23% | dev-only operator surface (bucket c) |
| `_cli/imagescmd.py` | 26% | command bodies run in devbox batteries (bucket b) |
| `_cli/appliercmd.py` | 33% | spawned as a real process by batteries (bucket b) |
| `_channel/vsock.py` | 34% | AF_VSOCK transport, CI cannot open it (bucket b) |
| `_cli/upcmd.py` | 35% | battery-driven CLI body (bucket b) |
| `_challenges/setup.py` | 37% | solver body runs in real evals (bucket b) + unwind-failure branches |
| `_cli/plancmd.py` | 70% | render flags battery-driven (bucket b) |
| `_challenges/goaltypes.py` | 75% | **exfiltrate check/compare untested anywhere** (bucket a) |
| `_cli/reapercmd.py` | 75% | fresh-shell reaper runs in batteries (bucket b) |
| `_provider/evidence.py` | 80% | finalize/host-seal failure paths (bucket a) + battery paths |
| `_evidence/location.py` | 80% | `sample_active` path runs in real evals (bucket b) |
| `_challenges/poller.py` | 81% | stop-timeout guards (bucket a, one test) + eval-only paths |
| `_challenges/pcapscan.py` | 81% | parser edge branches adjacent to covered guards |
| `_runtime/down.py` | 82% | teardown branches battery-driven (bucket b) |
| `_provider/ops.py` | 83% | retry/confirm-session branches partially battery-only |
| `_challenges/scorer.py` | 83% | `@scorer` wrapper eval-only (b) + defensive guards (a) |
| `_host/remote.py` | 83% | two-process error branches (b, partial) |
| `_provider/provider.py` | 84% | double-cancellation drain (a) + eval-only registration paths |
| `_challenges/oracle.py` | 85% | evidence accessors run against real records (b) |
| everything else | 86-100% | micro-branches, see the grouped note |

## Bucket (a): load-bearing gaps, proposed tests (behavior-named; nothing written yet)

1. **T1 `evidenceread` span alignment** (`evidenceread.py`, 15%): both `stream_json_records` and `stream_chunks_with_spans` are unexecuted in CI; the chunk-to-span position zip decides every window verdict (detection, evade, telemetry classification). Test: records read from a real `LocalDirSink` record carry their chunk's wall span; a chunk missing its span entry defaults to (0.0, 0.0); the gapped flag reflects in-chain gap records.
2. **T2 exfiltrate compare** (`goaltypes.py` 160-174): the canary-containment rule (canary in submitted content, or exact match; presence-only never passes) is the proof contract of a core type and has NO coverage anywhere: refchains covers flag/answer/execute/control/patch, mhbench migrated without a chain. Test: containment achieves, exact match achieves, unrelated content and empty submission fail.
3. **T3 exfiltrate corroboration** (`goaltypes.py` 149-155, 166-173): source-bound pcap corroboration with probe-MAC exclusion for exfiltrate specifically (pcapscan has its own tests; the type's wiring of src resolution and exclusion does not). Test over synthesized frames: right-source corroborates, wrong-source and probe-MAC frames do not.
4. **T4 answer oracle-read source** (`goaltypes.py` 106-117): the host+path source reads the expected value via `read_file(user="root")`; untested in CI and the refchains kypo ladder uses the variable source. Test against the fake channel: root read becomes the expected value; comparison host-side.
5. **T5 scorer never-raise guards** (`scorer.py` 186-204): a latch-read failure degrades to empty records and a corroborate crash degrades to an incomplete flag; neither errors the sample. The hardening suite pinned the write guards but not these two read/compose guards. Test with a hostile store and a raising corroborate seam.
6. **T6 finalize budget** (`_provider/evidence.py` 236-258): the 30 s finalize budget with a hanging sink stops producers, logs the unsealed warning, and teardown proceeds. This was demonstrated only by an UNCOMMITTED verifier probe (chunk-3 verification); the behavior has no durable pin. Test with a never-returning fake sink and a short injected budget.
7. **T7 host-seal fallback** (`_provider/evidence.py` 262-281): a missing applier-side host seal degrades the binding to driver-only with the warning, never raises post-teardown. Test against a store without the host seal.
8. **T8 corroborate unverifiable trio** (`corroborate.py` 181-211): identity unresolved, chunk fetch failed, and plant missing each yield `unverifiable` plus the incomplete flag, never an exception. Table-driven over the three injected failures.
9. **T9 provider second-cancellation drain** (`provider.py` 368-387): a second cancellation during the unwind drain abandons the gather, cancels pending acquire/render/boot, and still runs the unwind exactly once (no lease left with a live renewal). The first-cancellation path is pinned; this branch is not.
10. **T10 realize reconnect** (`channel.py` 881-890): a `ConnectionError` on reconnect during realize-resume backs off and replays the already-seen stage reports before new ones. The resume-replay contract is pinned via a different entry; the connect-loss branch is not.
11. **T11 reap-seal continuation** (`sealer.py` 55-66): a lost seal race (FileExistsError) and a delivery failure each continue to the remaining writers instead of aborting the reap-seal.
12. **T12 poller stop timeout** (`poller.py` 118-126): a wedged tick makes `stop()` log the timeout and return within budget, never raise.

A systemic observation for the findings checkpoint: several load-bearing behaviors (T6, and previously the stall classification and wall probes) were demonstrated only by verifier probes that were deliberately left uncommitted. Where a probe proved an integrity property, the property deserves a durable pin; T1-T12 convert the coverage-visible subset.

## Bucket (b): VM-battery-covered (citations verified by reading the battery code)

| Region | Battery (file, driving check) |
|---|---|
| `_channel/vsock.py` transport body | every devbox battery boots through the provider's `VsockTransport`; e.g. `design/spikes/challenges-v1/refchains_battery.py` (real `inspect_eval` samples over vsock), `design/spikes/range-host-v1/lifecycle_matrix.py` |
| `_challenges/setup.py` `plant_goals().solve`, `run_setup`, `_start_producers` | `refchains_battery.py`, `engine_battery.py`, `poller_battery.py` (grep-verified: `plant_goals` in each task's solver chain); `evade_battery.py` and `observed_battery.py` drive types against the live oracle directly, not through the solver |
| `_challenges/scorer.py` `@scorer` wrapper (245-271) | `refchains_battery.py`, `engine_battery.py`, `poller_battery.py`: Scores asserted from the eval log |
| `_evidence/location.py` `sample_active` identity (40-61) | `refchains_battery.py` and `engine_battery.py` assert the evidence binding in the eval log, which only resolves through this path; CI pins the private API shape |
| `_challenges/prober.py` sidecar subprocess runner (39-51) | `observed_battery.py` via `run_observed.sh`: live nonce probes through the rendered sidecar |
| `_challenges/oracle.py` evidence accessors incl. `_telemetry_export_fetch` | `evade_battery.py` and `observed_battery.py` (grep-verified oracle accessor use; detection/evade from the live export), `engine_battery.py` (pcap beacon); the export substrate itself also proven by `design/spikes/evidence-v1/telemetry_battery.py` |
| `_provider/provider.py` eval-only registration/cleanup paths | `refchains_battery.py` (foothold-only wall asserted live), `lifecycle_matrix.py` |
| `_provider/ops.py` confirm-session retry branches | `self_check` batteries (range-host-v1 44/44 run) exercise the session re-pin paths on real daemons |
| `_host/applier.py`, `_host/remote.py`, `_channel/uds.py` two-process branches | `design/spikes/range-host-v1/run.sh` + `applier_proc.py` (real applier process), `design/spikes/evidence-v1/seam_battery.py` (applier-side capture + seal) |
| `_evidence/sealer.py` success path | `seam_battery.py` kill -9 scenario: reaper reap-seals and the record verifies off-instance |
| `_evidence/capture.py` streamer main cycle and injury branches | `design/spikes/evidence-v1/battery.py` (backpressure, capture kill, gap records) and `run_seam.sh` |
| `_runtime/up.py` / `down.py` / `images.py` boot and teardown branches | `design/spikes/realizer-batteries/phase-exit.sh`, `design/spikes/up-core/run.sh`, and every booting battery |
| `_cli/appliercmd.py` | spawned as the real `inspect-ranges applier` process by `applier_proc.py` |
| `_cli/reapercmd.py` | fresh-shell reaper invocation in `lifecycle_matrix.py` |
| `_cli/upcmd.py`, `_cli/imagescmd.py`, `_cli/plancmd.py` render flags | `realizer-batteries/phase-exit.sh`, `design/spikes/images-derive/run.sh`, `evidence-capture/run.sh` and `challenge-prober/run.sh` (`--evidence-capture`, probe rendering via the CLI) |

Battery coverage is real but unmeasured (coverage instruments the CI suite only); the citation column is the audit trail.

## Bucket (c): justified exclusions

- `_devbox/__init__.py` (23%): dev-only operator CLI driving real AWS; exercised by daily devbox use, out of the test mandate.
- `__main__.py` (0%): `python -m` entry stub.
- `__init__.py` lines 5-6: version fallback for a non-installed tree.
- `_channel/mocks.py` 204-206, 307-309: test-harness knob combinations no current test selects; they exist for future conformance variants.
- Grouped micro-branches (~120 of the 1228 missed statements across 20 modules): defensive log-and-continue arms adjacent to covered guards (e.g. `capture.py` remove-retry, `dnsmasq`/`egress` render fallbacks, `_diagnostics` loc-walk edge arms, `uds` preamble-garbage close paths partially covered by two-process tests). Per the charter, no line-chaser tests are proposed; any of these that a phase-2 review unit flags as a real defect gets its test through that finding instead.

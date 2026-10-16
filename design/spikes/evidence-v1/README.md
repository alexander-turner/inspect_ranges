# evidence-v1 battery

The live battery for the evidence-v1 phase ([record](../../inspect-ranges/evidence-v1.md)). This README accumulates per-slice sections as the phase lands; the headline kill -9 / compromise-window demonstrations arrive with slice 5 (seam wiring).

## Slice 2: capture in the range container (2026-10-15)

Run on the metal devbox: **24/24 checks green plus zero residue**, `./run.sh`, CID base 30100, shared battery flock. Re-run green after the fresh-context review's fixes (51.0 s up), whose main change is the fail-safe ship rule: a chunk ships only when the supervisor's status proves it completed (strictly older than the declared active file, or a writer-less segment state), so a missing or stale status can delay shipping but can never truncate a chunk. The range is a static-IP two-segment topology (dmz / internal, router, attacker) rendered with `evidence_capture=True` at 1 MB chunks and `CAPTURE_MAX_RESTARTS=2`.

What the run demonstrated, in order:

- **The floor holds**: the rendered compose grants the range container the measured eight capabilities only; the capture sidecar carries `CAP_NET_RAW` alone (`cap_drop: ALL`), per the evidence-capture spike's recommendation. Asserted from the bundle, then exercised live.
- **Boot cost is noise**: range up with the sidecar at **50.7 s** against the ~50 s 4-VM enforced-ready baseline.
- **Consoles stream continuously**: `console/<guest>` chunks for all four guests shipped while the range was healthy, not pulled on failure.
- **Per-segment correctness from shipped chunks alone** (each clause asserted by the battery, not just observed): the cross-segment ping's frame count is **identical on both** `pcap/dmz` and `pcap/internal` and covers at least all 8 echo frames (observed 14/14), the same-segment ping appears in `pcap/dmz` only (at least 8; internal exactly 0; observed 8/0), and the 8000-datagram UDP flood is **complete** on the internal stream (exactly 8000). All counts come from replaying the sealed evidence record offline, which is the point.
- **Live shipping under rotation**: the flood rotated 1 MB chunks and the streamer shipped them while the range ran (23 MB evidence record total); every guest daemon still answered during and after the flood (evidence pressure never destabilized the sample).
- **Injury is visible, bounded, and in-chain**: killing the dmz tcpdump produced a `capture-restart` gap; killing it past the restart bound produced `exhausted` state and a `capture-dead` gap; tcpdump's own stderr (including the kernel-drop summaries it prints on exit) shipped as `capture-stderr/dmz`.
- **The record closes honestly**: seal `complete`, `inspect-ranges evidence verify`-equivalent offline replay unbroken, `stages` carrying `ready`, `verify` carrying readiness events, heartbeats present throughout.

Files: `run.sh` (setup + battery + residue check), `battery.py` (the checks), `spec.yaml` (the two-segment range). Artifacts land under `tmp/` (gitignored).

## Slice 4: in-guest telemetry export (2026-10-15)

Run on the metal devbox: **18/18 checks green plus zero residue**, `./run_telemetry.sh`, CID base 30300, shared battery flock, range up 50.7 s. The range is the minimal telemetry shape (`spec-telemetry.yaml`: one segment, one target, the attacker); the driver-side `TelemetryPoller` polls two collectors on the target over vsock at 0.5 s cadence: a journald `command` source (`journalctl --after-cursor={cursor} --show-cursor`) and a file source (`/var/log/tele.log`, offset watermark), both into one `driver` evidence record.

What the run demonstrated, in order:

- **Events flow with watermarks advancing**: a real in-guest appender (0.3 s period) and `logger`-emitted journald events both appear in the record; the file watermark advanced across at least 3 separate polls and the journal cursor was extracted and re-substituted per poll.
- **A producer kill is a visible stall, not silence**: after `pkill` of the appender, at least 4 further polls ran (proven from the record's own poll counters), every one `quiet` with the watermark frozen; coverage demonstrably continued. The paired post-hoc invariant: every data chunk corresponds to an `ok` poll, so nothing shipped during the stall.
- **An unreachable guest is a poll-failed gap, and recovery is clean**: `virsh suspend` of the target produced `error` meta records and exactly one in-chain `poll-failed` gap for the streak; after `virsh resume`, polling recovered with no chain break.
- **Log truncation is a watermark regression**: `: > tele.log` produced the `watermark-regression` gap and shipping resumed from the new content.
- **The record closes honestly**: seal `complete`, offline verify unbroken **with the seal binding supplied** (`expected_seals`), journald and file events both present, every non-error poll carrying its watermark.

Re-run green (18/18, zero residue) after the fresh-context review's fixes, whose main changes are content-anchored regression detection for file sources (a truncate that regrows past the old offset is caught by a shipped-prefix digest, and rotation surfacing as ENOENT after shipped content is a regression, not an absence), cursor-banner stripping with banner-only polls reading as quiet (stall-vs-quiet stays decidable for command sources and the data stream carries events only), a bounded cursor-search window over adversarial guest output, an explicit replay flag on post-reset bootstrap polls, a restart-after-stop refusal, and a bounded `stop()` that cancels a hung poll.

Two operational findings worth keeping: the production daemon reaps the exec's process group on return, so an in-guest background producer must `setsid` to survive its starting exec (the prototype-era "background processes survive" no longer holds unqualified); and live battery predicates must be delivery-lag immune (assert from the record's own poll counters, never from counts of delivered-so-far chunks, which lag appends by a flush).

Quality-review fix round (2026-10-16): re-run green twice more (18/18 plus zero residue each), once after the finding fixes (A3 single-line cursor stripping, so an event line embedding the pattern can no longer be silently suppressed; B11 replay-flag survival past a failed bootstrap) and once after that round's own code-review refinements (cursor taken from the final non-empty line only, with a suppressed banner at worst mis-taking the single trailing line and surfacing loudly on the next poll; the replay flag kept by an empty-output bootstrap and cleared unmarked by a banner-only one, so it uniformly means this poll shipped possibly-duplicate entries).

Files: `run_telemetry.sh`, `telemetry_battery.py`, `spec-telemetry.yaml`. Artifacts land under `tmp-telemetry/` (gitignored).

## Slice-5 section: the provider/host seam (run_seam.sh)

Devbox, 2026-10-15: 39 checks green (32 in S1-S4 plus 7 eval-smoke checks), zero container residue, zero S3 residue, exit 0. The S3 leg ran against the chunk-3 scratch bucket under a per-run prefix, removed at the end.

| Measurement | Value |
|---|---|
| 4-VM sample boot with capture + evidence wiring on (budget stated in advance: 56 s vs the ~51 s chunk-2 baseline) | 51.9 s |
| kill -9 to reaper reclaim (lease TTL 20 s) | one sweep after expiry |
| Unreferenced trailing chunks after the kill (the manifest-batching crash window, listed never broken) | 1 |

Headlines, as run: (S1) a normal provider sample streamed to real S3 while live; the binding (both writers' seal digests plus chain heads) verified from a scrubbed subprocess; in the compromise window a conditional re-put of a delivered chunk was refused 412 by the store, and a post-window PLAIN overwrite (this bucket carries no deny-overwrite policy; the chunk-3 IAM limitation) was detected by the binding-holder as a chunk-size break at the forged key: tamper-evident, exactly the claim. (S2) the driver was SIGKILLed after a manifest part committed; the reaper reclaimed the range and reap-sealed the host record (`reaped`); the record verified off-instance with every pre-kill chunk present. (S3) a 1 MB buffer cap under the flood produced explicit in-chain `buffer-cap` gaps, an unbroken chain, and a range whose daemons kept answering. (S4) the separated topology: the APPLIER owned the host capture writer, driver streams stayed driver-side, and the binding carried both digests. (S5) a real `inspect eval` (mockllm) left the store binding in the eval log, the evidence beside the log via the `sample_active()` identity path, and `evidence verify --expect-seal` from the log's binding alone exited 0.

Battery-driven findings fixed in the slice: a relative inspect log location produced a relative (cwd-bound) binding path, so filesystem locations now absolutize at derivation; the kill headline is scoped to COMMITTED evidence (a delivered manifest part), with trailing chunks the recorded batching trade-off; `sweep` must be driven via a thread from async callers (the reap-sealer runs its own event loop); and inspect's loader requires a relative task path.

Post-review re-run (same day, after the 8-finding fresh-context review round): 39 checks green again, up 51.7 s, zero container and S3 residue.

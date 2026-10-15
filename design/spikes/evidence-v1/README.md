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

Two operational findings worth keeping: the production daemon reaps the exec's process group on return, so an in-guest background producer must `setsid` to survive its starting exec (the prototype-era "background processes survive" no longer holds unqualified); and live battery predicates must be delivery-lag immune (assert from the record's own poll counters, never from counts of delivered-so-far chunks, which lag appends by a flush).

Files: `run_telemetry.sh`, `telemetry_battery.py`, `spec-telemetry.yaml`. Artifacts land under `tmp-telemetry/` (gitignored).

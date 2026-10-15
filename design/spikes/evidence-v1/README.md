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

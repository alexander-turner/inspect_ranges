# challenges-v1 battery

Live batteries for the challenges-v1 phase (`design/inspect-ranges/challenges-v1.md`). CID band 30600+ for the oracle section (the prober spike holds 30500); exclusive via the shared battery lock at `/tmp/inspect-ranges-battery.lock`. Artifacts under `tmp/` (gitignored).

## Slice 2: oracle planting and the residue sweep (`./run_oracle.sh`)

A two-segment range (the evidence-v1 shape: dmz and internal joined by a router, eight-capability floor, capture sidecar on) boots at CID 30600; a real `EvidenceSession` owns capture, and a `RangeOracle` over the raw vsock channel plants a flag-shaped value (`web:/root/crown-flag`, 600 root) and an owner-bound value (`db:/opt/owned-secret`, 600 daemon) through `run_setup`. The sweep then proves the residue rule on live guests:

- **proc**: every guest's `/proc/*/cmdline` and `/proc/*/environ` dumped out (base64 over exec, compared host-side so the sweep itself never sends a value guest-ward) and scanned for both values.
- **disk**: `find / -xdev -type f -newer <pre-plant marker>` per planted guest; every new file read back host-side and scanned, the declared plant paths excluded.
- **placement**: `stat` shows exactly `600 root` / `600 daemon` (the mode rides the write atomically; ownership transfers by a path-only root chown).
- **evidence**: the `plants` stream carries both digests in order and zero value bytes.
- **wire**: the live per-segment pcap (real cross-segment noise generated first, so the check is non-vacuous) contains no plant bytes; the control plane is vsock, not a network.

The failure leg plants one goal then targets a nonexistent guest: setup refuses with the prior plant removed from the guest and discarded from the store (`planted`/`unwound` events in the stream). The record then seals and verifies offline.

### Results

<!-- filled from tmp/logs/oracle_battery.txt after the runs -->

## Honest notes

- Per-plant setup timings print from the `inspect_ranges.challenges` logger (the measure-first rows); the eval-log timing instrumentation is slice 5.
- The disk sweep's scope is files modified since the pre-plant marker on the planted guests: a plant value cannot land in an unmodified file, and plant-adjacent churn (logs, caches) is exactly what the mtime window catches.
- `root` plants on the CI endpoint are emulated (the test host cannot chown); this battery is where the real daemon's root chown and 0600-atomic write are proven on live guests.

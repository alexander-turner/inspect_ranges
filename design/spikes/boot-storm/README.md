# Spike: boot-storm density — concurrent ranges on one host

*Measures the per-host density question from the performance envelope's "not yet measured" list: how many ranges can one host start simultaneously, and what does degradation look like? The storm unit is the production shape — one range container per range (own netns, bridge, per-VM cloud-init seeds, vsock daemons on per-range CIDs) with two Linux VMs — launched N at a time, each range timed from storm start to fully provisioned (both VMs cloud-init complete). Run on the m6i.metal devbox (128 vCPU / 503 GB / 500 GB gp3 EBS root), 2026-10-04. `./run.sh` reproduces (`ROUNDS="..."` to vary); `./run.sh down` tears down everything.*

## Verdict

**No knee through 48 concurrent ranges (96 VMs): degradation is graceful and the host is nowhere near saturation.** Median time to a fully provisioned range rises from 47 s solo to 77 s at 48× density (+61%), with zero failures at every rung and max barely above median (tight distribution — no stragglers). On a warm host the goldens are served entirely from page cache (disk reads: 0 MB at every N), so the contended resources are CPU (cloud-init's tail; loadavg peaked at ~43 of 128) and EBS writes (linear at ~96 MB/range; ~75 MB/s averaged at N=48, under the gp3 125 MB/s baseline).

## Measurements (metal, warm page cache, final consistent ladder)

| N ranges (2 VMs each) | median ready | max ready | disk read | disk written | loadavg |
|---|---|---|---|---|---|
| 1 | 47.4 s | 47.4 s | 0 MB | 112 MB | 0.3–19* |
| 2 | 51.1 s | 51.1 s | 0 MB | 198 MB | 8.7 |
| 4 | 50.8 s | 51.2 s | 0 MB | 385 MB | 4.9 |
| 8 | 52.0 s | 52.9 s | 0 MB | 763 MB | 3.4 |
| 16 | 55.2 s | 55.9 s | 0 MB | 1527 MB | 6.5 |
| 24 | 59.4 s | 59.9 s | 0 MB | 2292 MB | 18.9 |
| 48 | 76.5 s | 79.7 s | 0 MB | 4606 MB | 43.2 |

\* the N=1 loadavg is residue from the preceding round in one run; solo baseline is ~0.3.

Raw per-range times in `tmp/results-final.csv`.

## The incidental real finding: Docker's address pools, and `network_mode: none`

The first N=48 attempt lost 18 of 48 ranges to `all predefined address pools have been fully subnetted`: each compose project allocates a default Docker bridge network, and Docker's default address pools exhaust at ~31 projects. The fix is better than a workaround: **range containers need no Docker network at all** — the range's networking lives inside the container's own netns, and the control plane is `docker exec` plus vsock — so the spike (and the production compose template) sets `network_mode: none`. That removes the density ceiling *and* removes the container's entire Docker-network surface, a small bonus for the hardened profile. One consequence to carry into the provider design: anything that must leave the container (evidence streaming) cannot assume a container network and goes through the host side.

## Scope and what this does not measure

- **Warm host only.** With 503 GB RAM the shared goldens never leave page cache, which is the realistic steady state for a long-lived host; the *cold* image path (first boot on a fresh instance) is the EBS/FSR spike's question.
- Linux guests only; a Windows restore-storm (N × 1.2 GB memory-state reads) would stress reads instead of writes and is the obvious follow-on once memory-snapshot flows are production-shaped. The checkpoint-clone 3 s restore figure is single-range.
- The ladder stopped at 48 because the curve stayed boring, not because anything broke; RAM (96 × 1 GB + QEMU overhead) and vCPU oversubscription are the next walls, both arithmetic rather than empirical.

## Density guidance (from these numbers)

- For the standard 4-VM range: ~24 concurrent ranges on this host class stays within the measured regime (96 VMs ≈ the N=48 rung), at ~+60% provisioning latency and unchanged reliability.
- Production one-sample-per-instance is untouched by any of this (density 1); the numbers size dev boxes, CI hosts, and build farms.
- gp3's 125 MB/s baseline was not the limiter here, but it is only ~1.7× the N=48 average write rate: hosts running denser or with chattier provisioning should provision gp3 throughput or place `/var/lib/docker` volumes on faster storage.

## Files

- `run.sh` — the ladder orchestrator (concurrent `one_range` jobs, per-round disk-stat deltas, CSV)
- `assets/storm.sh` — the in-container storm unit (bridge + 2 VMs, idempotent)
- `compose.yaml` — per-project template with `network_mode: none`
- `tmp/run-final.log`, `tmp/results-final.csv` — the final consistent ladder

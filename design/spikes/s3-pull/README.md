# Spike: s3-pull — measuring the S3-only distribution baseline

*Measures the cold-start numbers behind the 2026-10-05 decision to make digest-verified eager pull from object storage the image-distribution baseline ([image-distribution](../../inspect-ranges/image-distribution.md) §3), superseding the EBS/FSR path ([ebs-fsr](../ebs-fsr/README.md), never run). Needs zero credentials: pulls from a public us-east-1 open-data bucket (NOAA GOES-16) with unsigned requests, streaming to `/dev/null` so the network path is measured rather than local disk. Run on the m6i.metal devbox, 2026-10-05. `./run.sh` reproduces.*

## Results

**Eager pull throughput** (~16.5 GB corpus of 20–400 MB objects, parallel HTTPS streams):

| parallel streams | throughput |
|---|---|
| 1 | 31 MB/s |
| 4 | 83 MB/s |
| 16 | 368 MB/s |
| 32 | **617 MB/s** |

Implied image-set pull times at the P=32 rate: a Linux range set (~1 GB) in **~2 s**; a Windows golden set (~12 GB) in **~20 s**; a worst-case AD set with checkpoint memory images (~25 GB) in **~41 s**. These are conservative floors: the corpus objects are small (median ~35 MB, so per-object TLS/TTFB overhead is overrepresented), and a CRT/multipart puller on multi-GB goldens with higher stream counts pushes closer to instance network limits.

**Ranged-GET latency** (the lazy-boot read pattern; 50 random 64 KiB reads of a 400 MB object): **median 146 ms, p95 225 ms** time-to-first-byte.

## What the numbers mean for the design

1. **The eager baseline is comfortably fine.** The one cost S3-only adds versus EBS/FSR is the per-instance pull under one-sample-per-instance, and it measures at seconds (Linux) to under a minute (worst-case Windows/AD) — small against range build/convergence times and sample durations.
2. **Lazy boot directly over S3 is TTFB-bound, and the nginx number does not transfer.** The lazy-pull spike's +0.4 s penalty was against a local nginx (sub-millisecond reads); S3's ~150 ms per cold read means a boot that touches a few hundred cold blocks serially would add tens of seconds. The mechanism still works (and `copy-on-read` make reads one-time), but the honest Windows cold-start shape over S3 is **boot concurrently with a background hydrate** (eager pull racing the guest's reads, or `block-stream` into the cache) rather than pure demand paging. Pure lazy stays attractive against low-latency backing (same-host or same-VPC cache tier).
3. **No IAM, no platform coupling**: the measurement itself demonstrates the deployment story — anonymous HTTPS against a bucket was enough to hit 617 MB/s with plain `curl`; production adds only digest verification and (optionally) pre-signed granted URLs.

## Files

- `run.sh` — corpus listing, parallel pull rounds at P ∈ {1,4,16,32}, ranged-GET latency battery
- `tmp/run1.log` — the measured run

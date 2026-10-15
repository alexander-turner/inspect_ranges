# evidence-capture spike: per-bridge pcap inside the hardened range container

The evidence-v1 phase's one genuine unknown ([evidence-v1](../../inspect-ranges/evidence-v1.md)): does packet capture on the range bridges run under the hardened container's measured eight-capability floor, what is the minimal grant if not, what does a capture process cost at the 48-range density point, and how does size-rotation behave under a flood. Run 2026-10-15 on the metal devbox (128 vCPU / 503 GB, Ubuntu 24.04), 24/24 checks green, zero residue. Reproduce with `./run.sh` (`./run.sh down` to clean up a wreck).

Method: a static-IP two-segment range (dmz / internal joined by a router; no DHCP, so the rendered compose carries exactly the eight-cap floor, asserted) booted through `render`/`up` at CID base 30000. Capture attempts run (a) inside the real range container via `docker exec` and (b) in sidecar containers sharing the range container's network namespace (`--network container:`), differing only in granted capabilities, which isolates the capability variable in an otherwise identical environment. The spike bind-mounts the host's tcpdump 4.99.4 plus its libraries (same distro as the range image, which does not ship tcpdump today; slice 2 must add it to whichever image captures). Traffic is generated in-guest over vsock exec: pings for flow correctness, a python UDP blaster (`blast.py`, 1400-byte datagrams, 30 s) for load.

## Findings

**1. The eight-cap floor refuses capture; `CAP_NET_RAW` is the minimal fix.** Inside the real range container (and identically in an eight-cap sidecar):

```
tcpdump: br-dmz: You don't have permission to perform this capture on that device
(socket: Operation not permitted)
```

The eight caps plus `NET_RAW` captures cleanly. A sidecar with `NET_RAW` **alone** (`--cap-drop ALL --cap-add NET_RAW`) also captures cleanly: the scoped-sidecar alternative is viable. Precedent for the conditional in-container grant already exists: render adds `NET_RAW` to the floor for DHCP ranges, by observed failure, at the same place in `render.py`.

**2. Per-segment capture semantics hold.** A cross-segment ping (attacker→db through the router) appears on **both** bridge captures (6 packets each: it crosses both segments); a same-segment ping (web→attacker on dmz) appears on the dmz capture only (6 / 0). Capturing on the bridge device sees forwarded frames without extra configuration.

**3. The resource bill is noise at density.** One tcpdump per bridge: idle **0.0% CPU, 8.6 MB RSS**. Under a worst-case synthetic flood (11.8 M datagrams at 1400 B in 30 s ≈ 394 k pps ≈ 4.4 Gbit/s offered through the router VM): **34% of one core, RSS flat at 8.6 MB**, 11,807,973 of 11,808,085 flood packets captured with **0 kernel drops** (plain `-w`, default buffer). Extrapolated to the boot-storm density point: 48 ranges × 2 bridges = 96 capture processes ≈ **0.8 GB RSS total and ~0 CPU at realistic traffic**, against a host that was unsaturated at that density. Capture cost is not a factor; the budget-threatening variable is pcap *volume*, below.

**4. Rotation under flood works; rotation boundaries cost drops; the buffer knob cuts them 9×.** Same 30 s flood against `-C 10` (10 MB file rotation):

| Variant | Files | Bytes | Kernel drops |
|---|---|---|---|
| `-C 10`, default buffer | 1474 | 14.1 GB | 384,077 (~3.3%) |
| `-C 10 -B 8192` (8 MiB buffer) | 1238 | 11.8 GB | 43,308 (~0.37%) |

tcpdump never died in any run; drop counts are printed on SIGTERM (the slice-2 streamer must collect capture stderr and fold the counts into the evidence stream as anomaly/gap records). The headline operational number: a hostile in-range flood generates pcap at **~450 MB/s**, which is why the per-sample volume caps and drop-oldest-with-gap-record policy in the record are load-bearing, not hypothetical.

**5. Surprise: a `NET_RAW`-only sidecar cannot write a borrowed volume.** With `--cap-drop ALL`, sidecar root loses `DAC_OVERRIDE`, so it cannot write into a bind mount owned by another uid (`/dev/null` worked, files did not). The capture volume must be writable by the capture uid outright (sidecar-owned volume in production; `chmod 777` in this spike).

## Recommendation for slice 2

Prefer the **`NET_RAW`-only capture sidecar** over growing the range container's floor: one additional compose service (`network_mode: service:range`, so lifecycle stays one project), `--cap-drop ALL --cap-add NET_RAW`, writing chunks to its own private volume. This keeps the range container at the measured eight (an agent escaping QEMU lands in a container that still cannot open raw sockets beyond what DHCP ranges already grant) and puts the pre-stream pcap chunks outside the container an escapee would land in. The in-container grant (`NET_RAW` added conditionally when evidence is enabled, mirroring the DHCP conditional) is the recorded simpler fallback; both are proven above. Invocation: `tcpdump -Z root -B 8192 -i <bridge> -C <chunk-MB> -w <dir>/<segment>.pcap` (full snaplen; chunk size matched to the sink's chunking), stderr collected for drop counts. The capture image needs tcpdump added (range image ships none today).

## Files

- `run.sh`: the full battery (flock-exclusive, zero-residue, `PASS=24 FAIL=0` on 2026-10-15)
- `spec.yaml`: the static-IP two-segment range (asserts the eight-cap floor)
- `blast.py`: in-guest UDP load generator
- `measure.py`: host-side /proc CPU/RSS sampler

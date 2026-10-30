# Spike: nested virtualization — the compatibility gate for non-metal hosts

*Settles the "nested-virt (c8i/m8i/r8i) vs metal deltas" row in [architecture.md](../../inspect-ranges/architecture.md) §10's not-yet-measured list, and the checkpoint-clone leftover of cross-host restore: every prior number was measured on m6i.metal (Skylake), while the deployment story targets nested-virt instances. The spike is a compatibility gate first and a benchmark second. Build host: the m6i.metal devbox. Target host: `devbox-b`, an r8i.8xlarge (Granite Rapids, 32 vCPU / 256 GiB) with nested virtualization enabled at launch. Run 2026-10-05. Artifacts move through S3 (`s3://$INSPECT_RANGES_SCRATCH_BUCKET/inspect-ranges/spikes/nested-virt/`, sha256 manifest); logs under `tmp/`.*

## Verdict

**The full stack runs under nested KVM with no functional loss, and the headline holds: a checkpoint built on metal Skylake restores on a nested Granite Rapids host with the AD secure channel intact and per-sample instantiation at the same 3 seconds as metal.** Every battery passed: compiled networking (9/9), the hardened container profile (all checks, including profile verification from the running system), Linux and Windows vsock planes, `self_check` on both daemons (41/44 Linux, 40/44 + 4 xfail Windows — identical to metal), the `inspect eval` smoke (accuracy 1.0), and the cross-host sample-independence pair. The nesting tax concentrates in VM boot (+12–51% depending on phase) and leaves steady-state I/O at parity. One real robustness finding surfaced (Windows daemon listener wedge under connect flood, below).

## Measurements (nested r8i.8xlarge vs m6i.metal baselines)

| What | Nested | Metal | Delta |
|---|---|---|---|
| net-compile T1–T9 battery | 9/9 PASS | 9/9 | — |
| 4-VM range: up → daemons (warm) | 21.4 s | 16 s | +34% |
| 4-VM range: enforced-ready (warm) | 55.8 s | 50 s | +12% |
| hardened profile: all checks, enforced-ready | PASS, 54.2 s | PASS, 49.8 s | +9% |
| vsock exec RTT (median / p95) | 1.0 / 3.2 ms | 1.1 / 3.5 ms | parity |
| vsock file put / get (100 MB) | 476 / 714 MB/s | 398 / 696 MB/s | parity |
| agent VM boot → daemon ready (warm) | 14.5 s | 9.6 s | +51% |
| `self_check` vs Linux daemon | 41/44 (same 3 known) | 41/44 | identical |
| `inspect eval` smoke (boot→solve→score→teardown) | 1.000, 20 s | 1.000, 15–16 s | +~30% |
| `self_check` vs Windows daemon | 40/44, 4 xfail, 0 unexpected | 40/44 | identical |
| Windows native supplement / soak | 15/15, 570/570 | 15/15, 570/570 | identical |
| Windows exec RTT (median) | 22.2 ms | 17.3 ms | +28% |
| Windows channel RTT (paced, median) | 0.89 ms | 0.36 ms | +0.5 ms |
| Windows file 100 MB round trip | ≥140 / 175 MB/s (incl. client startup) | 400 / 281 MB/s | same order |
| Windows save/restore + reboot recovery | PASS | PASS | — |
| **Cross-host AD checkpoint restore** (Skylake bundle → Granite Rapids nested) | **secure channel + Kerberos intact; 5/5 independence checks** | n/a (new) | — |
| per-sample instantiation (warm) | **3 s** (cold first sample 56 s) | 3 s | parity |
| S3 artifact pull (16 GB, `aws s3 sync`) | 41 s (~400 MB/s) | 27 s up | — |
| boot storm N=1/4/8 (median ready, zero failures) | 55.4 / 56.2 / 57.8 s | 47.4 / 50.8 / 52.0 s | +11–17% base, flatter curve |

## Findings

1. **Cross-host restore works, which makes the named CPU model a verified compatibility statement, not a hope.** The bundle's `Skylake-Server-noTSX-IBRS` domains restored on a Granite Rapids host two generations newer, under nesting, after `docker compose cp` relocation — domain healthy, DNS SRV answering, `Test-ComputerSecureChannel` true, destructive/pristine sample pair fully independent. The build-farm-to-fleet direction (metal build, nested restore) is the one production needs.
2. **The nesting tax is boot-phase, not steady-state.** virtio/vsock I/O, exec RTT, and file throughput are at or near metal parity; what slows is VM-exit-heavy work (boot +34–51%, Windows process creation +28%). All absolute costs remain small against sample durations.
3. **Windows vsock daemon listener wedge (the one real defect found).** A rapid per-op reconnect flood (sub-millisecond spacing, the `perf.py` ping benchmark) drops ~4% of connects (5 s connect timeouts) and can leave the daemon's accept loop dead while the service process stays alive — so service-level restart-on-failure never fires, and recovery requires an explicit `Restart-Service`. Metal ran the same benchmark clean; nested timing widens whatever race this is. Production-shaped traffic was unaffected (570/570 soak, all conformance). Consequences for the v3 protocol/daemon: connect retry with backoff is mandatory (already a v3 contract term), the daemon must supervise its accept loop and recreate the listener on failure, and the provider should pace or pool connections rather than flood.
4. **Doctor earns its keep on hosts we didn't build.** On devbox-b's stock base image it correctly identified the missing pieces (qemu-utils, libguestfs, kernel readability, kvm group); the one gap: `vhost_vsock`/`vhost_net` module *persistence* was fixed manually (`/etc/modules-load.d/`), worth folding into doctor's fix script if not already covered on this path.
5. **vsock CIDs are host-global in practice, not just in principle.** Rung 2 initially failed because rung 1's range was still running and both compile to CIDs 3–6. Harmless in one-sample-per-instance production; on dev boxes the per-range CID allocation (as boot-storm does) is required whenever two ranges coexist.
6. **S3 round trip held up**: 27 s up from metal, 41 s down on the nested box (~400 MB/s with plain `aws s3 sync`), digest-verified both ways via the manifest. First signed-request datapoint confirming the s3-pull baseline on real images.

## Reproduce

Phase 0 (build host): `../checkpoint-clone/run.sh` end to end, then `./stage.sh`. Phase 1 (nested host): `inspect-ranges doctor --fix-script | sudo sh`, then `./fetch.sh`. Phase 2 (nested host): run in order, tearing each down before the next — `../net-compile/run.sh`, `../hardened-container/run.sh`, `../vsock-exec/run.sh`, `uv run python ../e2e-provider/run_self_check.py`, `uv run inspect eval ../e2e-provider/task.py --model mockllm/model`, `../vsockd-win/run.sh all` (seed `win-golden.qcow2` into its scratch volume first to skip the install), `./restore.sh`, `ROUNDS="1 4 8" ../boot-storm/run.sh`.

## Files

- `stage.sh` — Phase 0: validated bundle + goldens + ISOs → sha256 manifest → S3 (run on the build host after `../checkpoint-clone/run.sh`)
- `fetch.sh` — Phase 1: S3 → verify against manifest → local caches (run on the nested host)
- `restore.sh` — the cross-host restore battery: seed scratch, timed instantiate, destructive sample A, pristine sample B (reuses the checkpoint-clone compose project and `ga.py`)
- `tmp/` — run logs pulled from the nested host (`restore.log`, `net-compile-warm.log`, `hardened.log`, `vsock-exec.log`, `vsockd-win.log`, `selfcheck.log`, `boot-storm.log`, `boot-storm-results.csv`, `stage.log`)

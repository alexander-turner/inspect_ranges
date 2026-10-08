# Spike battery: channel v1 slice 4 (Go daemon v3 over the real vsock transport)

*The conformance battery for the Go v3 daemon and the host vsock transport: the pinned toolchain builds the static daemon, a battery golden is baked from the noble vendor image, booted in the range container at CID 2048 (the channel band, 2048-2999), and driven over real `AF_VSOCK`. Serializes on the shared battery lock (`/tmp/inspect-ranges-battery.lock`); project prefix `chan-`.*

*Reproduce: `./run.sh` (needs the noble vendor image in the shared cache, `vhost_vsock` loaded, docker, and the pinned Go toolchain per `src/inspect_ranges/_channel/daemon/linux/README.md`; `./run.sh down` tears down). Run logs under `tmp/` (gitignored).*

## Checks (latest run: 6/6, `tmp/run5.log`)

1. The daemon builds with the pinned toolchain and reports protocol 3.
2. The battery golden bakes (vendor + daemon + unit, relative backing ref) and boots.
3. The daemon answers v3 ping on vsock from the chan CID band.
4. `tests/test_channel_vsock.py` green (21 tests): the PORTABLE conformance suite over the real transport (exec semantics incl. liveness polling, errno taxonomy, chunked bulk, caps/truncation, round-trip budgets), dropped-reply retry without double-run (raw-socket fault injection), results re-readable until acked, pending liveness for running commands, and the 520-operation soak with zero flake.
5. Inspect `self_check` over v3: **41/44**, parity with the e2e-provider spike; the 3 failures are the documented root-daemon permission xfails (default unprivileged exec user is build-phase image work).
6. The hostile-daemon shim, uploaded through the honest channel and fed through the real transport on alternate ports: garbage and wrong-id surface as `TamperError`, truncation as loss (`TransportFailure`), never a parse fallback.

## Findings the implementation forced (protocol clarifications)

- **Large argv rides a wrapper script, never the control frame.** The 32 KiB control cap is deliberate; Inspect's 1 MB-command self_check passes via the provider-side uploaded-script pattern (`self_check3.py`), exactly the guest-exec-lessons wrapper architecture.
- **Daemon inbound bulk cap 256 MiB** (write_file payloads, exec stdin): generous but bounded; outbound stays 16 MiB per stream. The first run's 32 MiB cap broke Inspect's large-file tests with mid-transfer EPIPE.
- **Poll replies replay the stored result under the ORIGINAL request id**; only `pending` and poll-errors carry the poll's own id. The client exec loop accepts exactly that id pair; anything else is tamper.
- **Relative backing refs** for the battery golden (the images.py lesson applies to spike harnesses too).
- **Evicted-after-confirmation is `TransportFailure`**: once delivery was confirmed (a pending observed), a missing stored result is an infrastructure loss; the effect ran and is never retried.
- **`ESTALE` is the at-most-once sentinel**: the daemon tombstones evicted-unacked result ids (bounded FIFO, 4096) and answers polls/resends for them with `ESTALE` ("executed, result lost"); clients surface it as `TransportFailure` and never resend. An unconfirmed `ENOENT` resend is legal only while the request provably never left (connect failed).

## The Windows battery (slice 6, `windows/`, latest run: 5/5)

`windows/run-win.sh` reuses the vsockd-win spike machinery (range container, ~3 min unattended Server 2022 golden, qemu-ga bootstrap) at CID 2049 (chan band), project `chan-v1-win`, with the PRODUCTION daemon sources riding the payload ISO and compiled in-guest by the in-box csc.exe. Results:

1. The v3 daemon answers on vsock reporting `windows`.
2. `tests/test_channel_vsock_win.py` green (21 tests): the portable suite over busybox vocabulary, dedupe/durability/pending pins, the ESTALE eviction pin against the real daemon, and the 520-operation soak at zero flake.
3. Inspect `self_check` **41/44** with the windows xfail NAMES pinned (read-permission bit, adduser provisioning, POSIX signals): one better than the v2 spike, because the wrapper-script path turns the 1 MiB argv into a busybox-sh builtin.
4. The native supplement 16/16 (the spike's 15 plus the diag ring).
5. **The wedge regression**: three rounds of 1000 unpaced raw pings + 1000 bare connect/close cycles (~850 conn/s): zero drops, zero supervised recoveries needed, listener alive with no Restart-Service, on metal. The nested re-run on devbox-b is the recorded follow-up.

## The realizer convergence run (slice 7, `realizer/`, latest run: 14/14)

`realizer/run.sh` re-runs the slice 4 components against a REALIZER-BOOTED range instead of the compose harness: `daemon-bundle` -> `images derive` with the pinned daemon sha256 -> `render realizer/spec.yaml --cid-base 3000` (`ir-` project; this is the realizer path, so the realizer's conventions apply) -> `up`, then the conformance suite + soak, `self_check` (same 41/44 pinned xfails), the hostile shim (3/3), and the wedge storm asserting `listener_restarts == 0` over diag. The storm's one new datapoint: 160/3000 bare connect/close cycles refused-fast by the accept backlog under unpaced flood (pings 0/3000 dropped, zero recoveries); refusal-fast is the designed bound. It then proves CID and pacing coordination: the compose battery (band 2048) runs to completion (6/6) while the realizer range (band 3000+) stays up under continuous channel load (`realizer/load_loop.py`: 2302 ops, zero failures, both windows persisted in `tmp/realizer/logs/overlap.log`). The orchestrator holds the shared flock for the entire run and invokes the compose battery with `IR_BATTERY_LOCK_HELD=1`, so both bands run concurrently under the one lock owner and no third battery's exclusive section can interfere mid-proof. Windows re-ran through `windows/run-win.sh` with slice 6 results (Windows-through-realizer waits on the build phase's Windows render support).

## Files

- `run.sh` — the Linux battery; `compose.yaml` — the range container (net-compile recipe)
- `windows/` — the Windows battery (`run-win.sh`, `boot-win.sh`, `storm_v3.py`, `windows_checks3.py`)
- `realizer/` — the slice 7 convergence run (`run.sh`, `spec.yaml`, `load_loop.py`)
- `tests/test_channel_vsock.py` (repo tests, env-gated by `IR_VSOCK_BATTERY_CID`)
- `self_check3.py` — Inspect sandbox self_check over a v3 adapter
- `hostile_shim_check.py`, `guest/shim.py` — the hostile-daemon shim

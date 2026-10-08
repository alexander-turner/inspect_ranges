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

## Files

- `run.sh` — the battery; `compose.yaml` — the range container (net-compile recipe)
- `tests/test_channel_vsock.py` (repo tests, env-gated by `IR_VSOCK_BATTERY_CID`)
- `self_check3.py` — Inspect sandbox self_check over a v3 adapter
- `hostile_shim_check.py`, `guest/shim.py` — the hostile-daemon shim

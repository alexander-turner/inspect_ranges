---
type: decision
title: "Channel v1: protocol v3, the vsock daemons, and the RangeChannel client, landed in slices"
status: accepted
tags: [inspect-ranges, channel, vsockd, protocol, conformance, plan, decision]
timestamp: 2026-10-08
---

# Channel v1: protocol v3, the vsock daemons, and the RangeChannel client, landed in slices

*Phase plan for the channel track of the provider arc, developed in parallel with the realizer track. It implements what [range-channel](range-channel.md) specifies (the six message properties, untrusted replies, the two mock channels), what [guest-exec-lessons](guest-exec-lessons.md) binds the daemon to (idempotent launches, durable results, layered budgets, hostile-daemon shim), and what the [nested-virt spike](../spikes/nested-virt/README.md) made mandatory (connect retry with backoff, listener supervision, after the Windows accept-loop wedge under connect flood). The seam it fills is the `RangeChannel` interface from [host-provider](host-provider.md), vsock as the first transport. Each slice lands under the lockstep rule: implementation, failure modes, battery, docs, fresh-context review, or it does not count as done.*

## Scope and independence

This track owns the wire protocol, the guest daemons (Linux and Windows), the host-side `RangeChannel` client with its vsock transport, the mock channels, and the conformance suite. It does not depend on the realizer: development runs against the existing spike harness pattern (compose-booted range container, host-side batteries), exactly how [vsockd-win](../spikes/vsockd-win/README.md) and [e2e-provider](../spikes/e2e-provider/README.md) ran. The only cross-track couplings are the daemon artifact (published by this track, baked into goldens by the realizer track, slice 5) and CID discipline (below).

## Protocol v3, summarized

v3 is the named successor to the spike-proven v2 wire protocol ([vsockd2.py](../spikes/e2e-provider/guest/vsockd2.py), its C# port behind a codec seam). What it adds is exactly the range-channel contract: request IDs with idempotent retry, durable replies held until acknowledged, length-prefixed framing with explicit payload chunking (the viosock 32 KiB send cap makes implicit chunking a trap), errno-tagged errors with the established exit-code semantics, layered budgets (per-command in-guest, channel allowance, untimed bound), and strict schema validation of every reply as untrusted input with byte caps enforced reader-side. Message types cover both planes from range-channel: guest control (`exec`, `read_file`, `write_file`, `forward`) implemented fully here, and host lifecycle (`realize`, `teardown`, stage reports, heartbeat) defined as schemas here and exercised against mocks, with the real applier arriving in the provider phase.

## Slices

**1. Protocol v3 messages and codec.** Typed message schemas for both planes (pydantic strict, aliased per house conventions), the length-prefixed framing codec with explicit chunking, request ID semantics, the errno taxonomy, budget fields. Pure code, no VMs. Acceptance: codec round-trips every message type byte-exactly; malformed, truncated, oversized, and length-field-lying frames all produce typed decode errors, never exceptions escaping the codec. Shared wire test vectors (golden frame fixtures in-repo) pin the encoding; the Go and C# codecs must round-trip the same fixtures when they land. Battery: property-style unit tests in CI.

**2. RangeChannel interface, driver state machine, loopback transport.** The `RangeChannel` protocol from host-provider as real types, the driver-side sample state machine (acquire, realize, verify, execute, finalize evidence, destroy) with every transition observable, an in-memory loopback transport, and the conformance suite skeleton that runs against any channel implementation. Acceptance: the state machine runs end to end against loopback with no cloud and no VM; illegal transitions are unrepresentable or rejected. Battery: CI, suite green on loopback.

**3. Mock channels and the full conformance suite.** The hostile mock channel (malformed, oversized, protocol-violating replies surface as tamper errors, never parse fallbacks) and the latency-injecting mock channel (full `self_check` semantics at second-scale round trips, failing any multi-round-trip regression in the hot path). Acceptance: the conformance suite is transport-parameterized and both mocks pass it; a deliberately chatty reference bug is caught by the latency mock. Battery: CI, both mocks in the suite from here on.

**4. Linux daemon v3 (Go) and the vsock transport.** The daemon written fresh as a static Go binary against the slice 1 wire vectors (the Python v2 daemon is the behavioral reference), implementing v3 (request-ID dedupe, durable acked results, in-guest timeout with kill-grace and tree kill, cwd/env/user/stdin, chunked bulk) plus the host-side vsock transport: per-operation connect with retry and backoff, connection pacing, budgets enforced. Acceptance: the 44-check `self_check` passes (xfails only documented platform facts), plus v3-specific checks: a dropped reply recovered by retry without double-run, results re-readable until acked, the hostile-daemon shim fed through the real transport. Battery: compose-booted Linux guest harness (spike pattern), conformance suite over the real transport, soak at the vsockd-win scale (500+ operations, zero flake tolerance).

**5. Daemon artifact publication.** The daemon sources live in-repo (host package layout below); `inspect-ranges daemon-bundle` emits a versioned tarball (static Go linux daemon (amd64) + installer, windows daemon source + installer, a `daemon.json` carrying protocol version, package version, per-file sha256, and the bundle digest). The realizer track bakes the daemon into goldens by this digest; the build manifest records it, mirroring the render-bundle manifest pattern. Acceptance: byte-deterministic bundle, digest verifiable offline. Battery: CI (build twice, identical digest; tamper refusal on a modified file). This slice unblocks the realizer's golden derivation and ships as soon as slice 4 stabilizes the Linux daemon.

**6. Windows daemon v3 and the wedge regression.** The codec swap the vsockd-win port isolated for, plus the two nested-virt consequences: connect retry tolerance proven from the client side, and listener supervision in the daemon (the accept loop is watched and the listener recreated on failure, so recovery never requires `Restart-Service`). Acceptance: `self_check` parity with the spike result (40 passed, 4 documented xfails), the native supplement green. Battery: the wedge regression specifically, a sub-millisecond reconnect storm (the `perf.py` ping shape that produced the wedge) sustained with zero listener deaths and bounded connect retries, run on metal and, when a nested box is available, under nesting where the race was widest.

**7. Integration against the realizer (blocked on the realizer landing).** Re-run the full conformance suite, soak, and the wedge regression against a realizer-booted range instead of the compose harness, on both daemon OSes. Acceptance: identical results to slices 4 and 6; CID and pacing coordination verified with both tracks' batteries running concurrently on one host. This is the only slice with a cross-track dependency and it is last by design.

## Logging and debuggability

Channel failures are the subtle kind (timeouts with three candidate layers, dropped frames, dedupe misfires); the plan makes them mechanical to triage:

- Request-id correlation end to end: every host-side log line carries the guest CID and request id, and the daemon echoes request ids in its own log, so one grep follows an operation across the boundary (slices 2 and 4).
- The codec exposes a wire trace hook (direction, message type, request id, sizes, timing; bulk payloads redacted to digests). `RangeChannel` enables it per channel, and conformance failures dump the trace tail automatically (slice 1 for the hook, slice 3 for the dump-on-failure).
- The daemon keeps an in-guest ring buffer of recent operations and errors, retrievable over the channel via a diag request and never written anywhere the range can see; the Windows wedge battery asserts the listener supervisor's recovery events appear in it (slices 4 and 6).
- Every errno-tagged failure names the layer whose budget fired (in-guest, channel allowance, transport), so timeout triage never starts from guesswork (slice 1 taxonomy, enforced by the latency mock in slice 3).

## Review discipline

Every slice closes with a fresh-context code review: a reviewer with no shared session context with the author (not a fork of the authoring session) reads the slice diff against this record's acceptance criteria, the house rules, and the seam contracts. For this track the review brief additionally weights the untrusted-input posture (every reply strict-validated, byte caps reader-side, no parse fallbacks) and protocol-semantics gaps (dedupe, durability, budget enforcement) against the range-channel contract. Blocking findings are fixed before the slice is declared done.

## CID discipline

vsock CIDs are host-global and both tracks run VM batteries on shared dev hosts. The compiler allocates range CIDs from 3 upward; this track's harness takes the band 2048 through 2999, and the realizer track's batteries plan at 3000 and up (via `PlanOptions.cid_base`, per [realizer-v1](realizer-v1.md)), so the bands cannot collide. Compose projects are prefixed `chan-` (the stale-project collision lesson), batteries tear down their projects before and after each run, and batteries that assume an otherwise-quiet host serialize on the shared host flock (`/tmp/inspect-ranges-battery.lock`, same lock as the realizer track).

## Module layout

Host-side code under `src/inspect_ranges/_channel/` (files inside the underscored package drop the leading underscore): `protocol.py` (message types), `codec.py`, `channel.py` (the `RangeChannel` protocol, state machine, loopback), `mocks.py`, `vsock.py` (the transport), `bundle.py` (the daemon artifact builder). Guest daemon sources under `src/inspect_ranges/_channel/daemon/` (`linux/` as a small Go module, `windows/VsockDaemon.cs`, installers); the Go toolchain version is pinned and `daemon-bundle` builds reproducibly. No imports from the realizer's `_runtime/` in either direction; the daemon artifact digest is the only coupling. CI-runnable tests in `tests/`; the VM batteries live as a harness under `design/spikes/channel-v1/` per spike convention, with run logs in `tmp/`.

## Verification

Slices 1 to 3 are fully CI: codec properties, state machine, mock conformance run in `pytest` under `make check` discipline. Slices 4 and 6 are battery-verified on the devbox via the spike harness with logged runs; their CI shadow is the conformance suite against mocks plus codec/dedupe unit tests, so regressions in driver logic fail fast without VMs. Slice 5 is CI (determinism, tamper refusal). Slice 7 re-runs 4 and 6 batteries on the realizer path and closes the phase. The phase is done when: conformance green on loopback, both mocks, and real vsock; `self_check` green on both daemon OSes; the wedge regression green; soak at zero flake; artifact digest consumed by a realizer-built golden.

## Non-goals

- No realizer work: no netns, bridge, nftables, dnsmasq, or VM boot code in this track.
- No Inspect `SandboxEnvironment` wiring; the provider phase consumes this track's channel.
- No evidence streaming; evidence as a declared output stays with the host-provider seam work.
- No bridged or connectionless transports; vsock is the only transport implemented, behind an interface that already forbids callers from knowing that.
- No qemu-ga runtime path; it remains a build-time image tool per guest-exec-lessons.

## Decisions (resolved 2026-10-08)

1. **The Linux daemon is a static Go binary** (stdlib plus `x/sys`, `CGO_ENABLED=0`, `-trimpath` for reproducible builds, amd64 only in v1). Forced now, not later: Kali, the attack-box image class, does not carry python3. The proven Python v2 daemon is demoted to reference implementation; the Go toolchain is pinned in CI. With three codec implementations (Python host, Go Linux daemon, C# Windows daemon), slice 1 ships shared wire test vectors that every implementation must round-trip.
2. **Goldens carry v3 only.** No dual-protocol surface; spikes stay pinned to their own assets.
3. **Per-operation connect with retry, backoff, and pacing.** The proven model and what the wedge analysis recommends; connection pooling is a later, measured optimization.
4. **The daemon artifact digest is recorded in golden derivation metadata** and flows into the build manifest, alongside the channel package's own record. One digest, visible from both sides.
5. **The driver sample state machine lives in this track** (slice 2), exercised against mocks; the provider phase wires Inspect onto it and adds nothing to its semantics. Transport-level lifecycle belongs with the channel, Inspect wiring with the provider.

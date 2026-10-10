# range-host-v1 slice-4 battery: the separated topology on one host, for real

*The booted-range integration gate for the range-host phase: a real `inspect-ranges applier` process and real driver processes on the m6i.metal devbox against recipe-v4 goldens, exercising everything the CI suites reached only through injected seams. Run 2026-10-10 (45 battery checks across the two scripts plus the orchestrator's residue sweep, all green); logs under `tmp/` (gitignored).*

Usage: `./run.sh` (exclusive via the shared battery lock; derives its own golden into `tmp/cache`, state under `tmp/state`; `./run.sh down` sweeps). The applier socket lives under `/tmp/ir-rh-<uid>/` because `AF_UNIX` paths cap at ~107 bytes and a worktree-nested spike path exceeds it. Battery CID band 20000+ for the battery's own direct allocations; provider-driven samples ride the allocator's 10000+ partition as in production.

## What runs

1. **Battery main** (`battery_main.py`), against one applier process:
   - **Observed realize-to-ready**: the driver renders the two-guest bundle, acquires a `RemoteRangeHost` lease, and drives `channel.realize` directly. The stage stream arrives in seam vocabulary (`fetch, construct, boot, verify, ready`, with the construct detail carrying the triggering up stage), a concurrent heartbeat poller sees `pending`/`booting` mid-realize and `ready` after, relayed pings reach both real guest daemons, and after teardown plus lease release the heartbeat is refused at connect (the released lease fails routing).
   - **The portable conformance suite over the LIVE applier**, `realize_digest()` pointed at the genuinely rendered bundle, in three sequential pytest phases (realize boots the suite's own range; the guest-plane and heartbeat tests ride the registered relay; teardown closes it). The phase split exists because `up` is deliberately not re-runnable on a booted project (`virsh define` is not idempotent) while the suite's file order puts guest tests before the host plane.
   - **`self_check` 44/44 with the EMPTY two-sided pin through `RemoteRangeHost`**: a sample booted purely through the registered entry point under `INSPECT_RANGES_HOST=uds:`, basic cross-guest ops over the relay (exec as agent, compiled-segment ping, file round trip), then every inspect-ai check green. The separated topology meets exactly the co-resident bar.
   - **Local-versus-UDS wall clock** (below).
2. **Lifecycle matrix** (`lifecycle_matrix.py`), 25 checks at a 12-second lease TTL:
   - **Two concurrent samples through one applier**: non-vacuous boot overlap (both boots spanned the same ~46 s window), distinct leases, disjoint CID blocks (10000-10002 and 10002-10004), same-name `web` guests reaching their own guests (distinct file contents round-tripped), one sample torn down while the other kept serving, both leases released.
   - **Wedged teardown + applier restart**: the applier SIGKILLed mid-sample; `sample_cleanup` fails loudly and frees NOTHING (lease, CID lease, registry entry all findable, the range still running); a restarted applier serves a NEW sample cleanly (the recorded restart limitation holds: charges and relay map lost, logged loudly at startup), and the wedged sample's teardown then recovers from disk through `task_cleanup`.
   - **kill -9 + the fresh-shell reaper**: a driver process SIGKILLed mid-sample leaves the range running and the lease active-but-unrenewed; after TTL expiry a fresh-process `inspect-ranges reaper` reclaims THROUGH the live applier (no direct-down fallback warning) in 1.6 s, zero residue, lease and CID lease released.
   - **Forced expiry + the reaper-versus-renewal race, both ways, against the real store**: a just-renewed lease is spared by the sweep's under-flock expiry re-check and keeps serving ops; when the sweep wins, the RUNNING sample is reclaimed through the applier and the driver fails loudly with `LeaseLostError` at its next operation (the deliberate expiry-mid-sample policy), after which cleanup completes with no leases left.
3. **Zero residue** (orchestrator): `down --all` a no-op; no `ir-` containers, networks, or volumes; no CID leases; **no host leases**; no staging; the applier socket removed.

## Timings (run 2026-10-10, m6i.metal, warm golden)

| What | Seconds |
|---|---|
| Observed realize to ready (2 guests, through the applier) | 50.6 |
| Suite realize phase (same flow plus pytest startup) | 48.4 |
| UDS sample boot + teardown through the entry point | 47.4 |
| Local sample boot + teardown through the entry point | 48.1 |
| UDS boot + ops/self_check battery + teardown | 64.9 |
| Fresh-shell reaper reclaim of a 2-guest range | 1.6 |

The separated topology costs nothing measurable on one host: UDS boot+teardown landed inside run-to-run noise of the local path (the relay adds no per-frame round trips, and realize is dominated by guest boot either way).

## Findings

- **`AF_UNIX`'s ~107-byte path cap is a real deployment constraint.** The battery's first run failed at `sock.bind` from a worktree-nested socket path. Short socket dirs (`/run/user/<uid>`, a flat `/tmp` dir) are now the documented guidance (docs: Host Topology).
- **A SIGTERM-killed applier must still unlink its socket.** The CLI originally relied on `finally` alone, which SIGTERM's default disposition skips; the stale socket file then faked readiness for the next applier's watcher and every connect raced the rebind. The applier CLI now installs SIGTERM/SIGINT handlers so shutdown runs `aclose` (and the battery additionally waits for CONNECTABLE, not merely present).
- **`uv run` wrappers absorb SIGKILL.** The wedge scenario first "killed" the uv wrapper while the real applier kept serving underneath, making the failure injection vacuous (and the teardown quietly succeed). The battery spawns the venv console script directly; fault-injecting harnesses should never signal through a wrapper.
- **The host-plane routability exemption carried its weight**: the reaper's reclaim-through-the-applier works precisely because `@host` stays routable for a `reaping` lease; the guest plane refused the same lease throughout.

## Files

- `range.yaml`: the two-guest battery spec (image `noble-range-guest`)
- `run.sh`: the orchestrator (setup, battery main, lifecycle matrix, residue sweep)
- `battery_main.py`, `lifecycle_matrix.py`, `boot_and_die.py`: the scenarios

Timing summaries from battery runs belong in this committed README, per the house spike convention; `tmp/` evidence is ephemeral, so a number only the logs carry is a number the record loses.

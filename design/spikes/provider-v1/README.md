# provider-v1 slice-5 battery: the provider on realizer-booted ranges

*The booted-range integration gate for the provider phase: everything the CI suites could only mock, run for real on the m6i.metal devbox against recipe-v4 goldens (vsockd 3.1.0, agent user), reached exclusively through the registered `libvirt_range` entry point. Run 2026-10-09; logs under `tmp/` (gitignored).*

Usage: `./run.sh` (exclusive via the shared battery lock; derives its own golden into `tmp/cache`, state under `tmp/state`; `./run.sh down` sweeps). Provider CID band 10000+ (the allocator's partition).

## What runs

1. **Main battery** (`battery_main.py`): `task_init`/`sample_init` on the two-guest spec (attacker + web, isolated segment) through `registry_find_sandboxenv("libvirt_range")`, never a provider import; basic cross-guest ops; Inspect's full **`self_check`, 44/44 with the EMPTY two-sided pin**; the **portable conformance suite** (`tests/test_channel_vsock.py`, incl. the 520-op soak and the dedupe fault injection) over the provider-booted attacker's real vsock CID; the **third-user wrapper path** (in-guest `useradd`, oversized-env exec as that user, self-deletion proven by zero `/tmp/.ir-exec-*` residue, a 0600 agent-owned mode-carrying write statted on the real guest); the **agent-identity pins** (caller HOME survives the runuser reset; no `agent-user-unavailable` diag); the **suspend/resume fault**; the **vsockd-restart fault** (details below). Teardown is in a `finally`, so a failed scenario never leaks the range.
2. **Lifecycle matrix** (`lifecycle_matrix.py`): interrupt deferral (`sample_cleanup(interrupted=True)` leaves the range booted, `task_cleanup` sweeps); `cleanup=False` leaves the range up, logs the removal commands, and the printed `inspect sandbox cleanup libvirt_range <project>` removes it from a fresh process; two same-spec samples boot CONCURRENTLY with distinct projects and disjoint CID leases, both serve ops mid-overlap (evidence persisted to `tmp/concurrency.json`), both tear down.
3. **kill -9 recovery** (`boot_and_die.py`): a booted sample's process dies with no cleanup hooks; `inspect sandbox cleanup libvirt_range` from a fresh shell recovers it from on-disk state (the CID lease registry plus provider-marked owner records).
4. **The real eval**: `uv run inspect eval evals/smoke/task.py --model mockllm/model`, pure entry-point registration: sample file + setup script land via Inspect, the solver execs on the default sandbox and `sandbox("web")`, the scorer reads the flag file off the web guest; green at accuracy 1.
5. **Zero `ir-` residue**: `down --all` reports a no-op; no `ir-` containers; no CID leases; no staging.

## Findings

- **The restart fault is self-amplifying, by design of the hazard itself.** A plain `exec("systemctl restart vsockd", user="root")` kills the daemon before its reply ships; the wire layer resends the same id; the restarted daemon's EMPTY dedupe store re-runs the restart; the loop repeats until systemd's default start limit (5 in 10 s) killed the unit PERMANENTLY (`start-limit-hit` in the journal), bricking the control channel for the guest's lifetime. This is the exact non-idempotent double-run that layer 2b exists to surface, demonstrated end to end. Two consequences shipped: the baked unit now sets `StartLimitIntervalSec=0` (the control daemon must always come back; the storm is bounded by the host's retry budgets), and the battery arms the restart through `systemd-run --on-active=2 --timer-property=AccuracySec=100ms` (a pid1-owned transient timer, detached from its own delivery, with the default MINUTE of timer coalescing slack pinned down and room for the probe's own delivery) so the fault fires exactly once, aimed mid-flight. The timing is arranged so that losing the race FAILS the check rather than passing it: a restart that lands outside the probe's window leaves the probe cleanly delivered once, no SessionChangedError, and the check reports that honestly. Residual of the hardening: the start-limit protection is traded away permanently, so a daemon that cannot start at all now restarts for the guest's lifetime at RestartSec pacing instead of stopping.
- **A retried success can hide a restart.** The first battery run showed a fresh-id retry (layer 2) succeeding across the restart with no session check: the earlier delivery's possible double-run went invisible. The provider now confirms the session after ANY re-delivery of a side-effecting op, whatever the layer and outcome shape, and the restart scenario deterministically surfaces `SessionChangedError` with the follow-up op succeeding on the re-pin.
- **Suspension is a delay, not a fault, on this stack.** `virsh suspend` parks host vsock connects in the vhost queue rather than refusing them; the in-flight op simply completes after `resume`, with zero retries at any layer. The recovers-within-deadline check pins that; the retry-counter evidence rides the restart fault, where real transients occur.
- **Sample file and `setup=` references resolve against the process CWD**, not the task file; the eval task uses absolute paths derived from `__file__`.

## devbox-b (the realizer carry-over)

Not run. The `devbox-b` instance (i-xxxxxxxxxxxxxxxxx, x.x.x.x) was STOPPED at battery time and starting it is outside this run's permissions; there is no network route from the build host while it is down. The realizer phase-exit carry-over (nested-virt coverage) and the channel's nested-wedge follow-up therefore remain open, with this harness ready to run there unchanged (`fetch` the vendor per the nested-virt spike, then `./run.sh`).

## Files

- `range.yaml`: the two-guest battery spec (image `noble-range-guest`)
- `run.sh`: the orchestrator (setup, batteries, eval, residue sweep)
- `battery_main.py`, `lifecycle_matrix.py`, `boot_and_die.py`: the scenarios
- `../../..//evals/smoke/`: the real-eval task (sample files, setup script, solver, scorer)

Convention note (2026-10-10): timing summaries from battery runs belong in this committed README, per the realizer/channel spike convention; tmp/ evidence is ephemeral, so a number only the logs carry is a number the record loses.

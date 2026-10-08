# Spike battery: the production applier (realizer-v1 slices 2 and 3)

*`inspect-ranges up` and `down` as the product path: the bundle spike's combined conformance realized by the packaged applier under the hardened non-root-QEMU range image, plus the failure-mode and crash-cleanup batteries. CID band 3000+ (`--cid-base`), project state isolated via `XDG_STATE_HOME`, serialized on the shared battery lock.*

*Reproduce: `./run.sh` (slice 2, 17 checks) and `./crash.sh` (slice 3). Both derive their own v2-daemon golden (`images derive`) and render at CID 3000+. `./run.sh down` sweeps leftovers. Run logs under `tmp/` (gitignored). Measured: up to enforced-ready in 52.3 s for the 4-guest range.*

## run.sh (slice 2)

1. Tamper refusal: one flipped byte refuses at `verify-bundle` before anything runs.
2. Missing image refuses at `verify-images`, naming the guest.
3. `up` reaches ready, reporting the project and per-guest state.
4-9c. The bundle spike's combined conformance over the running range: deny carve-out beats later allow, network allow refused-fast, guest and CIDR endpoints (allowed refused-fast, excluded dropped), icmp, DHCP reservations deliver allocated addresses, derived and explicit DNS records resolve.
10. Zero range artifacts on the host while the range runs.
11. Duplicate `up` of the identical bundle refuses, naming the running project and the exact `down` command.
12. `up --from-spec` composes render into a temp bundle and reaches ready.
13. Readiness timeout (daemon-less vendor image): the failure names guest and stage, the guest's serial console log is captured non-empty into the project state dir, and the project is torn down.

## crash.sh (slice 3)

Kill-mid-up matrix (SIGKILL during `range-container`, `guest-boot`, and `readiness`, synchronized on the stage log), each followed by `down` leaving nothing (no containers, volumes, or state); double `down` is a no-op; `down --all` sweeps `ir-` projects only (a decoy `chan-` labeled volume survives); the pkill-the-harness recovery scenario.

## Files

- `spec.yaml` — the bundle spike's combined-coverage spec with explicit battery-golden images
- `timeout-spec.yaml` — a guest that can never become ready (raw vendor image, no daemon)
- `run.sh`, `crash.sh` — the batteries

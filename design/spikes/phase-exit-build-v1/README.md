# The build-v1 phase exit

*One scripted run proving the phase per `build-v1.md`'s Verification section: `make check` and the unit suite; the slice 1 fixture-recipe battery; the slice 2 crash matrix; the slice 4 verification-failure battery; the slice 6 vulhub battery; then the Journey A transcript (`build-images-journey-a.md`) executed command for command on a scratch copy of the real range with isolated caches. The sequence and concept count are Journey A's contract: bare `validate` in the range directory; the induced wrong-version detour (php declared 7.0 against the installed 7.4) failing with the coded, declared-versus-observed, log-carrying refusal and minting no manifest; the fixed build going green through verification, capture, manifest, and the three behavioral chains; the unchanged rebuild reporting the cached no-op; a recipe edit rebuilding exactly the edited guest; and a real `inspect eval` whose deterministic solver runs the range's own reference chain through the foothold sandbox and scores 1.0/valid with both execute goals corroborated.*

*Reproduce: `./run.sh` (focal vendor image, `vhost_vsock`, outbound internet). The delegated batteries take the shared battery lock themselves; the Journey A section holds it for its own span. CID band 3800; the eval's provider allocates from the isolated state dir. `./run.sh down` tears down.*

## Measured timings (the phase-exit record)

The J-legs time the measurements `build-v1.md`'s phase-exit record carries (derive wall time for the focal class, first vulhub build, cached no-op, one-guest incremental); the authoritative numbers live in the build-v1.md Verification addendum, recorded from this battery's green run.

## Files

- `run.sh` — the battery: P1 checks/suite, P2-P5 delegated slice batteries, J0-J6 the Journey A transcript.
- `journey_eval.py` — J6: `challenge_dataset` + `plant_goals` + a deterministic solver executing `checks/zabbix-rce/reference.sh` via `sandbox()` with `IR_ATTACKER_IP` derived in-guest, scored by `challenge_scorer` against the realized images the build-aware gate consumes.

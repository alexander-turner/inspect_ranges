# Spike battery: dist-provider (distribution v1, slice 4)

*The provider's implicit pull, live: a builder machine builds `distmini` and publishes its closure to a local `registry:2`; a consumer environment with fresh empty caches runs a real `inspect eval`, whose `task_init` resolves the spec hash, announces `pull OK <name>@<digest>` with docker-pull-shaped transfer lines BEFORE the eval runs, materializes the exact published manifest bytes, and the sample boots the pulled realized guest (the solver also pins the sandbox wall: the marker lives on `web`, and the foothold attacker must not carry it). A second identical eval is warm: one spec hash, zero fetch lines, zero network. A host pinned with `INSPECT_RANGES_NEVER_PULL=1` refuses with the knob named before any sample boots. Serializes on `/tmp/inspect-ranges-battery.lock`; CID band 4030; registry port 5059. The fixture is dist-registry's `minirange`.*

*Reproduce: `./run.sh` (focal vendor image in the shared cache, `vhost_vsock`, docker, the `registry:2` image). `./run.sh down` tears down.*

## Checks

1. **P1** the builder builds green and `push` publishes to the live registry.
2. **P2** the headline: the consumer eval runs green on pulled artifacts; the implicit pull announces itself before the eval (`task_init` placement); docker-pull transfer lines render; the consumer's manifest is the exact published bytes; the foothold wall holds.
3. **P3** the second eval is warm: no pull line, no transfer lines, nothing fetched.
4. **P4** never-pull refuses with the knob named, before any guest boots.

## Files

- `run.sh`: builder, publish, consumer evals, never-pull, under the battery lock.
- `dist_eval.py`: the minimal real eval (mockllm; a deterministic solver probing the marker through the foothold).

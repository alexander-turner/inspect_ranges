# Spike battery: dist-registry (distribution v1, slice 2)

*The pure-Python registry client against live `registry:2` containers: a real (minimal) build pushes its transitive closure over the distribution v2 protocol, a re-push stores zero new registry bytes (content-addressed dedup pinned at the registry's own filesystem), fresh empty caches pull the closure back and the range boots carrying its recipe's marker, and the closure mirrors registry-to-registry with the root digest reproduced and a byte-identical pull from the mirror. The bearer-token auth flow is covered at the unit tier (an in-process v2 server with a 401 challenge) and against the real hub by the slice-6 `dist-hub` spike; `registry:2` runs unauthenticated. Serializes on `/tmp/inspect-ranges-battery.lock`; CID band 4010; registry ports 5056/5057.*

*Reproduce: `./run.sh` (needs the focal vendor image in the shared cache, `vhost_vsock`, docker, and the `registry:2` image present locally; see parked-decisions entry 1 for why pulling it needs the credential dance while the scoped org token is logged in). `./run.sh down` tears down.*

## Checks

1. **R1** the minimal fixture range (`distmini`: one guest, one marker recipe) builds green.
2. **R2/R3** push prints the root digest; a second push stores zero new bytes in the registry's filesystem and reproduces the root digest.
3. **R4** fresh caches pull from the registry: the manifest is the exact published bytes, render and `up` run from the pulled caches, and the realized guest carries the recipe's marker (`shipped-by-registry`), proving the pulled artifact is the provisioned one.
4. **R5** `copy_closure` mirrors A to B reproducing the root digest, a re-mirror copies nothing, and a pull from the mirror is byte-identical to the original.

## Files

- `run.sh`: build, push, dedup, pull, boot, mirror under the battery lock.
- `dist.py`: drives the store forms (`layout:` and `registry+http:`) through `push_build`/`materialize_closure`/`copy_closure`.
- `fixtures/minirange/`: the smallest buildable range, so the battery proves transport rather than compilation.
